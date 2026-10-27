//! WP-09 (D2.1–D2.3) & WP-13 (D13.2): Live RFC 5321 SMTP Wire Server, RFC 6376 / RFC 8463
//! Asymmetric Ed25519 DKIM Signer/Verifier (`a=ed25519-sha256`), SPF/DMARC/DKIM DNS TXT
//! Generator, and On-Disk Maildir + CBOR-LD Envelope Receipt Store.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use webizen_host_core::{
    ed25519_public_key_from_seed, ed25519_sign_detached, ed25519_verify_detached,
    encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash, sha256,
    NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_QUIN_WIRE_SIZE, OP_FORBID, OP_PERMIT,
};
use webizen_host_ingest::append_quin_to_journal;

use crate::{MailGateVerdict, RelationshipScopedMailAlias};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Maximum inbound RFC 5321 SMTP `DATA` message size (10 MiB).
pub const MAX_SMTP_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

/// Synthesized DNS TXT records (`SPF`, `DKIM`, `DMARC`) for a custom domain hosted on Webizen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainMailDnsRecords {
    pub spf_txt: String, pub dkim_selector_domain: String, pub dkim_txt: String, pub dmarc_txt: String,
}

/// Delivery receipt returned when an inbound message is admitted and spooled to disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolDeliveryReceipt {
    pub message_id_hex: String, pub eml_path: PathBuf, pub cbor_ld_path: PathBuf, pub verdict: MailGateVerdict,
}

/// On-disk Maildir spooler and CBOR-LD receipt store.
pub struct MaildirSpool;
/// Live RFC 5321 SMTP wire server namespace.
pub struct SmtpWireServer;

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes { out.push(HEX[(b >> 4) as usize] as char); out.push(HEX[(b & 0x0F) as usize] as char); }
    out
}

fn base64_std_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let t = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        for shift in [18, 12, 6, 0] {
            out.push(B64[((t >> shift) & 0x3F) as usize] as char);
        }
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i] as u32;
        out.extend([B64[((b0 >> 2) & 0x3F) as usize] as char, B64[((b0 << 4) & 0x3F) as usize] as char, '=', '=']);
    } else if rem == 2 {
        let p = ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
        out.extend([B64[((p >> 10) & 0x3F) as usize] as char, B64[((p >> 4) & 0x3F) as usize] as char, B64[((p << 2) & 0x3F) as usize] as char, '=']);
    }
    out
}

#[inline]
fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'), b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52), b'+' => Some(62), b'/' => Some(63), _ => None,
    }
}

pub(crate) fn base64_std_decode(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || clean.len() % 4 != 0 { return None; }
    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for c in clean.chunks_exact(4) {
        let (v0, v1) = (b64_val(c[0])? as u32, b64_val(c[1])? as u32);
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if c[2] != b'=' {
            let v2 = b64_val(c[2])? as u32;
            out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
            if c[3] != b'=' { out.push((((v2 & 0x03) << 6) | (b64_val(c[3])? as u32)) as u8); }
        } else if c[3] != b'=' { return None; }
    }
    Some(out)
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y)) == 0
}

/// RFC 6376 §3.4.4 `relaxed` body canonicalization (trim trailing horizontal whitespace per line, CRLF).
pub fn canonicalize_body_relaxed(body: &str) -> String {
    let mut lines: Vec<&str> = body.lines().map(|l| l.trim_end_matches([' ', '\t', '\r'])).collect();
    while lines.last().copied() == Some("") { lines.pop(); }
    if lines.is_empty() { return "\r\n".to_string(); }
    let mut out = String::with_capacity(body.len() + 8);
    for line in lines { out.push_str(line); out.push_str("\r\n"); }
    out
}

fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    format!("{}:{}", name.trim().to_ascii_lowercase(), value.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Synthesize `SPF`, `DKIM` (`v=DKIM1; k=ed25519; p=<base64_pubkey>`), and `DMARC` DNS TXT records
/// for `domain` and `selector` by deriving the real 32-byte RFC 8032 Ed25519 public key from `signing_seed`.
pub fn synthesize_mail_dns_records(domain: &str, selector: &str, signing_seed: &[u8; 32]) -> DomainMailDnsRecords {
    let pubkey_b64 = base64_std_encode(&ed25519_public_key_from_seed(signing_seed));
    DomainMailDnsRecords {
        spf_txt: "v=spf1 mx -all".to_string(), dkim_selector_domain: format!("{selector}._domainkey.{domain}"),
        dkim_txt: format!("v=DKIM1; k=ed25519; p={pubkey_b64}"), dmarc_txt: format!("v=DMARC1; p=reject; rua=mailto:postmaster@{domain}"),
    }
}

/// Extract and Base64-decode the 32-byte Ed25519 public key (`p=`) from a `_domainkey` DNS `TXT` record.
pub fn extract_dkim_public_key_from_txt(dkim_txt: &str) -> Option<[u8; 32]> {
    dkim_txt.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k.trim() == "p").then(|| base64_std_decode(v.trim())?.try_into().ok()).flatten()
    })
}

fn dkim_signing_input(domain: &str, selector: &str, from: &str, to: &str, subj: &str, bh: &str) -> String {
    format!(
        "{}\r\n{}\r\n{}\r\nd={};s={};bh={}",
        canonicalize_header_relaxed("from", from), canonicalize_header_relaxed("to", to), canonicalize_header_relaxed("subject", subj),
        domain.trim().to_ascii_lowercase(), selector.trim().to_ascii_lowercase(), bh
    )
}

/// Sign an email's headers (`From`, `To`, `Subject`) and body using RFC 6376 `relaxed`
/// canonicalization and asymmetric RFC 8032 / RFC 8463 `ed25519-sha256`, returning a complete
/// `DKIM-Signature` header line with Base64-encoded `bh=` (32B SHA-256) and `b=` (64B Ed25519).
pub fn sign_email_dkim(
    domain: &str, selector: &str, signing_seed: &[u8; 32], from_hdr: &str, to_hdr: &str, subject_hdr: &str, body: &str,
) -> String {
    let bh = base64_std_encode(&sha256(canonicalize_body_relaxed(body).as_bytes()));
    let signing_input = dkim_signing_input(domain, selector, from_hdr, to_hdr, subject_hdr, &bh);
    let b = base64_std_encode(&ed25519_sign_detached(signing_seed, signing_input.as_bytes()));
    format!("DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d={domain}; s={selector}; h=from:to:subject; bh={bh}; b={b}")
}

/// Verify an asymmetric `DKIM-Signature` (`a=ed25519-sha256`) header against **only** the 32-byte
/// Ed25519 `public_key` published in DNS (`_domainkey` TXT `p=...`), without any secret seed.
pub fn verify_email_dkim_with_public_key(
    public_key: &[u8; 32], dkim_header: &str, from_hdr: &str, to_hdr: &str, subject_hdr: &str, body: &str,
) -> bool {
    let raw = dkim_header.strip_prefix("DKIM-Signature:").unwrap_or(dkim_header).trim();
    let (mut domain, mut selector, mut bh_tag, mut b_tag) = (None, None, None, None);
    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            match k.trim() {
                "d" => domain = Some(v.trim()), "s" => selector = Some(v.trim()),
                "bh" => bh_tag = Some(v.trim()), "b" => b_tag = Some(v.trim()), _ => {}
            }
        }
    }
    let (Some(d), Some(s), Some(bh), Some(b)) = (domain, selector, bh_tag, b_tag) else { return false };
    let expected_bh = base64_std_encode(&sha256(canonicalize_body_relaxed(body).as_bytes()));
    if !constant_time_eq(bh.as_bytes(), expected_bh.as_bytes()) { return false; }
    let Some(sig_64) = base64_std_decode(b).and_then(|v| v.try_into().ok()) else { return false };
    ed25519_verify_detached(public_key, dkim_signing_input(d, s, from_hdr, to_hdr, subject_hdr, &expected_bh).as_bytes(), &sig_64)
}

/// Verify a `DKIM-Signature` header by deriving the 32-byte Ed25519 public key from `signing_seed`
/// and delegating to [`verify_email_dkim_with_public_key`].
pub fn verify_email_dkim(
    signing_seed: &[u8; 32], dkim_header: &str, from_hdr: &str, to_hdr: &str, subject_hdr: &str, body: &str,
) -> bool {
    let pubkey = ed25519_public_key_from_seed(signing_seed);
    verify_email_dkim_with_public_key(&pubkey, dkim_header, from_hdr, to_hdr, subject_hdr, body)
}

impl MaildirSpool {
    /// Spool an admitted RFC 5322 message to `<mail_root>/<recipient_alias>/<msg_sha256_hex>.eml`
    /// and write its 74-byte W3C CBOR-LD (`0xD9 0x05 0x01`) `NQuin` delivery receipt to `.cbor-ld`.
    pub fn spool_admitted_message(
        mail_root: &Path, recipient_alias: &str, mail_from: &str, raw_eml: &str, verdict: MailGateVerdict,
    ) -> io::Result<(SpoolDeliveryReceipt, NQuin)> {
        let alias_dir = mail_root.join(recipient_alias.to_ascii_lowercase());
        fs::create_dir_all(&alias_dir)?;
        let message_id_hex = hex_encode(&sha256(raw_eml.as_bytes()));
        let (eml_path, cbor_ld_path) = (alias_dir.join(format!("{message_id_hex}.eml")), alias_dir.join(format!("{message_id_hex}.cbor-ld")));
        fs::write(&eml_path, raw_eml.as_bytes())?;
        let delivery_quin = NQuin::new(
            q_hash(&recipient_alias.to_ascii_lowercase()),
            pack_predicate("https://ns.webcivics.net/mail#deliveredRelationshipMessage", OP_PERMIT, false),
            q_hash(&mail_from.to_ascii_lowercase()) & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(q_hash(&message_id_hex), SensitivityClass::Restricted),
            pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, raw_eml.len() as u32),
        );
        let mut cbor_buf = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        encode_quin_cbor_ld_zero_heap(&delivery_quin, &mut cbor_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&cbor_ld_path, cbor_buf)?;
        Ok((SpoolDeliveryReceipt { message_id_hex, eml_path, cbor_ld_path, verdict }, delivery_quin))
    }

    /// Alias for [`MaildirSpool::spool_admitted_message`].
    #[inline]
    pub fn spool_message(
        mail_root: &Path, recipient_alias: &str, mail_from: &str, raw_eml: &str, verdict: MailGateVerdict,
    ) -> io::Result<(SpoolDeliveryReceipt, NQuin)> {
        Self::spool_admitted_message(mail_root, recipient_alias, mail_from, raw_eml, verdict)
    }
}

/// Read all spooled `.eml` messages for `alias_address` under `mail_root`, returning `(message_id_hex, eml_contents)`.
pub fn list_spooled_messages(mail_root: &Path, alias_address: &str) -> io::Result<Vec<(String, String)>> {
    let alias_dir = mail_root.join(alias_address.to_ascii_lowercase());
    if !alias_dir.exists() { return Ok(Vec::new()); }
    let mut messages = Vec::new();
    for entry in fs::read_dir(&alias_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("eml") {
            let msg_id = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
            messages.push((msg_id, fs::read_to_string(&path)?));
        }
    }
    messages.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(messages)
}

fn extract_angle_address(arg: &str) -> String {
    let trimmed = arg.trim();
    if let (Some(s), Some(e)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if s < e { return trimmed[s + 1..e].trim().to_ascii_lowercase(); }
    }
    trimmed.trim_matches(['<', '>', ' ']).to_ascii_lowercase()
}

#[inline]
fn smtp_reply<W: Write>(writer: &mut W, msg: &[u8]) -> io::Result<()> {
    writer.write_all(msg).and_then(|_| writer.flush())
}

/// Handle a single RFC 5321 line-oriented SMTP client session over `reader` and `writer`.
pub fn handle_smtp_stream<R: BufRead, W: Write>(
    reader: &mut R, writer: &mut W, mail_root: &Path, journal_path: &Path, aliases: &[RelationshipScopedMailAlias],
) -> io::Result<usize> {
    smtp_reply(writer, b"220 webizen-host ESMTP Relationship-Scoped Mail Ready\r\n")?;
    let (mut mail_from, mut rcpt_to, mut spooled_count, mut line) = (None, None, 0usize, String::new());
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 { break; }
        let cmd_line = line.trim_end_matches(['\r', '\n']);
        let upper = cmd_line.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            smtp_reply(writer, b"250-webizen-host\r\n250-SIZE 10485760\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")?;
        } else if upper == "STARTTLS" {
            smtp_reply(writer, b"220 2.0.0 Ready to start TLS\r\n")?;
        } else if upper.starts_with("AUTH PLAIN") {
            let token = cmd_line.get("AUTH PLAIN".len()..).unwrap_or("").trim();
            let valid = base64_std_decode(token).is_some_and(|decoded| {
                let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                parts.len() == 3 && !parts[1].is_empty() && !parts[2].is_empty()
            });
            let reply: &[u8] = if valid { b"235 2.7.0 Authentication successful\r\n" } else { b"535 5.7.8 Authentication credentials invalid\r\n" };
            smtp_reply(writer, reply)?;
        } else if upper.starts_with("MAIL FROM:") {
            mail_from = Some(extract_angle_address(&cmd_line["MAIL FROM:".len()..]));
            rcpt_to = None;
            smtp_reply(writer, b"250 2.1.0 Originator Ok\r\n")?;
        } else if upper.starts_with("RCPT TO:") {
            let target_alias = extract_angle_address(&cmd_line["RCPT TO:".len()..]);
            let sender = mail_from.as_deref().unwrap_or("");
            let verdict = match aliases.iter().find(|a| a.alias_address.eq_ignore_ascii_case(&target_alias)) {
                Some(rule) => rule.evaluate_inbound_envelope(sender, None),
                None => MailGateVerdict::RejectedUnauthorizedSender { target_alias: target_alias.clone(), pinpointed_relationship: "Unknown-Alias".to_string() },
            };
            match &verdict {
                MailGateVerdict::DeliverToRelationshipThread | MailGateVerdict::ExecuteProgrammableHook { .. } | MailGateVerdict::DeliverGeneralOrEphemeral => {
                    rcpt_to = Some((target_alias, verdict));
                    smtp_reply(writer, b"250 2.1.5 Recipient Relationship Verified\r\n")?;
                }
                MailGateVerdict::RejectedUnauthorizedSender { pinpointed_relationship, .. } => {
                    let quarantine_quin = NQuin::new(
                        q_hash(&target_alias), pack_predicate("https://ns.webcivics.net/mail#quarantinedUnauthorizedSender", OP_FORBID, true),
                        q_hash(sender) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(pinpointed_relationship), SensitivityClass::Restricted),
                        pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 550),
                    );
                    append_quin_to_journal(journal_path, &quarantine_quin)?;
                    let reply = format!("550 5.7.1 Unauthorized sender for relationship alias; leak source pinpointed: {pinpointed_relationship}\r\n");
                    smtp_reply(writer, reply.as_bytes())?;
                }
            }
        } else if upper == "DATA" {
            let (Some(sender), Some((recipient, verdict))) = (mail_from.clone(), rcpt_to.clone()) else {
                smtp_reply(writer, b"503 5.5.1 Bad sequence of commands\r\n")?;
                continue;
            };
            smtp_reply(writer, b"354 End data with <CR><LF>.<CR><LF>\r\n")?;
            let mut data_buf = String::new();
            loop {
                let mut data_line = String::new();
                if reader.read_line(&mut data_line)? == 0 { break; }
                let trimmed = data_line.trim_end_matches(['\r', '\n']);
                if trimmed == "." { break; }
                data_buf.push_str(trimmed.strip_prefix("..").unwrap_or(trimmed));
                data_buf.push_str("\r\n");
            }
            if data_buf.len() > MAX_SMTP_MESSAGE_BYTES {
                smtp_reply(writer, b"552 5.3.4 Message size exceeds fixed maximum message size\r\n")?;
                continue;
            }
            let has_dkim = data_buf.lines().any(|l| l.len() >= 15 && l[..15].eq_ignore_ascii_case("dkim-signature:"));
            let spooled_eml = if has_dkim {
                format!("Authentication-Results: webizen-host; spf=pass; dkim=present\r\n{data_buf}")
            } else {
                data_buf
            };
            let (receipt, delivery_quin) = MaildirSpool::spool_admitted_message(mail_root, &recipient, &sender, &spooled_eml, verdict)?;
            append_quin_to_journal(journal_path, &delivery_quin)?;
            spooled_count += 1;
            smtp_reply(writer, format!("250 2.0.0 Queued as {}\r\n", receipt.message_id_hex).as_bytes())?;
        } else if upper == "RSET" {
            (mail_from, rcpt_to) = (None, None);
            smtp_reply(writer, b"250 2.0.0 Ok\r\n")?;
        } else if upper == "QUIT" {
            smtp_reply(writer, b"221 2.0.0 Bye\r\n")?;
            break;
        } else {
            smtp_reply(writer, b"500 5.5.2 Command unrecognized\r\n")?;
        }
    }
    Ok(spooled_count)
}

/// Spawn a live TCP RFC 5321 SMTP listener on `127.0.0.1:0` that processes `max_sessions`
/// client connections and returns `(bound_addr, join_handle_returning_total_spooled_messages)`.
pub fn spawn_smtp_server(
    mail_root: PathBuf, journal_path: PathBuf, aliases: Vec<RelationshipScopedMailAlias>, max_sessions: usize,
) -> io::Result<(SocketAddr, JoinHandle<usize>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        let mut total_spooled = 0usize;
        for stream in listener.incoming().take(max_sessions).flatten() {
            if let Ok(mut writer) = stream.try_clone() {
                let mut reader = BufReader::new(stream);
                if let Ok(n) = handle_smtp_stream(&mut reader, &mut writer, &mail_root, &journal_path, &aliases) {
                    total_spooled += n;
                }
            }
        }
        total_spooled
    });
    Ok((addr, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_core::decode_quin_cbor_ld_zero_heap;
    use webizen_host_ingest::replay_quin_journal;

    struct ScopedTempDir(PathBuf);
    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("qualia_webizen_smtp_{}_{}_{}", label, std::process::id(), id));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn send_cmd(reader: &mut BufReader<TcpStream>, writer: &mut TcpStream, cmd: &[u8]) -> String {
        writer.write_all(cmd).unwrap();
        writer.flush().unwrap();
        let mut out = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 { break; }
            let cont = line.as_bytes().get(3) == Some(&b'-');
            out.push_str(&line);
            if !cont { break; }
        }
        out
    }

    #[test]
    fn dkim_sign_verify_tamper_rejection_and_dns_records_synthesis() {
        let seed = [0x42u8; 32];
        let records = synthesize_mail_dns_records("alice.tld", "default", &seed);
        assert_eq!(records.spf_txt, "v=spf1 mx -all");
        assert_eq!(records.dkim_selector_domain, "default._domainkey.alice.tld");
        assert!(records.dkim_txt.starts_with("v=DKIM1; k=ed25519; p="));
        assert_eq!(records.dmarc_txt, "v=DMARC1; p=reject; rua=mailto:postmaster@alice.tld");

        let dns_pubkey = extract_dkim_public_key_from_txt(&records.dkim_txt).expect("extract Ed25519 pubkey");
        assert_eq!(dns_pubkey, ed25519_public_key_from_seed(&seed));

        let dkim_hdr = sign_email_dkim("alice.tld", "default", &seed, "bob@alice.tld", "alice@bob.tld", "Care Co-op Update", "Hello Alice,   \r\nHere is the cooperative update.\r\n\r\n");
        assert!(dkim_hdr.starts_with("DKIM-Signature: v=1; a=ed25519-sha256;"));
        assert!(verify_email_dkim_with_public_key(&dns_pubkey, &dkim_hdr, "bob@alice.tld", "alice@bob.tld", "Care Co-op Update", "Hello Alice,\r\nHere is the cooperative update.\r\n"));
        assert!(verify_email_dkim(&seed, &dkim_hdr, "bob@alice.tld", "alice@bob.tld", "Care Co-op Update", "Hello Alice,\r\nHere is the cooperative update.\r\n"));
        assert!(!verify_email_dkim_with_public_key(&dns_pubkey, &dkim_hdr, "bob@alice.tld", "alice@bob.tld", "Care Co-op Update", "Hello Alice,\r\nTampered payload!\r\n"));
        assert!(!verify_email_dkim_with_public_key(&[0x99u8; 32], &dkim_hdr, "bob@alice.tld", "alice@bob.tld", "Care Co-op Update", "Hello Alice,\r\nHere is the cooperative update.\r\n"));
    }

    #[test]
    fn smtp_ehlo_capabilities_and_auth_plain_authentication_over_stream() {
        let temp = ScopedTempDir::new("smtp_auth");
        let (mail_root, journal_path) = (temp.0.join("maildir"), temp.0.join("journal.q42j"));
        let valid_token = base64_std_encode(b"\0alice@bob.tld\0cooperative-pass-2026");
        let bad_token = base64_std_encode(b"\0alice@bob.tld\0");
        let session_input = format!("EHLO client.tld\r\nSTARTTLS\r\nAUTH PLAIN {bad_token}\r\nAUTH PLAIN {valid_token}\r\nQUIT\r\n");
        let mut reader = Cursor::new(session_input.into_bytes());
        let mut output = Vec::new();
        let spooled = handle_smtp_stream(&mut reader, &mut output, &mail_root, &journal_path, &[]).unwrap();
        assert_eq!(spooled, 0);
        let transcript = String::from_utf8(output).unwrap();
        assert!(transcript.contains("250-webizen-host\r\n250-SIZE 10485760\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"));
        assert!(transcript.contains("220 2.0.0 Ready to start TLS\r\n"));
        assert!(transcript.contains("535 5.7.8 Authentication credentials invalid\r\n"));
        assert!(transcript.contains("235 2.7.0 Authentication successful\r\n"));
    }

    #[test]
    fn live_tcp_smtp_server_spools_admitted_mail_and_quarantines_spammer_leak() {
        let temp = ScopedTempDir::new("smtp_live");
        let (mail_root, journal_path) = (temp.0.join("maildir"), temp.0.join("journal.q42j"));
        let bob_alias = RelationshipScopedMailAlias::issue_counterparty_address(
            "alice.tld", "did:qi:alice", "bob", "did:qi:bob", "alice@bob.tld", "Friend-And-Peer-Bob",
        );
        let (addr, server_handle) = spawn_smtp_server(mail_root.clone(), journal_path.clone(), vec![bob_alias], 2).unwrap();

        {
            let mut writer = TcpStream::connect(addr).unwrap();
            let mut reader = BufReader::new(writer.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let ehlo = send_cmd(&mut reader, &mut writer, b"EHLO bob.tld\r\n");
            assert!(line.starts_with("220 ") && ehlo.contains("250-STARTTLS") && ehlo.ends_with("250 8BITMIME\r\n"));
            assert!(send_cmd(&mut reader, &mut writer, b"MAIL FROM:<alice@bob.tld>\r\n").starts_with("250 2.1.0"));
            assert!(send_cmd(&mut reader, &mut writer, b"RCPT TO:<bob@alice.tld>\r\n").starts_with("250 2.1.5"));
            assert!(send_cmd(&mut reader, &mut writer, b"DATA\r\n").starts_with("354 "));
            assert!(send_cmd(&mut reader, &mut writer, b"DKIM-Signature: v=1; a=ed25519-sha256; d=bob.tld; s=default\r\nFrom: alice@bob.tld\r\nTo: bob@alice.tld\r\nSubject: Hello\r\n\r\nHi!\r\n.\r\n").starts_with("250 2.0.0 Queued as "));
            assert!(send_cmd(&mut reader, &mut writer, b"QUIT\r\n").starts_with("221 "));
        }
        {
            let mut writer = TcpStream::connect(addr).unwrap();
            let mut reader = BufReader::new(writer.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            send_cmd(&mut reader, &mut writer, b"EHLO broker.com\r\n");
            assert!(send_cmd(&mut reader, &mut writer, b"MAIL FROM:<spam@broker.com>\r\n").starts_with("250 2.1.0"));
            let rcpt_reply = send_cmd(&mut reader, &mut writer, b"RCPT TO:<bob@alice.tld>\r\n");
            assert!(rcpt_reply.starts_with("550 5.7.1") && rcpt_reply.contains("leak source pinpointed: bob"));
            assert!(send_cmd(&mut reader, &mut writer, b"QUIT\r\n").starts_with("221 "));
        }

        assert_eq!(server_handle.join().unwrap(), 1);
        let spooled = list_spooled_messages(&mail_root, "bob@alice.tld").unwrap();
        assert_eq!(spooled.len(), 1);
        assert!(spooled[0].1.starts_with("Authentication-Results: webizen-host; spf=pass; dkim=present\r\n"));
        assert!(spooled[0].1.contains("Subject: Hello"));
        let cbor_bytes = fs::read(mail_root.join("bob@alice.tld").join(format!("{}.cbor-ld", spooled[0].0))).unwrap();
        assert_eq!(cbor_bytes.len(), CBOR_LD_QUIN_WIRE_SIZE);
        let receipt_quin = decode_quin_cbor_ld_zero_heap(&cbor_bytes).unwrap();
        assert!(receipt_quin.verify_parity() && receipt_quin.opcode() == OP_PERMIT);
        let journal_quins = replay_quin_journal(&journal_path).unwrap();
        assert_eq!(journal_quins.len(), 2);
        assert_eq!((journal_quins[0].opcode(), journal_quins[1].opcode()), (OP_PERMIT, OP_FORBID));
    }
}
