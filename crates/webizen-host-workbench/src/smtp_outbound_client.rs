//! Outbound SMTP Relay Queue, DNS MX/A Resolution & RFC 3464 DSN Bounce Worker (`WP-16` / `WP-21`).
//!
//! Provides a live TCP RFC 5321 outbound SMTP relay client (`OutboundSmtpRelayClient`),
//! `NQuinDnsZoneRing` MX/A lookup, RFC 3464 DSN bounce generation on `5xx` permanent rejections,
//! RFC 5321 §4.5.2 dot-stuffing, and bitemporal `journal.q42j` `NQuin` delivery receipts.

use std::fs;
use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use webizen_host_core::{
    pack_context, pack_metadata, pack_predicate, q_hash, validate_human_centric_nomenclature,
    NQuin, PermissiveRoutingLane, SensitivityClass, OP_PERMIT,
};
use webizen_host_dns::{DnsQueryContext, DnsRrType, NQuinDnsZoneRing};
use webizen_host_ingest::append_quin_to_journal;

use crate::smtp_mail::{spawn_smtp_server, SmtpWireServer};
use crate::RelationshipScopedMailAlias;

/// Default TCP connect and socket read/write timeout for outbound MX relay sessions.
pub const DEFAULT_OUTBOUND_SMTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Retry state metadata tracked across outbound SMTP relay attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundRetryMetadata {
    pub attempts: u32,
    pub max_attempts: u32,
    pub last_error: String,
}

/// Receipt emitted when an outbound `.eml` message is delivered over TCP to a remote MX endpoint,
/// moved from `mail_root/outbox/` to `mail_root/sent/`, and recorded in `journal.q42j`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundSmtpDeliveryReceipt {
    pub message_id: String,
    pub from_addr: String,
    pub to_addr: String,
    pub mx_endpoint: SocketAddr,
    pub remote_250_status: String,
    pub sent_path: PathBuf,
    pub delivery_quin: NQuin,
}

/// Outbound RFC 5321 TCP SMTP MX delivery client and `maildir/outbox` queue worker.
pub struct OutboundSmtpRelayClient;

impl SmtpWireServer {
    /// Spawn a live background TCP RFC 5321 SMTP listener on `127.0.0.1:0` that serves
    /// `max_sessions` client sessions and returns `(bound_addr, join_handle)`.
    pub fn spawn_background_server(
        mail_root: PathBuf, journal_path: PathBuf, aliases: Vec<RelationshipScopedMailAlias>, max_sessions: usize,
    ) -> io::Result<(SocketAddr, JoinHandle<usize>)> {
        spawn_smtp_server(mail_root, journal_path, aliases, max_sessions)
    }
}

fn normalize_header_address(raw: &str) -> String {
    let trimmed = raw.trim();
    if let (Some(s), Some(e)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if s < e { return trimmed[s + 1..e].trim().to_string(); }
    }
    trimmed.trim_matches(['<', '>', ' ']).to_string()
}

/// Extract `(from_addr, to_addr)` from RFC 5322 headers at the top of `raw_eml`.
pub fn extract_eml_envelope_addresses(raw_eml: &str) -> io::Result<(String, String)> {
    let (mut from_addr, mut to_addr, mut fallback_rcpt) = (String::new(), String::new(), String::new());
    for line in raw_eml.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() { break; }
        if let Some((name, val)) = trimmed.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "from" if from_addr.is_empty() => from_addr = normalize_header_address(val),
                "to" if to_addr.is_empty() => to_addr = normalize_header_address(val),
                "x-webizen-recipient" if fallback_rcpt.is_empty() => fallback_rcpt = normalize_header_address(val),
                _ => {}
            }
        }
    }
    if to_addr.is_empty() && !fallback_rcpt.is_empty() { to_addr = fallback_rcpt; }
    if from_addr.is_empty() || to_addr.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "Outbound .eml missing required From: or To: header"));
    }
    Ok((from_addr, to_addr))
}

/// Read a single- or multi-line RFC 5321 SMTP response (`XYZ-...` followed by `XYZ ...`),
/// returning `(status_code, final_line)`.
fn read_smtp_response<R: BufRead>(reader: &mut R) -> io::Result<(u16, String)> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "Remote SMTP server closed connection"));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Malformed SMTP reply: {trimmed}")));
        }
        let code: u16 = trimmed[0..3].parse().map_err(|_| {
            io::Error::new(ErrorKind::InvalidData, format!("Invalid SMTP status code: {trimmed}"))
        })?;
        if trimmed.as_bytes().get(3) != Some(&b'-') {
            return Ok((code, trimmed.to_string()));
        }
    }
}

#[inline]
fn send_smtp_command<W: Write>(writer: &mut W, cmd: &str) -> io::Result<()> {
    writer.write_all(cmd.as_bytes()).and_then(|_| writer.flush())
}

#[inline]
fn status_error_kind(code: u16) -> ErrorKind {
    if (500..600).contains(&code) { ErrorKind::PermissionDenied } else { ErrorKind::InvalidData }
}

impl OutboundSmtpRelayClient {
    /// Deliver an RFC 5322 `.eml` payload over a live TCP connection to `mx_addr` with
    /// RFC 5321 §4.5.2 transparency dot-stuffing and `5xx` error classification.
    pub fn deliver_eml_over_tcp(
        mx_addr: SocketAddr, helo_domain: &str, mail_from: &str, rcpt_to: &str, raw_eml: &str,
    ) -> io::Result<String> {
        for field in [helo_domain, mail_from, rcpt_to, raw_eml] {
            validate_human_centric_nomenclature(field)
                .map_err(|msg| io::Error::new(ErrorKind::InvalidInput, msg))?;
        }
        let mut writer = TcpStream::connect_timeout(&mx_addr, DEFAULT_OUTBOUND_SMTP_TIMEOUT)?;
        writer.set_read_timeout(Some(DEFAULT_OUTBOUND_SMTP_TIMEOUT))?;
        writer.set_write_timeout(Some(DEFAULT_OUTBOUND_SMTP_TIMEOUT))?;
        let mut reader = BufReader::new(writer.try_clone()?);

        let (greet_code, greet_line) = read_smtp_response(&mut reader)?;
        if greet_code != 220 {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Expected 220 greeting, got: {greet_line}")));
        }
        send_smtp_command(&mut writer, &format!("EHLO {}\r\n", helo_domain.trim()))?;
        let (ehlo_code, ehlo_line) = read_smtp_response(&mut reader)?;
        if ehlo_code != 250 {
            return Err(io::Error::new(status_error_kind(ehlo_code), ehlo_line));
        }
        let clean_from = normalize_header_address(mail_from);
        send_smtp_command(&mut writer, &format!("MAIL FROM:<{clean_from}>\r\n"))?;
        let (mail_code, mail_line) = read_smtp_response(&mut reader)?;
        if mail_code != 250 {
            let _ = (send_smtp_command(&mut writer, "QUIT\r\n"), read_smtp_response(&mut reader));
            return Err(io::Error::new(status_error_kind(mail_code), mail_line));
        }
        let clean_rcpt = normalize_header_address(rcpt_to);
        send_smtp_command(&mut writer, &format!("RCPT TO:<{clean_rcpt}>\r\n"))?;
        let (rcpt_code, rcpt_line) = read_smtp_response(&mut reader)?;
        if rcpt_code != 250 {
            let _ = (send_smtp_command(&mut writer, "QUIT\r\n"), read_smtp_response(&mut reader));
            return Err(io::Error::new(status_error_kind(rcpt_code), rcpt_line));
        }
        send_smtp_command(&mut writer, "DATA\r\n")?;
        let (data_code, data_line) = read_smtp_response(&mut reader)?;
        if data_code != 354 {
            let _ = send_smtp_command(&mut writer, "QUIT\r\n");
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Expected 354 DATA, got: {data_line}")));
        }
        for line in raw_eml.lines() {
            let clean_line = line.trim_end_matches('\r');
            if clean_line.starts_with('.') { writer.write_all(b".")?; }
            writer.write_all(clean_line.as_bytes())?;
            writer.write_all(b"\r\n")?;
        }
        writer.write_all(b".\r\n")?;
        writer.flush()?;

        let (accept_code, accept_line) = read_smtp_response(&mut reader)?;
        let _ = (send_smtp_command(&mut writer, "QUIT\r\n"), read_smtp_response(&mut reader));
        if accept_code != 250 {
            return Err(io::Error::new(status_error_kind(accept_code), accept_line));
        }
        Ok(accept_line)
    }

    /// Scan `mail_root.join("outbox")` for queued `*.eml` messages, deliver each over TCP to
    /// `mx_addr`, archive delivered messages in `mail_root.join("sent")`, remove them from
    /// `outbox/`, and append an `OP_PERMIT` `https://ns.webcivics.net/mail#outboundMxDelivered`
    /// `NQuin` receipt to `journal_path`.
    pub fn flush_outbox_queue(
        mail_root: &Path, journal_path: &Path, mx_addr: SocketAddr, helo_domain: &str,
    ) -> io::Result<Vec<OutboundSmtpDeliveryReceipt>> {
        let queued_files = collect_outbox_files(&mail_root.join("outbox"))?;
        if queued_files.is_empty() { return Ok(Vec::new()); }
        let sent_dir = mail_root.join("sent");
        fs::create_dir_all(&sent_dir)?;
        let mut receipts = Vec::with_capacity(queued_files.len());
        for (message_id, outbox_path) in queued_files {
            let raw_eml = fs::read_to_string(&outbox_path)?;
            let (from_addr, to_addr) = extract_eml_envelope_addresses(&raw_eml)?;
            let remote_250_status =
                Self::deliver_eml_over_tcp(mx_addr, helo_domain, &from_addr, &to_addr, &raw_eml)?;
            receipts.push(record_sent_delivery(
                &sent_dir, journal_path, message_id, &outbox_path, from_addr, to_addr, mx_addr, remote_250_status, &raw_eml,
            )?);
        }
        Ok(receipts)
    }

    /// Resolve each queued `.eml` recipient domain against `dns_ring` (`DnsRrType::A` on `<domain>`
    /// or `mail.<domain>`, falling back to `127.0.0.1`) with `fallback_port`, deliver over TCP,
    /// and generate an RFC 3464 DSN bounce `.eml` in `mail_root/new/bounce-<id>.eml` on `5xx` rejection.
    pub fn resolve_mx_and_flush_outbox(
        mail_root: &Path, journal_path: &Path, dns_ring: &NQuinDnsZoneRing, fallback_port: u16, helo_domain: &str,
    ) -> io::Result<(Vec<OutboundSmtpDeliveryReceipt>, Vec<PathBuf>)> {
        let queued_files = collect_outbox_files(&mail_root.join("outbox"))?;
        if queued_files.is_empty() { return Ok((Vec::new(), Vec::new())); }
        let (sent_dir, new_dir) = (mail_root.join("sent"), mail_root.join("new"));
        fs::create_dir_all(&sent_dir)?;
        fs::create_dir_all(&new_dir)?;
        let dns_ctx = DnsQueryContext {
            has_valid_dni_cookie: true, has_webizen_id_tls_session: true, requester_jurisdiction_hash: q_hash("AU"),
        };
        let (mut receipts, mut bounces) = (Vec::new(), Vec::new());
        for (message_id, outbox_path) in queued_files {
            let raw_eml = fs::read_to_string(&outbox_path)?;
            let (from_addr, to_addr) = extract_eml_envelope_addresses(&raw_eml)?;
            let rcpt_domain = to_addr.split_once('@').map(|(_, d)| d.trim()).unwrap_or("localhost");
            let ipv4 = dns_ring
                .resolve_zero_heap(&format!("mail.{rcpt_domain}"), DnsRrType::A, &dns_ctx).1
                .or_else(|| dns_ring.resolve_zero_heap(rcpt_domain, DnsRrType::A, &dns_ctx).1)
                .map(|q| (q.object as u32).to_be_bytes())
                .filter(|&ip| ip != [0, 0, 0, 0])
                .unwrap_or([127, 0, 0, 1]);
            let mx_addr = SocketAddr::from((ipv4, fallback_port));
            match Self::deliver_eml_over_tcp(mx_addr, helo_domain, &from_addr, &to_addr, &raw_eml) {
                Ok(remote_250_status) => receipts.push(record_sent_delivery(
                    &sent_dir, journal_path, message_id, &outbox_path, from_addr, to_addr, mx_addr, remote_250_status, &raw_eml,
                )?),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    let bounce_path = new_dir.join(format!("bounce-{message_id}.eml"));
                    let dsn_eml = format!(
                        "From: MAILER-DAEMON@{}\r\nTo: {from_addr}\r\nSubject: Undelivered Mail Returned to Sender\r\nContent-Type: multipart/report; report-type=delivery-status\r\n\r\nFinal-Recipient: rfc822; {to_addr}\r\nAction: failed\r\nStatus: 5.7.1\r\nDiagnostic-Code: smtp; {e}\r\n",
                        helo_domain.trim()
                    );
                    fs::write(&bounce_path, dsn_eml.as_bytes())?;
                    fs::remove_file(&outbox_path)?;
                    bounces.push(bounce_path);
                }
                Err(e) => return Err(e),
            }
        }
        Ok((receipts, bounces))
    }
}

fn collect_outbox_files(outbox_dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    if !outbox_dir.exists() { return Ok(Vec::new()); }
    let mut queued: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(outbox_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("eml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()).filter(|s| !s.is_empty()) {
                queued.push((stem.to_string(), path));
            }
        }
    }
    queued.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(queued)
}

#[allow(clippy::too_many_arguments)]
fn record_sent_delivery(
    sent_dir: &Path, journal_path: &Path, message_id: String, outbox_path: &Path, from_addr: String,
    to_addr: String, mx_endpoint: SocketAddr, remote_250_status: String, raw_eml: &str,
) -> io::Result<OutboundSmtpDeliveryReceipt> {
    let sent_path = sent_dir.join(format!("{message_id}.eml"));
    fs::write(&sent_path, raw_eml.as_bytes())?;
    fs::remove_file(outbox_path)?;
    let delivery_quin = NQuin::new(
        q_hash(&from_addr.to_ascii_lowercase()),
        pack_predicate("https://ns.webcivics.net/mail#outboundMxDelivered", OP_PERMIT, false),
        q_hash(&to_addr.to_ascii_lowercase()) & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash(&message_id), SensitivityClass::Restricted),
        pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, raw_eml.len() as u32),
    );
    append_quin_to_journal(journal_path, &delivery_quin)?;
    Ok(OutboundSmtpDeliveryReceipt {
        message_id, from_addr, to_addr, mx_endpoint, remote_250_status, sent_path, delivery_quin,
    })
}

/// Convenience free-function wrapper around [`OutboundSmtpRelayClient::deliver_eml_over_tcp`].
#[inline]
pub fn deliver_eml_over_tcp(
    mx_addr: SocketAddr, helo_domain: &str, mail_from: &str, rcpt_to: &str, raw_eml: &str,
) -> io::Result<String> {
    OutboundSmtpRelayClient::deliver_eml_over_tcp(mx_addr, helo_domain, mail_from, rcpt_to, raw_eml)
}

/// Convenience free-function wrapper around [`OutboundSmtpRelayClient::flush_outbox_queue`].
#[inline]
pub fn flush_outbox_queue(
    mail_root: &Path, journal_path: &Path, mx_addr: SocketAddr, helo_domain: &str,
) -> io::Result<Vec<OutboundSmtpDeliveryReceipt>> {
    OutboundSmtpRelayClient::flush_outbox_queue(mail_root, journal_path, mx_addr, helo_domain)
}

/// Convenience free-function wrapper around [`OutboundSmtpRelayClient::resolve_mx_and_flush_outbox`].
#[inline]
pub fn resolve_mx_and_flush_outbox(
    mail_root: &Path, journal_path: &Path, dns_ring: &NQuinDnsZoneRing, fallback_port: u16, helo_domain: &str,
) -> io::Result<(Vec<OutboundSmtpDeliveryReceipt>, Vec<PathBuf>)> {
    OutboundSmtpRelayClient::resolve_mx_and_flush_outbox(mail_root, journal_path, dns_ring, fallback_port, helo_domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jmap_maildir_api::JmapMaildirEngine;
    use crate::smtp_mail::{list_spooled_messages, verify_email_dkim};
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_core::{OP_FORBID, OP_OBLIGATE};
    use webizen_host_ingest::replay_quin_journal;

    struct ScopedTempDir(PathBuf);
    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("qualia_webizen_outbound_smtp_{}_{}_{}", label, std::process::id(), id));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn outbound_smtp_queue_flushes_dkim_signed_mail_over_live_tcp_to_remote_mx() {
        let temp = ScopedTempDir::new("live_flush");
        let (sender_mail_root, sender_journal) = (temp.0.join("sender_maildir"), temp.0.join("sender_journal.q42j"));
        let (remote_mail_root, remote_journal) = (temp.0.join("remote_maildir"), temp.0.join("remote_journal.q42j"));

        let bob_at_alice = RelationshipScopedMailAlias::issue_counterparty_address(
            "alice.tld", "did:qi:alice", "bob", "did:qi:bob", "alice@bob.tld", "Cooperative-Peer-Relationship",
        );
        let (mx_addr, server_handle) = SmtpWireServer::spawn_background_server(
            remote_mail_root.clone(), remote_journal.clone(), vec![bob_at_alice], 2,
        ).expect("spawn background SMTP server");

        let signing_seed = [0x37u8; 32];
        let body_text = "Hello Alice,\r\nHere is the cooperative quarterly review.\r\nBest regards, Bob.";
        let sub_receipt = JmapMaildirEngine::submit_outbound_dkim_email(
            &sender_mail_root, &sender_journal, "bob.tld", "default", &signing_seed,
            "alice@bob.tld", "bob@alice.tld", "Care Co-op Quarterly Review", body_text,
        ).expect("submit outbound DKIM email");

        let outbox_file = sender_mail_root.join("outbox").join(format!("{}.eml", sub_receipt.message_id));
        assert!(outbox_file.exists());

        let delivered = OutboundSmtpRelayClient::flush_outbox_queue(&sender_mail_root, &sender_journal, mx_addr, "bob.tld")
            .expect("flush outbox queue to live MX");
        assert_eq!(delivered.len(), 1);
        assert_eq!((delivered[0].message_id.as_str(), delivered[0].from_addr.as_str(), delivered[0].to_addr.as_str()), (sub_receipt.message_id.as_str(), "alice@bob.tld", "bob@alice.tld"));
        assert_eq!(delivered[0].mx_endpoint, mx_addr);
        assert!(delivered[0].remote_250_status.starts_with("250 2.0.0 Queued as "));
        assert!(delivered[0].sent_path.exists() && !outbox_file.exists());
        assert!(delivered[0].delivery_quin.verify_parity() && delivered[0].delivery_quin.opcode() == OP_PERMIT);

        let dot_eml = "From: alice@bob.tld\r\nTo: bob@alice.tld\r\nSubject: Dot Transparency\r\n\r\nLine before dot\r\n.\r\nLine after dot\r\n";
        let status2 = OutboundSmtpRelayClient::deliver_eml_over_tcp(mx_addr, "bob.tld", "alice@bob.tld", "bob@alice.tld", dot_eml)
            .expect("deliver dot-stuffed eml");
        assert!(status2.starts_with("250 2.0.0 Queued as "));
        assert_eq!(server_handle.join().expect("join SMTP server"), 2);

        let remote_spooled = list_spooled_messages(&remote_mail_root, "bob@alice.tld").expect("list remote spool");
        assert_eq!(remote_spooled.len(), 2);
        assert!(remote_spooled.iter().any(|(_, eml)| eml.contains("Line after dot")));
        let dkim_spooled = &remote_spooled.iter().find(|(_, eml)| eml.contains("Care Co-op Quarterly Review")).unwrap().1;
        let dkim_line = dkim_spooled.lines().find(|l| l.starts_with("DKIM-Signature:")).expect("DKIM header");
        assert!(verify_email_dkim(&signing_seed, dkim_line, "alice@bob.tld", "bob@alice.tld", "Care Co-op Quarterly Review", body_text));

        let sender_quins = replay_quin_journal(&sender_journal).expect("replay sender journal");
        assert_eq!(sender_quins.len(), 2);
        assert_eq!((sender_quins[0].opcode(), sender_quins[1].opcode()), (OP_OBLIGATE, OP_PERMIT));
        assert_eq!(sender_quins[1].predicate, pack_predicate("https://ns.webcivics.net/mail#outboundMxDelivered", OP_PERMIT, false));
    }

    #[test]
    fn outbound_smtp_client_maps_remote_550_unauthorized_sender_to_permission_denied() {
        let temp = ScopedTempDir::new("reject_550");
        let (sender_mail_root, sender_journal) = (temp.0.join("sender_maildir"), temp.0.join("sender_journal.q42j"));
        let (remote_mail_root, remote_journal) = (temp.0.join("remote_maildir"), temp.0.join("remote_journal.q42j"));

        let bob_at_alice = RelationshipScopedMailAlias::issue_counterparty_address(
            "alice.tld", "did:qi:alice", "bob", "did:qi:bob", "alice@bob.tld", "Trusted-Bob-Only",
        );
        let (mx_addr, server_handle) = SmtpWireServer::spawn_background_server(
            remote_mail_root, remote_journal.clone(), vec![bob_at_alice], 1,
        ).expect("spawn background SMTP server");

        let sub_receipt = JmapMaildirEngine::submit_outbound_dkim_email(
            &sender_mail_root, &sender_journal, "intruder.org", "default", &[0x91u8; 32],
            "unsolicited@intruder.org", "bob@alice.tld", "Unsolicited Marketing Pitch", "Attempting to email alias.",
        ).expect("queue outbound message");

        let err = OutboundSmtpRelayClient::flush_outbox_queue(&sender_mail_root, &sender_journal, mx_addr, "intruder.org")
            .expect_err("remote MX must reject unauthorized sender with 550");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err.to_string().starts_with("550 5.7.1") && err.to_string().contains("leak source pinpointed: bob"));
        assert!(sender_mail_root.join("outbox").join(format!("{}.eml", sub_receipt.message_id)).exists());
        assert_eq!(server_handle.join().expect("join SMTP server"), 0);

        let remote_quins = replay_quin_journal(&remote_journal).expect("replay remote journal");
        assert_eq!(remote_quins.len(), 1);
        assert_eq!(remote_quins[0].opcode(), OP_FORBID);
    }

    #[test]
    fn resolve_mx_and_flush_outbox_resolves_dns_ring_and_generates_rfc3464_bounce_on_550() {
        let temp = ScopedTempDir::new("dns_mx_bounce");
        let (sender_mail_root, sender_journal) = (temp.0.join("sender_maildir"), temp.0.join("sender_journal.q42j"));
        let (remote_mail_root, remote_journal) = (temp.0.join("remote_maildir"), temp.0.join("remote_journal.q42j"));

        let bob_at_alice = RelationshipScopedMailAlias::issue_counterparty_address(
            "alice.tld", "did:qi:alice", "bob", "did:qi:bob", "alice@bob.tld", "Trusted-Bob-Only",
        );
        let (mx_addr, server_handle) = SmtpWireServer::spawn_background_server(
            remote_mail_root, remote_journal, vec![bob_at_alice], 2,
        ).expect("spawn background SMTP server");

        let mut dns_ring = NQuinDnsZoneRing::new();
        dns_ring.upsert_record(
            "alice.tld", DnsRrType::A, u32::from_be_bytes([127, 0, 0, 1]) as u64,
            q_hash("did:qi:alice"), SensitivityClass::Public, 300, 1,
        );

        let ok_sub = JmapMaildirEngine::submit_outbound_dkim_email(
            &sender_mail_root, &sender_journal, "bob.tld", "default", &[0x51u8; 32],
            "alice@bob.tld", "bob@alice.tld", "Authorized Relationship Message", "Hello via DNS MX lookup!",
        ).expect("queue valid message");
        let bad_sub = JmapMaildirEngine::submit_outbound_dkim_email(
            &sender_mail_root, &sender_journal, "intruder.org", "default", &[0x52u8; 32],
            "unsolicited@intruder.org", "bob@alice.tld", "Rejected Message", "Should bounce.",
        ).expect("queue rejected message");

        let (receipts, bounces) = resolve_mx_and_flush_outbox(
            &sender_mail_root, &sender_journal, &dns_ring, mx_addr.port(), "bob.tld",
        ).expect("resolve MX and flush outbox");
        assert_eq!(server_handle.join().expect("join SMTP server"), 1);

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].mx_endpoint, mx_addr);
        assert!(sender_mail_root.join("sent").join(format!("{}.eml", ok_sub.message_id)).exists());

        assert_eq!(bounces.len(), 1);
        let expected_bounce = sender_mail_root.join("new").join(format!("bounce-{}.eml", bad_sub.message_id));
        assert_eq!(bounces[0], expected_bounce);
        assert!(!sender_mail_root.join("outbox").join(format!("{}.eml", bad_sub.message_id)).exists());
        let bounce_text = fs::read_to_string(&expected_bounce).expect("read bounce eml");
        assert!(bounce_text.contains("From: MAILER-DAEMON@bob.tld"));
        assert!(bounce_text.contains("To: unsolicited@intruder.org"));
        assert!(bounce_text.contains("Subject: Undelivered Mail Returned to Sender"));
    }
}
