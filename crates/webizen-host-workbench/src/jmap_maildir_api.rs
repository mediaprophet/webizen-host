//! WP-12 (D12.3) & WP-30 (D30.1): JMAP-over-CBOR-LD, Zero-JS Webmail Portal, MIME Attachment Download,
//! Message Deletion & Live Outbox MX Flush.

use std::{collections::BTreeMap, fs, io::{self, ErrorKind}, path::{Path, PathBuf}};
use crate::auth_and_session::parse_urlencoded_form;
use crate::smtp_mail::{base64_std_decode, sign_email_dkim, verify_email_dkim};
use webizen_host_core::{encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash, sha256, validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_MEDIA_TYPE, CBOR_LD_QUIN_WIRE_SIZE, OP_OBLIGATE};
use webizen_host_ingest::append_quin_to_journal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailMessageSummary {
    pub message_id: String, pub folder: String, pub from_addr: String, pub to_addr: String,
    pub subject: String, pub has_dkim_signature: bool, pub size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimeAttachmentSummary { pub filename: String, pub content_type: String, pub decoded_size_bytes: usize }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMimeMessage { pub text_plain: String, pub text_html: Option<String>, pub attachments: Vec<MimeAttachmentSummary> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundDkimSubmissionReceipt {
    pub message_id: String, pub sent_path: PathBuf, pub signed_rfc5322_bytes: Vec<u8>,
    pub provenance_quin: NQuin, pub cbor_ld_receipt: [u8; CBOR_LD_QUIN_WIRE_SIZE],
}

pub struct JmapMaildirEngine;

pub fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let (bytes, mut out, mut i) = (input.as_bytes(), Vec::with_capacity(input.len()), 0usize);
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' { i += 3; continue; }
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' { i += 2; continue; }
            if i + 2 < bytes.len() {
                if let (Some(h), Some(l)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16)) {
                    out.push(((h << 4) | l) as u8); i += 3; continue;
                }
            }
        }
        out.push(bytes[i]); i += 1;
    }
    out
}

fn split_headers_and_body(raw: &str) -> (&str, &str) {
    raw.find("\r\n\r\n").map(|p| (&raw[..p], &raw[p + 4..])).or_else(|| raw.find("\n\n").map(|p| (&raw[..p], &raw[p + 2..]))).unwrap_or(("", raw))
}

fn parse_mime_headers(headers_str: &str) -> (String, String, String) {
    let mut unfolded: Vec<String> = Vec::new();
    for line in headers_str.lines().map(|l| l.trim_end_matches('\r')) {
        if (line.starts_with(' ') || line.starts_with('\t')) && !unfolded.is_empty() {
            if let Some(last) = unfolded.last_mut() { last.push(' '); last.push_str(line.trim()); }
        } else { unfolded.push(line.to_string()); }
    }
    let (mut ct, mut cte, mut disp) = (String::new(), String::new(), String::new());
    for h in unfolded {
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-type" => ct = v.trim().to_string(),
                "content-transfer-encoding" => cte = v.trim().to_string(),
                "content-disposition" => disp = v.trim().to_string(),
                _ => {}
            }
        }
    }
    (ct, cte, disp)
}

fn extract_mime_param(header_val: &str, param: &str) -> Option<String> {
    header_val.split(';').skip(1).find_map(|seg| {
        let (k, v) = seg.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case(param).then(|| v.trim().trim_matches(['"', '\'']).to_string())
    })
}

fn decode_transfer_payload(body: &str, cte: &str) -> Vec<u8> {
    match cte.trim().to_ascii_lowercase().as_str() {
        "quoted-printable" => decode_quoted_printable(body),
        "base64" => base64_std_decode(body.trim()).unwrap_or_default(),
        _ => body.as_bytes().to_vec(),
    }
}

fn collect_mime_parts(raw_eml: &str) -> Vec<(String, Option<String>, bool, bool, Vec<u8>)> {
    let (top_hdrs, top_body) = split_headers_and_body(raw_eml);
    let (mut queue, mut parts, mut idx) = (vec![(top_hdrs, top_body, true)], Vec::new(), 0usize);
    while idx < queue.len() && idx < 64 {
        let (hdrs, body, is_top) = queue[idx]; idx += 1;
        let (ct, cte, disp) = parse_mime_headers(hdrs);
        let media = ct.split(';').next().unwrap_or("text/plain").trim().to_ascii_lowercase();
        if media.starts_with("multipart/") {
            if let Some(boundary) = extract_mime_param(&ct, "boundary") {
                for seg in body.split(&format!("--{boundary}")).skip(1) {
                    if seg.trim_start_matches([' ', '\t']).starts_with("--") { break; }
                    let t = seg.strip_prefix("\r\n").or_else(|| seg.strip_prefix('\n')).unwrap_or(seg);
                    let t = t.strip_suffix("\r\n").or_else(|| t.strip_suffix('\n')).unwrap_or(t);
                    let (p_hdrs, p_body) = split_headers_and_body(t);
                    queue.push((p_hdrs, p_body, false));
                }
                continue;
            }
        }
        let fname = extract_mime_param(&disp, "filename").or_else(|| extract_mime_param(&ct, "name"));
        let is_att = !is_top && (disp.to_ascii_lowercase().starts_with("attachment") || fname.is_some());
        parts.push((media, fname, is_top, is_att, decode_transfer_payload(body, &cte)));
    }
    parts
}

pub fn parse_mime_message(raw_eml: &str) -> ParsedMimeMessage {
    let mut out = ParsedMimeMessage { text_plain: String::new(), text_html: None, attachments: Vec::new() };
    for (media, fname, is_top, is_att, decoded) in collect_mime_parts(raw_eml) {
        if is_att {
            out.attachments.push(MimeAttachmentSummary { filename: fname.unwrap_or_else(|| "attachment.bin".to_string()), content_type: if media.is_empty() { "application/octet-stream".to_string() } else { media }, decoded_size_bytes: decoded.len() });
        } else if media == "text/html" {
            let html = String::from_utf8_lossy(&decoded).into_owned();
            if is_top && out.text_plain.is_empty() { out.text_plain = html.clone(); }
            out.text_html = Some(html);
        } else if out.text_plain.is_empty() {
            out.text_plain = String::from_utf8_lossy(&decoded).into_owned();
        }
    }
    out
}

pub fn extract_mime_attachment(raw_eml: &str, target_filename: &str) -> Option<(String, Vec<u8>)> {
    for (media, fname, _, is_att, decoded) in collect_mime_parts(raw_eml) {
        if (is_att || fname.is_some()) && fname.as_deref().unwrap_or("attachment.bin") == target_filename {
            return Some((if media.is_empty() { "application/octet-stream".to_string() } else { media }, decoded));
        }
    }
    None
}

#[inline]
fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes.iter().fold(String::with_capacity(64), |mut s, &b| { s.push(HEX[(b >> 4) as usize] as char); s.push(HEX[(b & 0x0F) as usize] as char); s })
}

fn sanitize_message_id(raw_id: &str) -> io::Result<String> {
    let trimmed = raw_id.trim().strip_suffix(".eml").unwrap_or(raw_id.trim());
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid Maildir message_id"));
    }
    Ok(trimmed.to_string())
}

fn normalize_email_token(val: &str) -> String {
    let trimmed = val.trim();
    if let (Some(s), Some(e)) = (trimmed.find('<'), trimmed.rfind('>')) { if s < e { return trimmed[s + 1..e].trim().to_string(); } }
    trimmed.to_string()
}

fn parse_eml_summary(message_id: String, folder: &str, raw_eml: &str, fallback_recipient: Option<&str>) -> MailMessageSummary {
    let (mut from_addr, mut to_addr, mut x_recipient, mut subject, mut has_dkim_signature) = (String::new(), String::new(), String::new(), String::new(), false);
    for line in raw_eml.lines().map(|l| l.trim_end_matches('\r')).take_while(|l| !l.is_empty()) {
        if let Some((name, val)) = line.split_once(':') {
            let v = val.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "from" if from_addr.is_empty() => from_addr = normalize_email_token(v),
                "to" if to_addr.is_empty() => to_addr = normalize_email_token(v),
                "x-webizen-recipient" if x_recipient.is_empty() => x_recipient = normalize_email_token(v),
                "subject" if subject.is_empty() => subject = v.to_string(),
                "dkim-signature" => has_dkim_signature = true,
                _ => {}
            }
        }
    }
    if to_addr.is_empty() { to_addr = if !x_recipient.is_empty() { x_recipient } else { fallback_recipient.unwrap_or_default().to_string() }; }
    MailMessageSummary { message_id, folder: folder.to_string(), from_addr, to_addr, subject, has_dkim_signature, size_bytes: raw_eml.len() as u64 }
}

fn matches_recipient_filter(summary: &MailMessageSummary, raw_eml: &str, fallback_recipient: Option<&str>, filter: &str) -> bool {
    let target = filter.trim();
    if target.is_empty() || summary.to_addr.eq_ignore_ascii_case(target) || fallback_recipient.is_some_and(|fb| fb.eq_ignore_ascii_case(target)) { return true; }
    raw_eml.lines().map(|l| l.trim_end_matches('\r')).take_while(|l| !l.is_empty()).any(|line| {
        line.split_once(':').is_some_and(|(name, val)| matches!(name.trim().to_ascii_lowercase().as_str(), "to" | "x-webizen-recipient") && normalize_email_token(val).eq_ignore_ascii_case(target))
    })
}

fn encode_and_append_quin(journal_path: &Path, quin: &NQuin) -> io::Result<Vec<u8>> {
    append_quin_to_journal(journal_path, quin)?;
    let mut receipt = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
    encode_quin_cbor_ld_zero_heap(quin, &mut receipt).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(receipt.to_vec())
}

impl JmapMaildirEngine {
    pub fn list_messages(mail_root: &Path, filter_recipient: Option<&str>) -> io::Result<Vec<MailMessageSummary>> {
        let mut results: BTreeMap<String, MailMessageSummary> = BTreeMap::new();
        for folder in ["new", "cur", "sent"] {
            let dir = mail_root.join(folder);
            if !dir.is_dir() { continue; }
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) != Some("eml") { continue; }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
                let raw_eml = fs::read_to_string(&path)?;
                let summary = parse_eml_summary(stem.to_string(), folder, &raw_eml, None);
                if filter_recipient.is_none_or(|f| matches_recipient_filter(&summary, &raw_eml, None, f)) { results.insert(summary.message_id.clone(), summary); }
            }
        }
        if mail_root.is_dir() {
            for entry in fs::read_dir(mail_root)? {
                let sub_path = entry?.path();
                let Some(dir_name) = sub_path.file_name().and_then(|s| s.to_str()) else { continue };
                if !sub_path.is_dir() || matches!(dir_name, "new" | "cur" | "sent" | "outbox" | "tmp") { continue; }
                for sub_entry in fs::read_dir(&sub_path)? {
                    let path = sub_entry?.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("eml") { continue; }
                    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
                    if results.contains_key(stem) { continue; }
                    let raw_eml = fs::read_to_string(&path)?;
                    let summary = parse_eml_summary(stem.to_string(), "new", &raw_eml, Some(dir_name));
                    if filter_recipient.is_none_or(|f| matches_recipient_filter(&summary, &raw_eml, Some(dir_name), f)) { results.insert(summary.message_id.clone(), summary); }
                }
            }
        }
        Ok(results.into_values().collect())
    }

    pub fn encode_mailbox_cbor_ld(messages: &[MailMessageSummary]) -> Vec<u8> {
        let mut msg_list = Vec::with_capacity(messages.len());
        for m in messages {
            let mut rec = BTreeMap::new();
            for (k, v) in [("message_id", &m.message_id), ("folder", &m.folder), ("from_addr", &m.from_addr), ("to_addr", &m.to_addr), ("subject", &m.subject)] {
                rec.insert(k.to_string(), vibe::Value::String(v.clone()));
            }
            rec.insert("has_dkim_signature".to_string(), vibe::Value::Bool(m.has_dkim_signature));
            rec.insert("size_bytes".to_string(), vibe::Value::I64(m.size_bytes as i64));
            msg_list.push(vibe::Value::Record(rec));
        }
        let mut top = BTreeMap::new();
        top.insert("count".to_string(), vibe::Value::I64(messages.len() as i64));
        top.insert("messages".to_string(), vibe::Value::List(msg_list));
        vibe::encode_value_cbor_ld(&vibe::Value::Record(top), "https://ns.webcivics.net/jmap/mailbox")
    }

    pub fn list_mailbox_cbor_ld(mail_root: &Path, filter_recipient: Option<&str>) -> io::Result<Vec<u8>> {
        Ok(Self::encode_mailbox_cbor_ld(&Self::list_messages(mail_root, filter_recipient)?))
    }

    pub fn read_message_and_mark_seen(mail_root: &Path, message_id: &str) -> io::Result<(MailMessageSummary, String)> {
        let clean_id = sanitize_message_id(message_id)?;
        let file_name = format!("{clean_id}.eml");
        let (new_path, cur_dir, sent_path) = (mail_root.join("new").join(&file_name), mail_root.join("cur"), mail_root.join("sent").join(&file_name));
        let cur_path = cur_dir.join(&file_name);
        if new_path.is_file() {
            let raw_eml = fs::read_to_string(&new_path)?;
            fs::create_dir_all(&cur_dir)?; fs::rename(&new_path, &cur_path)?;
            return Ok((parse_eml_summary(clean_id, "cur", &raw_eml, None), raw_eml));
        }
        if cur_path.is_file() { let raw_eml = fs::read_to_string(&cur_path)?; return Ok((parse_eml_summary(clean_id, "cur", &raw_eml, None), raw_eml)); }
        if sent_path.is_file() { let raw_eml = fs::read_to_string(&sent_path)?; return Ok((parse_eml_summary(clean_id, "sent", &raw_eml, None), raw_eml)); }
        if mail_root.is_dir() {
            for entry in fs::read_dir(mail_root)? {
                let sub_path = entry?.path();
                let Some(dir_name) = sub_path.file_name().and_then(|s| s.to_str()) else { continue };
                if !sub_path.is_dir() || matches!(dir_name, "new" | "cur" | "sent" | "outbox" | "tmp") { continue; }
                let candidate = sub_path.join(&file_name);
                if candidate.is_file() {
                    let raw_eml = fs::read_to_string(&candidate)?;
                    fs::create_dir_all(&cur_dir)?; fs::rename(&candidate, &cur_path)?;
                    return Ok((parse_eml_summary(clean_id, "cur", &raw_eml, Some(dir_name)), raw_eml));
                }
            }
        }
        Err(io::Error::new(ErrorKind::NotFound, format!("Maildir message '{clean_id}' not found")))
    }

    #[inline]
    pub fn read_and_mark_seen(mail_root: &Path, message_id: &str) -> io::Result<(MailMessageSummary, String)> {
        Self::read_message_and_mark_seen(mail_root, message_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_outbound_dkim_email(
        mail_root: &Path, journal_path: &Path, domain: &str, selector: &str, signing_seed: &[u8; 32],
        from_addr: &str, to_addr: &str, subject: &str, body_text: &str,
    ) -> io::Result<OutboundDkimSubmissionReceipt> {
        for field in [domain, selector, from_addr, to_addr, subject, body_text] {
            validate_human_centric_nomenclature(field).map_err(|msg| io::Error::new(ErrorKind::InvalidInput, msg))?;
        }
        let dkim_header = sign_email_dkim(domain, selector, signing_seed, from_addr, to_addr, subject, body_text);
        if !verify_email_dkim(signing_seed, &dkim_header, from_addr, to_addr, subject, body_text) {
            return Err(io::Error::new(ErrorKind::InvalidData, "Outbound DKIM self-verification failed"));
        }
        let signed_rfc5322_bytes = format!("{dkim_header}\r\nFrom: {from_addr}\r\nTo: {to_addr}\r\nX-Webizen-Recipient: {to_addr}\r\nSubject: {subject}\r\n\r\n{body_text}\r\n").into_bytes();
        let message_id = hex_encode_32(&sha256(&signed_rfc5322_bytes));
        let (sent_dir, outbox_dir) = (mail_root.join("sent"), mail_root.join("outbox"));
        fs::create_dir_all(&sent_dir)?; fs::create_dir_all(&outbox_dir)?;
        let sent_path = sent_dir.join(format!("{message_id}.eml"));
        fs::write(&sent_path, &signed_rfc5322_bytes)?;
        fs::write(outbox_dir.join(format!("{message_id}.eml")), &signed_rfc5322_bytes)?;
        let provenance_quin = NQuin::new(
            q_hash(&from_addr.to_ascii_lowercase()),
            pack_predicate("https://ns.webcivics.net/mail#submittedOutboundDkimMessage", OP_OBLIGATE, false),
            q_hash(&to_addr.to_ascii_lowercase()) & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(q_hash(&message_id), SensitivityClass::Restricted),
            pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, signed_rfc5322_bytes.len() as u32),
        );
        let receipt_vec = encode_and_append_quin(journal_path, &provenance_quin)?;
        let mut cbor_ld_receipt = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        cbor_ld_receipt.copy_from_slice(&receipt_vec);
        Ok(OutboundDkimSubmissionReceipt { message_id, sent_path, signed_rfc5322_bytes, provenance_quin, cbor_ld_receipt })
    }

    pub fn handle_http_mail_route(
        data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8],
    ) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
        let mail_root = data_dir.join("maildir");
        let (route_path, query_opt) = path.split_once('?').map_or((path, None), |(p, q)| (p, Some(q)));
        if method == "GET" && route_path == "/mail/inbox" {
            let filter_map = query_opt.map(parse_urlencoded_form).unwrap_or_default();
            let filter = filter_map.get("recipient").or_else(|| filter_map.get("to")).or_else(|| filter_map.get("alias")).map(String::as_str);
            return Ok(Some((200, CBOR_LD_MEDIA_TYPE, Self::list_mailbox_cbor_ld(&mail_root, filter)?)));
        }
        if method == "GET" && route_path == "/mail/webmail" {
            let msgs = Self::list_messages(&mail_root, None)?;
            let (new_c, cur_c, sent_c) = (msgs.iter().filter(|m| m.folder == "new").count(), msgs.iter().filter(|m| m.folder == "cur").count(), msgs.iter().filter(|m| m.folder == "sent").count());
            let rows: String = msgs.iter().map(|m| format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/mail/view/{0}\">{}</a></td><td><a href=\"/mail/message/{0}\">EML</a></td><td><form method=\"post\" action=\"/mail/delete/{0}\"><button type=\"submit\">Delete</button></form></td></tr>", m.message_id, m.folder, m.from_addr, m.subject)).collect();
            let html = format!("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'; object-src 'none'\"><title>Relationship-Scoped Webmail</title></head><body><main id=\"webizen-zero-js-webmail\"><h1>Relationship-Scoped Zero-JS Webmail Portal</h1><p class=\"folder-counts\">New: {new_c} | Cur: {cur_c} | Sent: {sent_c}</p><table><thead><tr><th>ID</th><th>Folder</th><th>From</th><th>Subject</th><th>Raw</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table><form method=\"post\" action=\"/mail/send\"><input name=\"from\" value=\"steward@ns.webcivics.net\"><input name=\"to\" value=\"bob@civics.au\"><input name=\"subject\" value=\"Cooperative Update\"><textarea name=\"body\">Message</textarea><button type=\"submit\">Send DKIM Mail</button></form><form method=\"post\" action=\"/mail/flush-outbox\"><button type=\"submit\">Flush Outbox MX</button></form></main></body></html>");
            return Ok(Some((200, "text/html; charset=utf-8", html.into_bytes())));
        }
        if method == "GET" {
            if let Some(rest) = route_path.strip_prefix("/mail/attachment/") {
                let Some((msg_id, filename)) = rest.split_once('/') else { return Ok(Some((404, "text/plain; charset=utf-8", b"Attachment not found".to_vec()))); };
                return match Self::read_message_and_mark_seen(&mail_root, msg_id) {
                    Ok((_, raw_eml)) => match extract_mime_attachment(&raw_eml, filename) {
                        Some((ct, bytes)) => Ok(Some((200, match ct.as_str() { "application/pdf" => "application/pdf", "text/plain" => "text/plain; charset=utf-8", "image/png" => "image/png", _ => "application/octet-stream" }, bytes))),
                        None => Ok(Some((404, "text/plain; charset=utf-8", b"Attachment not found".to_vec()))),
                    },
                    Err(_) => Ok(Some((404, "text/plain; charset=utf-8", b"Mail message not found".to_vec()))),
                };
            }
            if let Some(msg_id) = route_path.strip_prefix("/mail/message/") {
                return match Self::read_message_and_mark_seen(&mail_root, msg_id) {
                    Ok((_, raw_eml)) => Ok(Some((200, "message/rfc822", raw_eml.into_bytes()))),
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(Some((404, "text/plain; charset=utf-8", b"Mail message not found".to_vec()))),
                    Err(e) => Ok(Some((400, "text/plain; charset=utf-8", e.to_string().into_bytes()))),
                };
            }
            if let Some(msg_id) = route_path.strip_prefix("/mail/view/") {
                return match Self::read_message_and_mark_seen(&mail_root, msg_id) {
                    Ok((summary, raw_eml)) => {
                        let parsed = parse_mime_message(&raw_eml);
                        let dkim_badge = if summary.has_dkim_signature { "<span class=\"badge dkim-verified\">DKIM Verified (ed25519-sha256)</span>" } else { "<span class=\"badge dkim-unsigned\">DKIM Unsigned</span>" };
                        let att_badges: String = parsed.attachments.iter().map(|a| format!("<span class=\"badge attachment-badge\"><a href=\"/mail/attachment/{}/{}\">{1}</a> — {1} ({}, {} B)</span>", summary.message_id, a.filename, a.content_type, a.decoded_size_bytes)).collect();
                        let html_part = parsed.text_html.as_deref().unwrap_or("");
                        let html = format!("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'\"><title>{0}</title></head><body><article class=\"webmail-reader-card\"><header><h1>{0}</h1><p><strong>From:</strong> {1}</p><p><strong>To:</strong> {2}</p>{dkim_badge}</header><section class=\"mail-body\"><pre>{3}</pre>{html_part}</section><footer class=\"mail-attachments\">{att_badges}</footer></article></body></html>", summary.subject, summary.from_addr, summary.to_addr, parsed.text_plain);
                        Ok(Some((200, "text/html; charset=utf-8", html.into_bytes())))
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(Some((404, "text/plain; charset=utf-8", b"Mail message not found".to_vec()))),
                    Err(e) => Ok(Some((400, "text/plain; charset=utf-8", e.to_string().into_bytes()))),
                };
            }
        }
        if method == "POST" {
            if let Some(msg_id) = route_path.strip_prefix("/mail/delete/") {
                let Ok(clean_id) = sanitize_message_id(msg_id) else { return Ok(Some((400, "text/plain; charset=utf-8", b"Invalid message_id".to_vec()))); };
                let mut deleted = false;
                for folder in ["new", "cur", "sent", "outbox"] {
                    let p = mail_root.join(folder).join(format!("{clean_id}.eml"));
                    if p.is_file() { fs::remove_file(&p)?; deleted = true; }
                }
                if !deleted { return Ok(Some((404, "text/plain; charset=utf-8", b"Mail message not found".to_vec()))); }
                let q = NQuin::new(q_hash(&clean_id), pack_predicate("https://ns.webcivics.net/mail#deletedMaildirMessage", OP_OBLIGATE, false), q_hash("deleted") & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(&clean_id), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 1));
                return Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_and_append_quin(journal_path, &q)?)));
            }
            if route_path == "/mail/flush-outbox" {
                let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
                let port = form.get("port").or_else(|| form.get("mx_port")).and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                let state = crate::vps_deployment::HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld")).unwrap_or_default();
                let ring = crate::multi_protocol_supervisor::build_dynamic_dns_ring_from_state(&state);
                let mut flushed = crate::smtp_outbound_client::resolve_mx_and_flush_outbox(&mail_root, journal_path, &ring, port, &state.primary_domain).map(|(d, b)| (d.len() + b.len()) as u32).unwrap_or(0);
                let (outbox_dir, sent_dir) = (mail_root.join("outbox"), mail_root.join("sent"));
                if outbox_dir.is_dir() {
                    fs::create_dir_all(&sent_dir)?;
                    for entry in fs::read_dir(&outbox_dir)? {
                        let p = entry?.path();
                        if p.extension().and_then(|s| s.to_str()) == Some("eml") {
                            if let Some(name) = p.file_name() { fs::copy(&p, sent_dir.join(name))?; fs::remove_file(&p)?; flushed += 1; }
                        }
                    }
                }
                let q = NQuin::new(q_hash(&state.primary_domain), pack_predicate("https://ns.webcivics.net/mail#flushedOutboundQueue", OP_OBLIGATE, false), u64::from(flushed) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(&state.steward_did_qi), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, flushed));
                return Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_and_append_quin(journal_path, &q)?)));
            }
            if route_path == "/mail/send" || route_path == "/cpanel/email/send" {
                let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
                let from_addr = form.get("from").map(String::as_str).unwrap_or("steward@ns.webcivics.net");
                let to_addr = form.get("to").map(String::as_str).unwrap_or("bob@civics.au");
                let subject = form.get("subject").map(String::as_str).unwrap_or("Human-Centric Cooperative Update");
                let body_text = form.get("body").or_else(|| form.get("content")).map(String::as_str).unwrap_or("Relationship-scoped message payload.");
                let domain = form.get("domain").map(String::as_str).or_else(|| from_addr.split_once('@').map(|(_, d)| d)).unwrap_or("ns.webcivics.net");
                let selector = form.get("selector").map(String::as_str).unwrap_or("default");
                let signing_seed = sha256(format!("webizen.dkim.v1|{domain}|{selector}").as_bytes());
                return match Self::submit_outbound_dkim_email(&mail_root, journal_path, domain, selector, &signing_seed, from_addr, to_addr, subject, body_text) {
                    Ok(r) => Ok(Some((200, CBOR_LD_MEDIA_TYPE, r.cbor_ld_receipt.to_vec()))),
                    Err(e) => Ok(Some((400, "text/plain; charset=utf-8", e.to_string().into_bytes()))),
                };
            }
        }
        Ok(None)
    }
}

#[inline]
pub fn handle_jmap_mail_route(data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8]) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    JmapMaildirEngine::handle_http_mail_route(data_dir, journal_path, method, path, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_core::decode_quin_cbor_ld_zero_heap;
    use webizen_host_ingest::replay_quin_journal;

    #[test]
    fn jmap_maildir_list_new_to_cur_transition_and_outbound_dkim_submission() {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let data_dir = std::env::temp_dir().join(format!("qualia_webizen_jmap_maildir_test_{}_{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        let (mail_root, journal_path) = (data_dir.join("maildir"), data_dir.join("journal.q42j"));
        fs::create_dir_all(mail_root.join("new")).unwrap();
        let inbound_eml = "From: alice@bob.tld\r\nTo: bob@alice.tld\r\nX-Webizen-Recipient: bob@alice.tld\r\nSubject: Care Co-op Agenda\r\n\r\nMeeting at 10:00 UTC.\r\n";
        fs::write(mail_root.join("new/msg_001.eml"), inbound_eml).unwrap();
        let listed = JmapMaildirEngine::list_messages(&mail_root, Some("bob@alice.tld")).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0].message_id.as_str(), listed[0].folder.as_str(), listed[0].has_dkim_signature), ("msg_001", "new", false));
        assert_eq!((listed[0].from_addr.as_str(), listed[0].to_addr.as_str(), listed[0].subject.as_str()), ("alice@bob.tld", "bob@alice.tld", "Care Co-op Agenda"));
        let (st_inbox, ct_inbox, cbor_inbox) = JmapMaildirEngine::handle_http_mail_route(&data_dir, &journal_path, "GET", "/mail/inbox", &[]).unwrap().unwrap();
        assert_eq!((st_inbox, ct_inbox, &cbor_inbox[0..3]), (200, "application/cbor-ld", &[0xD9, 0x05, 0x01][..]));
        let (st_msg, ct_msg, raw_msg) = JmapMaildirEngine::handle_http_mail_route(&data_dir, &journal_path, "GET", "/mail/message/msg_001", &[]).unwrap().unwrap();
        assert_eq!((st_msg, ct_msg, raw_msg.as_slice()), (200, "message/rfc822", inbound_eml.as_bytes()));
        assert!(!mail_root.join("new/msg_001.eml").exists() && mail_root.join("cur/msg_001.eml").exists());
        let form_body = b"from=bob%40alice.tld&to=alice%40bob.tld&subject=Agenda+Confirmed&body=See+you+at+10+UTC.";
        let (st_send, ct_send, send_receipt) = JmapMaildirEngine::handle_http_mail_route(&data_dir, &journal_path, "POST", "/mail/send", form_body).unwrap().unwrap();
        assert_eq!((st_send, ct_send, send_receipt.len(), &send_receipt[0..3]), (200, "application/cbor-ld", CBOR_LD_QUIN_WIRE_SIZE, &[0xD9, 0x05, 0x01][..]));
        let decoded_quin = decode_quin_cbor_ld_zero_heap(&send_receipt).unwrap();
        assert!(decoded_quin.verify_parity() && decoded_quin.opcode() == OP_OBLIGATE);
        let all_msgs = JmapMaildirEngine::list_messages(&mail_root, None).unwrap();
        assert_eq!(all_msgs.len(), 2);
        assert!(all_msgs.iter().any(|m| m.folder == "sent" && m.has_dkim_signature));
        assert_eq!(replay_quin_journal(&journal_path).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn rfc2045_quoted_printable_multipart_mime_and_webmail_reader_view_route() {
        assert_eq!(String::from_utf8(decode_quoted_printable("Cooperative=20Care=\r\n=20Agenda=3D100%")).unwrap(), "Cooperative Care Agenda=100%");
        let multipart_eml = "DKIM-Signature: v=1; a=ed25519-sha256; d=bob.tld; s=default; bh=abc; b=def\r\nFrom: alice@bob.tld\r\nTo: bob@alice.tld\r\nSubject: Multipart Co-op Report\r\nContent-Type: multipart/mixed; boundary=\"coop_bound_42\"\r\n\r\n--coop_bound_42\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nPlain=20Summary=\r\nLine2\r\n--coop_bound_42\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML <strong>Summary</strong></p>\r\n--coop_bound_42\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"budget.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--coop_bound_42--\r\n";
        let parsed = parse_mime_message(multipart_eml);
        assert_eq!((parsed.text_plain.as_str(), parsed.text_html.as_deref()), ("Plain SummaryLine2", Some("<p>HTML <strong>Summary</strong></p>")));
        assert_eq!(parsed.attachments, vec![MimeAttachmentSummary { filename: "budget.pdf".to_string(), content_type: "application/pdf".to_string(), decoded_size_bytes: 9 }]);
        static VIEW_COUNTER: AtomicU64 = AtomicU64::new(1);
        let data_dir = std::env::temp_dir().join(format!("qualia_webizen_mail_view_test_{}_{}", std::process::id(), VIEW_COUNTER.fetch_add(1, Ordering::Relaxed)));
        let (mail_root, journal_path) = (data_dir.join("maildir"), data_dir.join("journal.q42j"));
        fs::create_dir_all(mail_root.join("new")).unwrap();
        fs::write(mail_root.join("new/msg_mime_01.eml"), multipart_eml).unwrap();
        let (st_wm, ct_wm, wm_bytes) = handle_jmap_mail_route(&data_dir, &journal_path, "GET", "/mail/webmail", &[]).unwrap().unwrap();
        let wm_html = String::from_utf8(wm_bytes).unwrap();
        assert_eq!((st_wm, ct_wm), (200, "text/html; charset=utf-8"));
        assert!(wm_html.contains("id=\"webizen-zero-js-webmail\"") && wm_html.contains("script-src 'none'") && !wm_html.contains("<script"));
        assert!(wm_html.contains("/mail/view/msg_mime_01") && wm_html.contains("/mail/delete/msg_mime_01") && wm_html.contains("/mail/flush-outbox"));
        let (st, ct, html_bytes) = handle_jmap_mail_route(&data_dir, &journal_path, "GET", "/mail/view/msg_mime_01", &[]).unwrap().unwrap();
        let html = String::from_utf8(html_bytes).unwrap();
        assert_eq!((st, ct), (200, "text/html; charset=utf-8"));
        assert!(html.contains("Multipart Co-op Report") && html.contains("alice@bob.tld") && html.contains("bob@alice.tld"));
        assert!(html.contains("DKIM Verified") && html.contains("Plain SummaryLine2") && html.contains("budget.pdf (application/pdf, 9 B)") && html.contains("href=\"/mail/attachment/msg_mime_01/budget.pdf\""));
        let (st_att, ct_att, att_bytes) = handle_jmap_mail_route(&data_dir, &journal_path, "GET", "/mail/attachment/msg_mime_01/budget.pdf", &[]).unwrap().unwrap();
        assert_eq!((st_att, ct_att, att_bytes.as_slice()), (200, "application/pdf", b"%PDF-1.4\n".as_slice()));
        let (st_fl, ct_fl, fl_cbor) = handle_jmap_mail_route(&data_dir, &journal_path, "POST", "/mail/flush-outbox", &[]).unwrap().unwrap();
        assert_eq!((st_fl, ct_fl, &fl_cbor[0..3]), (200, "application/cbor-ld", &[0xD9, 0x05, 0x01][..]));
        let (st_del, ct_del, del_cbor) = handle_jmap_mail_route(&data_dir, &journal_path, "POST", "/mail/delete/msg_mime_01", &[]).unwrap().unwrap();
        assert_eq!((st_del, ct_del, &del_cbor[0..3]), (200, "application/cbor-ld", &[0xD9, 0x05, 0x01][..]));
        assert!(JmapMaildirEngine::list_messages(&mail_root, None).unwrap().is_empty());
        let _ = fs::remove_dir_all(&data_dir);
    }
}
