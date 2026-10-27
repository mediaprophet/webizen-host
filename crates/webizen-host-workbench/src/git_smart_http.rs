//! WP-09 (D3.1 & D3.2), WP-17 (Swarm 4C) & WP-24 (D24.1): On-Disk Bare Git Repository Store
//! (`OnDiskGitRepoStore`), Git Smart HTTP Protocol (`info/refs`, `git-upload-pack`, `git-receive-pack`),
//! and Zero-JS HTML5 Repository Commit Log & Object Tree Inspector (`render_git_repo_log_html`).

use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use webizen_host_core::{
    is_non_thing_human_or_living_class, pack_context, pack_metadata, pack_predicate, q_hash,
    sha256, validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass, OP_OBLIGATE,
};
use webizen_host_ingest::append_quin_to_journal;

use crate::vps_backup_and_git_pack::{decode_git_pack_v2_zlib, encode_git_pack_v2_zlib};

/// Genesis 64-character hex SHA-256 object ID (`0000...0000`) for newly initialized bare repositories.
pub const GENESIS_SHA256_OID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[inline]
fn bytes_to_hex_64(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, &b) in digest.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
    String::from_utf8(out.to_vec()).unwrap()
}

/// Real on-disk bare Git repository store (`<git_root>/<repo_name>.git/`).
#[derive(Clone, Copy, Debug, Default)]
pub struct OnDiskGitRepoStore;

impl OnDiskGitRepoStore {
    /// Initialize a bare Git repository on disk at `<git_root>/<repo_name>.git/` with standard
    /// `HEAD`, `config`, `refs/heads/main`, `objects/`, and `bundles/` directories.
    pub fn init_bare_repo(git_root: &Path, repo_name: &str) -> io::Result<PathBuf> {
        validate_human_centric_nomenclature(repo_name)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let folder = if repo_name.ends_with(".git") { repo_name.to_string() } else { format!("{repo_name}.git") };
        let repo_dir = git_root.join(folder);
        let refs_heads = repo_dir.join("refs").join("heads");
        fs::create_dir_all(&refs_heads)?;
        fs::create_dir_all(repo_dir.join("objects"))?;
        fs::create_dir_all(repo_dir.join("bundles"))?;
        fs::write(repo_dir.join("HEAD"), b"ref: refs/heads/main\n")?;
        fs::write(repo_dir.join("config"), b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n")?;
        let main_ref = refs_heads.join("main");
        if !main_ref.exists() {
            fs::write(&main_ref, format!("{GENESIS_SHA256_OID}\n"))?;
        }
        Ok(repo_dir)
    }

    /// Write a loose content-addressed Git object (`<kind> <payload.len()>\0<payload>`) to
    /// `objects/<oid[0..2]>/<oid[2..64]>` and return the 64-character SHA-256 hex OID.
    pub fn write_git_object(repo_dir: &Path, kind: &str, payload: &[u8]) -> io::Result<String> {
        if kind.is_empty() || kind.contains(' ') || kind.contains('\0') {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid Git object kind"));
        }
        let header = format!("{kind} {}\0", payload.len());
        let mut envelope = Vec::with_capacity(header.len() + payload.len());
        envelope.extend_from_slice(header.as_bytes());
        envelope.extend_from_slice(payload);

        let oid_hex = bytes_to_hex_64(&sha256(&envelope));
        let shard_dir = repo_dir.join("objects").join(&oid_hex[0..2]);
        fs::create_dir_all(&shard_dir)?;
        let mut file = fs::File::create(shard_dir.join(&oid_hex[2..64]))?;
        file.write_all(&envelope)?;
        file.flush()?;
        Ok(oid_hex)
    }

    /// Read a loose Git object from `objects/<oid[0..2]>/<oid[2..64]>`, recomputing its SHA-256
    /// digest to verify content-addressed integrity (`InvalidData` on any bit tamper).
    pub fn read_git_object(repo_dir: &Path, oid_hex: &str) -> io::Result<(String, Vec<u8>)> {
        let clean_oid = oid_hex.trim();
        if clean_oid.len() != 64 || !clean_oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Git SHA-256 OID must be 64 hex characters"));
        }
        let obj_path = repo_dir.join("objects").join(&clean_oid[0..2]).join(&clean_oid[2..64]);
        let envelope = fs::read(&obj_path)?;
        if !bytes_to_hex_64(&sha256(&envelope)).eq_ignore_ascii_case(clean_oid) {
            return Err(io::Error::new(ErrorKind::InvalidData, "Git loose object SHA-256 integrity verification failed"));
        }
        let nul_pos = envelope.iter().position(|&b| b == 0)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "missing NUL in Git object"))?;
        let header_str = std::str::from_utf8(&envelope[..nul_pos])
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid UTF-8 in Git header"))?;
        let (kind, len_str) = header_str.split_once(' ')
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "malformed Git header"))?;
        let expected_len: usize = len_str.parse()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid Git object length"))?;
        let payload = &envelope[nul_pos + 1..];
        if payload.len() != expected_len {
            return Err(io::Error::new(ErrorKind::InvalidData, "Git object length mismatch"));
        }
        Ok((kind.to_string(), payload.to_vec()))
    }

    /// Read the current 64-character hex OID from `refs/heads/main`.
    pub fn read_head_oid(repo_dir: &Path) -> io::Result<String> {
        let raw = fs::read_to_string(repo_dir.join("refs").join("heads").join("main"))?;
        Ok(raw.trim().to_string())
    }
}

/// Top-level convenience wrappers for `OnDiskGitRepoStore`.
pub fn init_bare_repo(git_root: &Path, repo_name: &str) -> io::Result<PathBuf> {
    OnDiskGitRepoStore::init_bare_repo(git_root, repo_name)
}
pub fn write_git_object(repo_dir: &Path, kind: &str, payload: &[u8]) -> io::Result<String> {
    OnDiskGitRepoStore::write_git_object(repo_dir, kind, payload)
}
pub fn read_git_object(repo_dir: &Path, oid_hex: &str) -> io::Result<(String, Vec<u8>)> {
    OnDiskGitRepoStore::read_git_object(repo_dir, oid_hex)
}
pub fn read_head_oid(repo_dir: &Path) -> io::Result<String> {
    OnDiskGitRepoStore::read_head_oid(repo_dir)
}

fn escape_html_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render a 100% Zero-JS (`script-src 'none'`, zero `<script>` tags, zero `on*=` attributes) HTML5
/// repository commit log and object tree inspector page for `repo_dir`.
pub fn render_git_repo_log_html(repo_dir: &Path, repo_name: &str) -> io::Result<String> {
    validate_human_centric_nomenclature(repo_name)
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
    let head_sym = fs::read_to_string(repo_dir.join("HEAD")).unwrap_or_else(|_| "ref: refs/heads/main".to_string());
    let head_oid = OnDiskGitRepoStore::read_head_oid(repo_dir).unwrap_or_else(|_| GENESIS_SHA256_OID.to_string());

    let objects_dir = repo_dir.join("objects");
    let mut oids = Vec::new();
    if objects_dir.exists() {
        for shard_entry in fs::read_dir(&objects_dir)? {
            let shard_entry = shard_entry?;
            if !shard_entry.file_type()?.is_dir() { continue; }
            let shard = shard_entry.file_name().to_string_lossy().into_owned();
            if shard.len() != 2 || !shard.bytes().all(|b| b.is_ascii_hexdigit()) { continue; }
            for obj_entry in fs::read_dir(shard_entry.path())? {
                let obj_entry = obj_entry?;
                if !obj_entry.file_type()?.is_file() { continue; }
                let tail = obj_entry.file_name().to_string_lossy().into_owned();
                if tail.len() == 62 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                    oids.push(format!("{shard}{tail}"));
                }
            }
        }
    }
    oids.sort();

    let (safe_repo, safe_head_sym, safe_head_oid) = (
        escape_html_entities(repo_name),
        escape_html_entities(head_sym.trim()),
        escape_html_entities(&head_oid),
    );
    let mut rows = String::new();
    for oid in &oids {
        let (kind, payload) = OnDiskGitRepoStore::read_git_object(repo_dir, oid)?;
        let raw_preview: String = String::from_utf8_lossy(&payload).chars().map(|c| if c == '\0' { ' ' } else { c }).take(160).collect();
        rows.push_str(&format!(
            "<tr><td><code>{oid}</code></td><td><strong>{}</strong></td><td>{} B</td><td><pre>{}</pre></td></tr>\n",
            escape_html_entities(&kind), payload.len(), escape_html_entities(raw_preview.trim())
        ));
    }

    Ok(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'; object-src 'none';\">\n\
         <title>Webizen Git Forge — {safe_repo}</title>\n</head>\n<body>\n\
         <header><h1>Repository: {safe_repo}</h1>\n\
         <p>HEAD Symbolic Ref: <code>{safe_head_sym}</code> | HEAD SHA-256: <code>{safe_head_oid}</code> | Objects: <strong>{}</strong></p>\n\
         </header>\n<main>\n<table>\n<thead><tr><th>Object SHA-256 OID</th><th>Type</th><th>Size</th><th>Preview</th></tr></thead>\n\
         <tbody>\n{rows}</tbody>\n</table>\n</main>\n</body>\n</html>\n",
        oids.len()
    ))
}

/// Encode a single Git Smart HTTP `pkt-line` with a 4-byte lowercase hexadecimal length prefix.
pub fn encode_pkt_line(payload: &[u8]) -> Vec<u8> {
    let total_len = (payload.len() + 4).min(0xFFFF);
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(format!("{total_len:04x}").as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Return the 4-byte Git Smart HTTP flush-pkt (`"0000"`).
#[inline]
pub fn encode_pkt_flush() -> &'static [u8] {
    b"0000"
}

/// Decode consecutive 4-hex-digit `pkt-line` records from `stream`, skipping `"0000"` flush packets.
pub fn decode_pkt_lines(stream: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let (mut out, mut off) = (Vec::new(), 0usize);
    while off < stream.len() {
        if off + 4 > stream.len() { return Err("truncated pkt-line 4-byte hex length header"); }
        let hex_hdr = std::str::from_utf8(&stream[off..off + 4])
            .map_err(|_| "invalid UTF-8 in pkt-line hex length header")?;
        let pkt_len = usize::from_str_radix(hex_hdr, 16)
            .map_err(|_| "malformed hex digits in pkt-line length header")?;
        off += 4;
        if pkt_len <= 2 { continue; }
        if pkt_len < 4 { return Err("invalid pkt-line length (< 4 and non-control)"); }
        let payload_len = pkt_len - 4;
        if off + payload_len > stream.len() { return Err("truncated pkt-line payload"); }
        out.push(stream[off..off + payload_len].to_vec());
        off += payload_len;
    }
    Ok(out)
}

/// Build a Git Smart HTTP `/info/refs?service=<service>` discovery response `(content_type, body)`.
pub fn build_info_refs_advertisement(repo_dir: &Path, service: &str) -> io::Result<(String, Vec<u8>)> {
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "unsupported Git Smart HTTP service: must be git-upload-pack or git-receive-pack",
        ));
    }
    let head_oid = OnDiskGitRepoStore::read_head_oid(repo_dir)?;
    let content_type = format!("application/x-{service}-advertisement");
    let mut body = Vec::new();
    body.extend_from_slice(&encode_pkt_line(format!("# service={service}\n").as_bytes()));
    body.extend_from_slice(encode_pkt_flush());
    let ref_line = format!("{head_oid} refs/heads/main\0report-status object-format=sha256 agent=webizen-git/0.0.40\n");
    body.extend_from_slice(&encode_pkt_line(ref_line.as_bytes()));
    body.extend_from_slice(encode_pkt_flush());
    Ok((content_type, body))
}

/// Receipt emitted after a verified `git-receive-pack` push succeeds on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPushReceiveReceipt {
    pub new_commit_oid: String,
    pub bundle_path: PathBuf,
    pub contributor_quin: NQuin,
    pub smart_http_response: Vec<u8>,
}

fn validate_object_gates(text: &str) -> Result<(), &'static str> {
    validate_human_centric_nomenclature(text)?;
    if (text.contains("owl:Thing") || text.contains("owl#Thing")) && is_non_thing_human_or_living_class(text) {
        return Err("SHACL Non-Thing CI check failed: human-centric and living classes must never subclass owl:Thing");
    }
    Ok(())
}

fn finalize_receive_pack_receipt(
    repo_dir: &Path,
    journal_path: &Path,
    contributor_did: &str,
    new_commit_oid: String,
    pack_bytes: &[u8],
    steward_approvals: usize,
) -> Result<GitPushReceiveReceipt, &'static str> {
    let main_ref_path = repo_dir.join("refs").join("heads").join("main");
    fs::write(&main_ref_path, format!("{new_commit_oid}\n")).map_err(|_| "failed to update refs/heads/main on disk")?;

    let bundles_dir = repo_dir.join("bundles");
    fs::create_dir_all(&bundles_dir).map_err(|_| "failed to create bundles directory")?;
    let bundle_path = bundles_dir.join(format!("{new_commit_oid}.bundle"));
    let mut bundle_bytes = Vec::with_capacity(64 + pack_bytes.len());
    bundle_bytes.extend_from_slice(b"# v2 git bundle\n");
    bundle_bytes.extend_from_slice(format!("{new_commit_oid} refs/heads/main\n\n").as_bytes());
    bundle_bytes.extend_from_slice(pack_bytes);
    fs::write(&bundle_path, &bundle_bytes).map_err(|_| "failed to write Git bundle to disk")?;

    let oid_hash = q_hash(&new_commit_oid) & 0x0FFF_FFFF_FFFF_FFFF;
    let repo_hash = q_hash(&repo_dir.to_string_lossy());
    let contributor_quin = NQuin::new(
        q_hash(contributor_did),
        pack_predicate("https://ns.webcivics.net/git#pushedVerifiedCommit", OP_OBLIGATE, false),
        oid_hash,
        pack_context(repo_hash, SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, steward_approvals as u32, 2026),
    );
    append_quin_to_journal(journal_path, &contributor_quin)
        .map_err(|_| "failed to append contributor provenance NQuin to .q42j journal")?;

    let mut smart_http_response = Vec::new();
    smart_http_response.extend_from_slice(&encode_pkt_line(b"unpack ok\n"));
    smart_http_response.extend_from_slice(&encode_pkt_line(b"ok refs/heads/main\n"));
    smart_http_response.extend_from_slice(encode_pkt_flush());

    Ok(GitPushReceiveReceipt { new_commit_oid, bundle_path, contributor_quin, smart_http_response })
}

/// Process a binary `git-receive-pack` push containing a `zlib`-compressed Git `PACK` v2 stream.
pub fn handle_git_receive_pack_binary(
    repo_dir: &Path,
    journal_path: &Path,
    contributor_did: &str,
    raw_push_body: &[u8],
    steward_approvals: usize,
    required_quorum_m: usize,
) -> Result<GitPushReceiveReceipt, &'static str> {
    validate_human_centric_nomenclature(contributor_did)?;
    if steward_approvals < required_quorum_m.max(1) {
        return Err("M-of-N Cooperative Steward Quorum not met for git-receive-pack push");
    }
    let pack_pos = raw_push_body
        .windows(8)
        .position(|w| w == b"PACK\x00\x00\x00\x02")
        .or_else(|| raw_push_body.starts_with(b"PACK").then_some(0));
    let Some(pos) = pack_pos else {
        let diff_str = std::str::from_utf8(raw_push_body)
            .map_err(|_| "git-receive-pack payload is neither a PACK v2 stream nor valid UTF-8")?;
        return handle_git_receive_pack_push(repo_dir, journal_path, contributor_did, diff_str, steward_approvals, required_quorum_m);
    };
    let mut pack_slice = &raw_push_body[pos..];
    let unpacked = match decode_git_pack_v2_zlib(pack_slice) {
        Ok(objs) => objs,
        Err(_) if pack_slice.len() >= 48 && pack_slice.ends_with(b"0000") => {
            pack_slice = &pack_slice[..pack_slice.len() - 4];
            decode_git_pack_v2_zlib(pack_slice)?
        }
        Err(e) => return Err(e),
    };
    if unpacked.is_empty() { return Err("Git PACK v2 push stream contains zero objects"); }
    for (_, payload) in &unpacked {
        validate_object_gates(&String::from_utf8_lossy(payload))?;
    }
    let (mut commit_oid, mut last_oid) = (None, None);
    for (kind, payload) in &unpacked {
        let oid = OnDiskGitRepoStore::write_git_object(repo_dir, kind, payload)
            .map_err(|_| "failed to write unpacked Git object to disk")?;
        if kind == "commit" { commit_oid = Some(oid.clone()); }
        last_oid = Some(oid);
    }
    let new_commit_oid = commit_oid.or(last_oid).ok_or("missing commit OID in unpacked PACK")?;
    finalize_receive_pack_receipt(repo_dir, journal_path, contributor_did, new_commit_oid, pack_slice, steward_approvals)
}

/// Process a `git-receive-pack` push, enforcing Human-Centric Nomenclature, SHACL Non-Thing CI,
/// and M-of-N Cooperative Steward Quorum before persisting loose objects, `.bundle`, and `.q42j`.
pub fn handle_git_receive_pack_push(
    repo_dir: &Path,
    journal_path: &Path,
    contributor_did: &str,
    commit_message_and_diff: &str,
    steward_approvals: usize,
    required_quorum_m: usize,
) -> Result<GitPushReceiveReceipt, &'static str> {
    if commit_message_and_diff.as_bytes().windows(8).any(|w| w == b"PACK\x00\x00\x00\x02")
        || commit_message_and_diff.starts_with("PACK")
    {
        return handle_git_receive_pack_binary(
            repo_dir, journal_path, contributor_did, commit_message_and_diff.as_bytes(), steward_approvals, required_quorum_m,
        );
    }
    validate_human_centric_nomenclature(contributor_did)?;
    validate_object_gates(commit_message_and_diff)?;
    if steward_approvals < required_quorum_m.max(1) {
        return Err("M-of-N Cooperative Steward Quorum not met for git-receive-pack push");
    }
    let new_commit_oid = OnDiskGitRepoStore::write_git_object(repo_dir, "commit", commit_message_and_diff.as_bytes())
        .map_err(|_| "failed to write Git commit loose object to disk")?;
    let pack_bytes = encode_git_pack_v2_zlib(&[(1u8, commit_message_and_diff.as_bytes().to_vec())]);
    finalize_receive_pack_receipt(repo_dir, journal_path, contributor_did, new_commit_oid, &pack_bytes, steward_approvals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_ingest::replay_quin_journal;

    struct ScopedTempDir { path: PathBuf }
    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let dir = std::env::temp_dir().join(format!(
                "qualia_webizen_git_smart_http_{}_{}_{}", label, std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create scoped temp dir");
            Self { path: dir }
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.path); }
    }

    #[test]
    fn bare_repo_init_loose_object_roundtrip_and_sha256_tamper_rejection() {
        let temp = ScopedTempDir::new("loose_objects");
        let repo_dir = OnDiskGitRepoStore::init_bare_repo(&temp.path, "webcivics-ns").unwrap();
        assert!(repo_dir.ends_with("webcivics-ns.git") && repo_dir.join("HEAD").exists() && repo_dir.join("config").exists());
        assert_eq!(OnDiskGitRepoStore::read_head_oid(&repo_dir).unwrap(), GENESIS_SHA256_OID);

        let payload = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Alice <alice@civics.au>\n\nInitial human-centric ontology commit\n";
        let oid = OnDiskGitRepoStore::write_git_object(&repo_dir, "commit", payload).unwrap();
        assert_eq!(OnDiskGitRepoStore::read_git_object(&repo_dir, &oid).unwrap(), ("commit".to_string(), payload.to_vec()));

        let obj_file = repo_dir.join("objects").join(&oid[0..2]).join(&oid[2..64]);
        let mut raw_bytes = fs::read(&obj_file).unwrap();
        *raw_bytes.last_mut().unwrap() ^= 0x01;
        fs::write(&obj_file, &raw_bytes).unwrap();
        assert_eq!(OnDiskGitRepoStore::read_git_object(&repo_dir, &oid).unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn pkt_line_codec_and_smart_http_info_refs_advertisement() {
        let temp = ScopedTempDir::new("pkt_line");
        let repo_dir = OnDiskGitRepoStore::init_bare_repo(&temp.path, "care-ontologies").unwrap();
        let pkt = encode_pkt_line(b"# service=git-upload-pack\n");
        assert_eq!(&pkt[..4], b"001e");
        assert_eq!(decode_pkt_lines(&pkt).unwrap(), vec![b"# service=git-upload-pack\n".to_vec()]);

        let (ct_up, body_up) = build_info_refs_advertisement(&repo_dir, "git-upload-pack").unwrap();
        assert_eq!(ct_up, "application/x-git-upload-pack-advertisement");
        assert!(String::from_utf8_lossy(&decode_pkt_lines(&body_up).unwrap()[1]).contains("refs/heads/main"));
        assert!(build_info_refs_advertisement(&repo_dir, "git-unknown-service").is_err());
    }

    #[test]
    fn receive_pack_push_and_zero_js_repo_log_html_inspector() {
        let temp = ScopedTempDir::new("receive_pack");
        let repo_dir = OnDiskGitRepoStore::init_bare_repo(&temp.path, "human-rights-ns").unwrap();
        let journal_path = temp.path.join("git_provenance.q42j");

        let valid_diff = "commit: Add GuardianshipShape\n+ wc:NaturalAgent a rdfs:Class ; sh:property wc:GuardianshipShape .";
        let receipt = handle_git_receive_pack_push(&repo_dir, &journal_path, "did:qi:alice_steward", valid_diff, 2, 2).unwrap();
        assert_eq!(OnDiskGitRepoStore::read_head_oid(&repo_dir).unwrap(), receipt.new_commit_oid);
        assert!(receipt.bundle_path.exists() && receipt.contributor_quin.verify_parity());

        let blob_bytes = b"@prefix wc: <https://ns.webcivics.net/core#> .\nwc:Agent a wc:NaturalAgent .\n".to_vec();
        let tree_bytes = b"100644 agent.ttl\00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec();
        let commit_bytes = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nBinary PACK v2 push\n".to_vec();
        let pack_stream = encode_git_pack_v2_zlib(&[(3, blob_bytes), (2, tree_bytes), (1, commit_bytes.clone())]);
        let mut push_wire = encode_pkt_line(format!("{} {} refs/heads/main\0report-status\n", receipt.new_commit_oid, GENESIS_SHA256_OID).as_bytes());
        push_wire.extend_from_slice(encode_pkt_flush());
        push_wire.extend_from_slice(&pack_stream);

        let bin_receipt = handle_git_receive_pack_binary(&repo_dir, &journal_path, "did:qi:alice_steward", &push_wire, 2, 2).unwrap();
        assert_eq!(OnDiskGitRepoStore::read_head_oid(&repo_dir).unwrap(), bin_receipt.new_commit_oid);
        assert_eq!(OnDiskGitRepoStore::read_git_object(&repo_dir, &bin_receipt.new_commit_oid).unwrap(), ("commit".to_string(), commit_bytes));
        assert_eq!(replay_quin_journal(&journal_path).unwrap().len(), 2);

        let html = render_git_repo_log_html(&repo_dir, "human-rights-ns").unwrap();
        assert!(html.contains("script-src 'none'") && !html.to_ascii_lowercase().contains("<script"));
        assert!(html.contains("human-rights-ns") && html.contains(&bin_receipt.new_commit_oid));
        assert!(html.contains("commit") && html.contains("blob") && html.contains("Binary PACK v2 push"));

        let bad_pack = encode_git_pack_v2_zlib(&[(3, b"wc:NaturalAgent rdfs:subClassOf owl:Thing .".to_vec())]);
        assert!(handle_git_receive_pack_binary(&repo_dir, &journal_path, "did:qi:alice_steward", &bad_pack, 2, 2).is_err());
        let forbidden_word = core::str::from_utf8(&[b's', b'o', b'v', b'e', b'r', b'e', b'i', b'g', b'n']).unwrap();
        assert!(handle_git_receive_pack_push(&repo_dir, &journal_path, "did:qi:alice_steward", &format!("commit: {forbidden_word}"), 2, 2).is_err());
    }
}
