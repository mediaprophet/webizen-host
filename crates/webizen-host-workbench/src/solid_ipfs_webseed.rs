//! WP-10 (D10.3 & D10.4) & WP-17 (Swarm 4D): W3C Solid LDP Pod Disk Gateway (`SolidPodDiskGateway`),
//! `.acl` Web Access Control (WAC), `ETag`, `DELETE`, `ldp:BasicContainer`, Active Q-CDN `HTTP 307`
//! Offload, & IPFS Content-Addressed Block / WebTorrent `HTTP 206` WebSeed Gateway (`P2pWebSeedGateway`).

use std::fs;
use std::path::{Path, PathBuf};
use webizen_host_core::{
    crc32c_bytes, encode_quins_graph_cbor_ld, is_non_thing_human_or_living_class, pack_context,
    pack_metadata, pack_predicate, q_hash, q_hash_bytes, sha256,
    validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass, OP_OBLIGATE,
};
use webizen_host_ingest::{append_quin_to_journal, read_file_byte_range, replay_quin_journal};
use webizen_host_qcdn::{MultiProtocolShareDescriptor, FLAG_PERMISSIVE_COMMONS};
use webizen_host_sandbox::{SandboxError, Tier3SolidAndEbpfSandbox};

/// Receipt returned after storing a W3C Solid LDP resource into a pod on disk and `.q42j` journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolidLdpPutReceipt {
    pub pod_name: String,
    pub resource_path: String,
    pub quins_stored: usize,
    pub cbor_ld_bytes: Vec<u8>,
}

/// Alias preserving compatibility with callers referencing `SolidPutReceipt`.
pub type SolidPutReceipt = SolidLdpPutReceipt;

/// W3C Web Access Control (`http://www.w3.org/ns/auth/acl#`) permission modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WacPermission {
    Read,
    Write,
    Append,
    Control,
}

/// W3C Solid LDP Pod Disk Gateway (`PUT` / `GET` / `DELETE` / `.acl` WAC / `ldp:BasicContainer`).
pub struct SolidPodDiskGateway;

impl SolidPodDiskGateway {
    pub fn handle_solid_ldp_put(data_dir: &Path, journal_path: &Path, sandbox: &mut Tier3SolidAndEbpfSandbox, pod_name: &str, resource_rel_path: &str, turtle_body: &str) -> Result<SolidLdpPutReceipt, &'static str> {
        handle_solid_ldp_put(data_dir, journal_path, sandbox, pod_name, resource_rel_path, turtle_body)
    }
    pub fn handle_solid_ldp_get(data_dir: &Path, pod_name: &str, resource_rel_path: &str, accept_header: &str) -> Result<(&'static str, Vec<u8>), &'static str> {
        handle_solid_ldp_get(data_dir, pod_name, resource_rel_path, accept_header)
    }
    pub fn handle_solid_ldp_delete(data_dir: &Path, journal_path: &Path, pod_name: &str, rel_path: &str, actor_did: &str) -> Result<NQuin, &'static str> {
        handle_solid_ldp_delete(data_dir, journal_path, pod_name, rel_path, actor_did)
    }
    pub fn list_solid_ldp_container_turtle(data_dir: &Path, pod_name: &str) -> Result<String, &'static str> {
        list_solid_ldp_container_turtle(data_dir, pod_name)
    }
}

/// Evaluate W3C Web Access Control (`.acl`) authorization for `<data_dir>/solid/<pod_name>/<rel_path>`.
pub fn evaluate_wac_acl(data_dir: &Path, pod_name: &str, rel_path: &str, agent_did_qi: &str, required: WacPermission) -> bool {
    let Ok(clean_pod) = sanitize_rel_segment(pod_name) else { return false };
    let clean_rel = rel_path.trim().trim_start_matches(['/', '\\']);
    if clean_rel.contains("..") { return false; }
    let pod_dir = data_dir.join("solid").join(clean_pod);
    let acl_text = (!clean_rel.is_empty())
        .then(|| pod_dir.join(format!("{clean_rel}.acl")))
        .and_then(|p| fs::read_to_string(p).ok())
        .or_else(|| fs::read_to_string(pod_dir.join(".acl")).ok());

    let Some(ttl) = acl_text else {
        return match required {
            WacPermission::Read => true,
            WacPermission::Write | WacPermission::Append | WacPermission::Control => {
                let agent = agent_did_qi.trim();
                !agent.is_empty() && (agent == format!("did:qi:{clean_pod}") || agent == clean_pod || agent.ends_with(&format!(":{clean_pod}")))
            }
        };
    };
    parse_and_evaluate_acl_turtle(&ttl, agent_did_qi.trim(), required)
}

/// Compute a strong HTTP `ETag` (`"\"<crc32c_hex>\""`) over resource bytes for `If-Match` concurrency control.
pub fn compute_resource_etag(bytes: &[u8]) -> String {
    format!("\"{:08x}\"", crc32c_bytes(bytes))
}

/// Handle `PUT /solid/<pod_name>/<resource_rel_path>`.
pub fn handle_solid_ldp_put(data_dir: &Path, journal_path: &Path, sandbox: &mut Tier3SolidAndEbpfSandbox, pod_name: &str, resource_rel_path: &str, turtle_body: &str) -> Result<SolidLdpPutReceipt, &'static str> {
    validate_human_centric_nomenclature(pod_name)?;
    validate_human_centric_nomenclature(resource_rel_path)?;
    validate_human_centric_nomenclature(turtle_body)?;
    let (clean_pod, clean_rel) = (sanitize_rel_segment(pod_name)?, sanitize_rel_segment(resource_rel_path)?);
    if let Some(parent) = journal_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "Failed to create Solid journal parent directory")?;
    }

    let mut quins: Vec<NQuin> = Vec::new();
    for raw_line in turtle_body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("@prefix") || line.starts_with("PREFIX ") { continue; }
        let (s_uri, p_uri, o_uri) = parse_turtle_triple_line(line)?;
        if is_owl_thing_reference(o_uri) && is_non_thing_human_or_living_class(s_uri) {
            return Err("SHACL Non-Thing violation: natural persons and living entities must not subclass owl:Thing");
        }
        let quin = sandbox.translate_turtle_triple_to_nquin(s_uri, p_uri, o_uri, raw_line.len() as u64).map_err(|err| match err {
            SandboxError::EbpfBandwidthQuotaExceeded { .. } => "Solid LDP eBPF egress bandwidth quota exceeded",
            _ => "Solid LDP sandbox translation error",
        })?;
        append_quin_to_journal(journal_path, &quin).map_err(|_| "Failed to append Solid LDP NQuin to .q42j journal")?;
        quins.push(quin);
    }

    let _ = q_hash(&format!("https://ns.webcivics.net/solid/{clean_pod}"));
    let cbor_ld_bytes = encode_quins_graph_cbor_ld(&quins, "https://ns.webcivics.net/solid");
    let ttl_path = data_dir.join("solid").join(clean_pod).join(clean_rel);
    if let Some(parent) = ttl_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "Failed to create Solid pod directory on disk")?;
    }
    fs::write(&ttl_path, turtle_body.as_bytes()).map_err(|_| "Failed to write Solid LDP Turtle resource to disk")?;
    fs::write(cbor_ld_companion_path(&ttl_path), &cbor_ld_bytes).map_err(|_| "Failed to write Solid LDP CBOR-LD resource to disk")?;

    Ok(SolidLdpPutReceipt { pod_name: clean_pod.to_string(), resource_path: clean_rel.to_string(), quins_stored: quins.len(), cbor_ld_bytes })
}

/// Handle `GET /solid/<pod_name>/<resource_rel_path>` (returns `ldp:BasicContainer` Turtle when `resource_rel_path` is `""` or `"/"`).
pub fn handle_solid_ldp_get(data_dir: &Path, pod_name: &str, resource_rel_path: &str, accept_header: &str) -> Result<(&'static str, Vec<u8>), &'static str> {
    if resource_rel_path.trim().is_empty() || resource_rel_path.trim() == "/" {
        let listing = list_solid_ldp_container_turtle(data_dir, pod_name)?;
        return Ok(("text/turtle; charset=utf-8", listing.into_bytes()));
    }
    let (clean_pod, clean_rel) = (sanitize_rel_segment(pod_name)?, sanitize_rel_segment(resource_rel_path)?);
    let base_path = data_dir.join("solid").join(clean_pod).join(clean_rel);
    if accept_header.contains("text/turtle") {
        let ttl_bytes = fs::read(&base_path).map_err(|_| "Solid LDP Turtle resource not found on disk")?;
        return Ok(("text/turtle; charset=utf-8", ttl_bytes));
    }
    let cbor_path = if clean_rel.ends_with(".cbor-ld") { base_path } else { cbor_ld_companion_path(&base_path) };
    let cbor_ld_bytes = fs::read(&cbor_path).map_err(|_| "Solid LDP CBOR-LD resource not found on disk")?;
    if cbor_ld_bytes.len() < 3 || cbor_ld_bytes[0..3] != [0xD9, 0x05, 0x01] {
        return Err("Corrupted Solid LDP CBOR-LD resource: missing 0xD90501 tag header");
    }
    Ok(("application/cbor-ld", cbor_ld_bytes))
}

/// Handle `DELETE /solid/<pod_name>/<rel_path>`: enforces WAC `Write`, deletes resource + `.cbor-ld` sidecar, and records an `OP_OBLIGATE` audit `NQuin`.
pub fn handle_solid_ldp_delete(data_dir: &Path, journal_path: &Path, pod_name: &str, rel_path: &str, actor_did: &str) -> Result<NQuin, &'static str> {
    validate_human_centric_nomenclature(pod_name)?;
    validate_human_centric_nomenclature(rel_path)?;
    validate_human_centric_nomenclature(actor_did)?;
    if !evaluate_wac_acl(data_dir, pod_name, rel_path, actor_did, WacPermission::Write) {
        return Err("WAC ACL denied Write permission for Solid LDP DELETE");
    }
    let (clean_pod, clean_rel) = (sanitize_rel_segment(pod_name)?, sanitize_rel_segment(rel_path)?);
    let ttl_path = data_dir.join("solid").join(clean_pod).join(clean_rel);
    if !ttl_path.exists() { return Err("Solid LDP resource not found on disk for DELETE"); }
    fs::remove_file(&ttl_path).map_err(|_| "Failed to delete Solid LDP Turtle resource")?;
    let cbor_path = cbor_ld_companion_path(&ttl_path);
    if cbor_path.exists() { let _ = fs::remove_file(&cbor_path); }

    let audit_quin = NQuin::new(
        q_hash(actor_did),
        pack_predicate("https://www.w3.org/ns/ldp#deletedResource", OP_OBLIGATE, false),
        q_hash(&format!("{clean_pod}/{clean_rel}")) & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash(clean_pod), SensitivityClass::Restricted),
        pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 0),
    );
    if let Some(parent) = journal_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "Failed to create Solid journal parent directory")?;
    }
    append_quin_to_journal(journal_path, &audit_quin).map_err(|_| "Failed to append Solid LDP DELETE audit NQuin to .q42j journal")?;
    Ok(audit_quin)
}

/// List all resources in `<data_dir>/solid/<pod_name>` as a W3C Solid `ldp:BasicContainer` Turtle document.
pub fn list_solid_ldp_container_turtle(data_dir: &Path, pod_name: &str) -> Result<String, &'static str> {
    let clean_pod = sanitize_rel_segment(pod_name)?;
    let pod_dir = data_dir.join("solid").join(clean_pod);
    let mut resources: Vec<String> = Vec::new();
    if pod_dir.exists() {
        let mut stack: Vec<PathBuf> = vec![pod_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir).map_err(|_| "Failed to read Solid pod directory")?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&pod_dir) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    if !rel_str.ends_with(".cbor-ld") && !rel_str.ends_with(".acl") { resources.push(rel_str); }
                }
            }
        }
    }
    resources.sort();
    if resources.is_empty() {
        Ok("@prefix ldp: <http://www.w3.org/ns/ldp#> .\n<> a ldp:BasicContainer, ldp:Container .\n".to_string())
    } else {
        let contained: Vec<String> = resources.iter().map(|r| format!("<{r}>")).collect();
        Ok(format!("@prefix ldp: <http://www.w3.org/ns/ldp#> .\n<> a ldp:BasicContainer, ldp:Container ; ldp:contains {} .\n", contained.join(", ")))
    }
}

/// Active Q-CDN peer offload helper: returns `HTTP 307` target URL when `used_egress_bytes * 100 >= cap_egress_bytes * 80`.
pub fn evaluate_qcdn_http307_offload(used_egress_bytes: u64, cap_egress_bytes: u64, healthy_seeder_endpoints: &[String], asset_path: &str) -> Option<String> {
    if cap_egress_bytes == 0 || healthy_seeder_endpoints.is_empty() { return None; }
    ((used_egress_bytes as u128) * 100 >= (cap_egress_bytes as u128) * 80)
        .then(|| format!("{}{}", healthy_seeder_endpoints[0].trim_end_matches('/'), asset_path))
}

/// Replay all `NQuin`s committed by the Solid LDP Pod Gateway into `journal_path`.
pub fn replay_solid_pod_journal(journal_path: &Path) -> Result<Vec<NQuin>, &'static str> {
    replay_quin_journal(journal_path).map_err(|_| "Failed to replay Solid LDP .q42j journal")
}

/// IPFS Content-Addressed Block Gateway & WebTorrent `HTTP 206` WebSeed Handler.
pub struct P2pWebSeedGateway;

impl P2pWebSeedGateway {
    pub fn publish_file_to_ipfs_and_webseed(data_dir: &Path, file_name: &str, payload: &[u8], origin_base_url: &str) -> Result<MultiProtocolShareDescriptor, &'static str> {
        publish_file_to_ipfs_and_webseed(data_dir, file_name, payload, origin_base_url)
    }
    pub fn serve_ipfs_block(data_dir: &Path, cid: &str) -> Result<Vec<u8>, &'static str> {
        serve_ipfs_block(data_dir, cid)
    }
    pub fn serve_webtorrent_webseed_range(data_dir: &Path, file_name: &str, start_byte: u64, end_byte_inclusive: u64) -> Result<(u16, String, Vec<u8>), &'static str> {
        serve_webtorrent_webseed_range(data_dir, file_name, start_byte, end_byte_inclusive)
    }
}

/// Publish a Permissive Commons file to `<data_dir>/files/<file_name>` and `<data_dir>/ipfs/<cid>`.
pub fn publish_file_to_ipfs_and_webseed(data_dir: &Path, file_name: &str, payload: &[u8], origin_base_url: &str) -> Result<MultiProtocolShareDescriptor, &'static str> {
    validate_human_centric_nomenclature(file_name)?;
    let clean_name = sanitize_rel_segment(file_name)?;
    let descriptor = MultiProtocolShareDescriptor::publish_permissive_commons(
        clean_name, FLAG_PERMISSIVE_COMMONS, SensitivityClass::Public, payload, origin_base_url, origin_base_url, Some("ns.webcivics.net"),
    ).map_err(|_| "Failed to publish Permissive Commons multi-protocol share descriptor")?;

    let files_path = data_dir.join("files").join(clean_name);
    if let Some(parent) = files_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "Failed to create WebSeed files directory")?;
    }
    fs::write(&files_path, payload).map_err(|_| "Failed to write WebSeed file to disk")?;

    let ipfs_dir = data_dir.join("ipfs");
    fs::create_dir_all(&ipfs_dir).map_err(|_| "Failed to create IPFS block directory")?;
    let cid_path = ipfs_dir.join(&descriptor.ipfs_cid);
    fs::write(&cid_path, payload).map_err(|_| "Failed to write IPFS block to disk")?;

    let sha256_cid_path = ipfs_dir.join(format!("bafkrei{}", hex_encode_32(&sha256(payload))));
    if sha256_cid_path != cid_path {
        fs::write(&sha256_cid_path, payload).map_err(|_| "Failed to write SHA-256 IPFS block alias to disk")?;
    }
    Ok(descriptor)
}

/// Read `<data_dir>/ipfs/<cid>`, verify `cid.starts_with("bafkrei")`, and enforce zero-trust block digest integrity.
pub fn serve_ipfs_block(data_dir: &Path, cid: &str) -> Result<Vec<u8>, &'static str> {
    let clean_cid = sanitize_rel_segment(cid)?;
    if !clean_cid.starts_with("bafkrei") { return Err("Invalid IPFS CIDv1 prefix: expected bafkrei..."); }
    let bytes = fs::read(data_dir.join("ipfs").join(clean_cid)).map_err(|_| "IPFS block not found on disk")?;
    let expected_q42_cid = format!("bafkrei{:016x}{:08x}", q_hash_bytes(&bytes), crc32c_bytes(&bytes));
    let expected_sha256_cid = format!("bafkrei{}", hex_encode_32(&sha256(&bytes)));
    if clean_cid != expected_q42_cid && clean_cid != expected_sha256_cid {
        return Err("Zero-trust IPFS block integrity verification failed: tampered bytes rejected");
    }
    Ok(bytes)
}

/// Serve a WebTorrent `HTTP 206 Partial Content` WebSeed byte range (`[start_byte..=end_byte_inclusive]`).
pub fn serve_webtorrent_webseed_range(data_dir: &Path, file_name: &str, start_byte: u64, end_byte_inclusive: u64) -> Result<(u16, String, Vec<u8>), &'static str> {
    let clean_name = sanitize_rel_segment(file_name)?;
    let (total, slice_bytes) = read_file_byte_range(&data_dir.join("files").join(clean_name), start_byte, end_byte_inclusive)
        .map_err(|_| "Failed to read requested WebSeed byte range from disk")?;
    Ok((206, format!("bytes {start_byte}-{end_byte_inclusive}/{total}"), slice_bytes))
}

fn parse_and_evaluate_acl_turtle(ttl: &str, agent_did: &str, required: WacPermission) -> bool {
    let (mut statements, mut current, mut in_angle, mut in_quote) = (Vec::new(), String::new(), false, false);
    for raw_line in ttl.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("@prefix") || trimmed.starts_with("PREFIX ") { continue; }
        for ch in trimmed.chars() {
            match ch {
                '<' if !in_quote => in_angle = true,
                '>' if !in_quote => in_angle = false,
                '"' if !in_angle => in_quote = !in_quote,
                '.' if !in_angle && !in_quote => { statements.push(std::mem::take(&mut current)); continue; }
                _ => {}
            }
            current.push(ch);
        }
        current.push(' ');
    }
    if !current.trim().is_empty() { statements.push(current); }

    let mut rules_by_subject: Vec<(String, String)> = Vec::new();
    for stmt in statements {
        let s_trim = stmt.trim();
        if s_trim.is_empty() { continue; }
        let subj = s_trim.split_whitespace().next().unwrap_or("");
        if let Some((_, body)) = rules_by_subject.iter_mut().find(|(k, _)| k == subj) {
            body.push(' ');
            body.push_str(s_trim);
        } else {
            rules_by_subject.push((subj.to_string(), s_trim.to_string()));
        }
    }

    rules_by_subject.iter().any(|(_, rule)| {
        let agent_ok = rule.contains("foaf:Agent")
            || rule.contains("http://xmlns.com/foaf/0.1/Agent")
            || (!agent_did.is_empty()
                && (rule.contains(&format!("<{agent_did}>"))
                    || rule.contains(&format!("\"{agent_did}\""))
                    || rule.split(|c: char| c.is_whitespace() || matches!(c, ';' | ',' | '<' | '>')).any(|t| t == agent_did)));
        let mode_ok = match required {
            WacPermission::Read => rule.contains("acl:Read") || rule.contains("acl#Read"),
            WacPermission::Write => rule.contains("acl:Write") || rule.contains("acl#Write"),
            WacPermission::Append => rule.contains("acl:Append") || rule.contains("acl#Append") || rule.contains("acl:Write") || rule.contains("acl#Write"),
            WacPermission::Control => rule.contains("acl:Control") || rule.contains("acl#Control"),
        };
        agent_ok && mode_ok
    })
}

fn cbor_ld_companion_path(ttl_path: &Path) -> PathBuf {
    ttl_path.with_extension(match ttl_path.extension() {
        Some(ext) => format!("{}.cbor-ld", ext.to_string_lossy()),
        None => "cbor-ld".to_string(),
    })
}

fn sanitize_rel_segment(input: &str) -> Result<&str, &'static str> {
    let trimmed = input.trim().trim_start_matches(['/', '\\']);
    if trimmed.is_empty() || trimmed.contains("..") { return Err("Invalid or traversal-attempt path segment rejected"); }
    Ok(trimmed)
}

fn parse_turtle_triple_line(line: &str) -> Result<(&str, &str, &str), &'static str> {
    let body = line.trim_end_matches('.').trim();
    let (s_raw, after_s) = body.split_once(char::is_whitespace).ok_or("Malformed Turtle triple: missing predicate")?;
    let (p_raw, after_p) = after_s.trim_start().split_once(char::is_whitespace).ok_or("Malformed Turtle triple: missing object")?;
    let (s, p, o) = (s_raw.trim_matches(['<', '>']), p_raw.trim_matches(['<', '>']), after_p.trim().trim_matches(['<', '>', '"']));
    if s.is_empty() || p.is_empty() || o.is_empty() { return Err("Malformed Turtle triple: empty term"); }
    Ok((s, p, o))
}

fn is_owl_thing_reference(obj_uri: &str) -> bool {
    obj_uri == "owl:Thing" || obj_uri == "http://www.w3.org/2002/07/owl#Thing" || obj_uri.ends_with("owl#Thing")
}

fn hex_encode_32(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct ScopedTempDir { path: PathBuf }
    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("qualia_webizen_solid_ipfs_{}_{}_{}", label, std::process::id(), id));
            fs::create_dir_all(&path).expect("create ScopedTempDir");
            Self { path }
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.path); }
    }

    #[test]
    fn d10_3_solid_ldp_put_get_cbor_ld_non_thing_and_ebpf_quota() {
        let tmp = ScopedTempDir::new("solid_ldp");
        let journal_path = tmp.path.join("solid_pod.q42j");
        let mut sandbox = Tier3SolidAndEbpfSandbox {
            pod_root_uri: "https://web.civics.au/alice/".to_string(),
            owner_did_hash: q_hash("did:qi:alice"),
            ebpf_egress_ceiling_bytes: 512,
            ebpf_egress_used_bytes: 0,
        };
        let ttl = "<https://web.civics.au/alice#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .\n\
                   <https://web.civics.au/alice#me> <https://ns.webcivics.net/care#hasRole> <https://ns.webcivics.net/care#Guardian> .";
        let receipt = handle_solid_ldp_put(&tmp.path, &journal_path, &mut sandbox, "alice", "profile/card.ttl", ttl).expect("valid PUT");
        assert_eq!(receipt.quins_stored, 2);
        assert_eq!(&receipt.cbor_ld_bytes[0..3], &[0xD9, 0x05, 0x01]);

        let (mime_cbor, bytes_cbor) = handle_solid_ldp_get(&tmp.path, "alice", "profile/card.ttl", "*/*").unwrap();
        assert_eq!(mime_cbor, "application/cbor-ld");
        assert_eq!(&bytes_cbor[0..3], &[0xD9, 0x05, 0x01]);

        let (mime_ttl, bytes_ttl) = handle_solid_ldp_get(&tmp.path, "alice", "profile/card.ttl", "text/turtle").unwrap();
        assert_eq!(mime_ttl, "text/turtle; charset=utf-8");
        assert_eq!(bytes_ttl, ttl.as_bytes());
        assert_eq!(replay_solid_pod_journal(&journal_path).unwrap().len(), 2);

        let bad_ttl = "<https://ns.webcivics.net/agent#NaturalAgent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> .";
        assert!(handle_solid_ldp_put(&tmp.path, &journal_path, &mut sandbox, "alice", "profile/bad.ttl", bad_ttl).is_err());

        let mut tiny_sandbox = Tier3SolidAndEbpfSandbox {
            pod_root_uri: "https://web.civics.au/alice/".to_string(),
            owner_did_hash: q_hash("did:qi:alice"),
            ebpf_egress_ceiling_bytes: 16,
            ebpf_egress_used_bytes: 0,
        };
        assert!(handle_solid_ldp_put(&tmp.path, &journal_path, &mut tiny_sandbox, "alice", "profile/overflow.ttl", ttl).is_err());
    }

    #[test]
    fn d10_4_ipfs_block_gateway_tamper_rejection_and_webseed_http_206() {
        let tmp = ScopedTempDir::new("ipfs_webseed");
        let payload = b"Permissive Commons SuperBlock Slice: Human Rights & Guardianship Semantics";
        let desc = publish_file_to_ipfs_and_webseed(&tmp.path, "webcivics_ns.q42", payload, "https://ns.webcivics.net").expect("publish");
        assert!(desc.ipfs_cid.starts_with("bafkrei"));
        assert_eq!(serve_ipfs_block(&tmp.path, &desc.ipfs_cid).unwrap(), payload);

        let (status, content_range, slice) = serve_webtorrent_webseed_range(&tmp.path, "webcivics_ns.q42", 0, 17).unwrap();
        assert_eq!(status, 206);
        assert_eq!(content_range, format!("bytes 0-17/{}", payload.len()));
        assert_eq!(slice, &payload[0..=17]);

        let block_path = tmp.path.join("ipfs").join(&desc.ipfs_cid);
        let mut tampered = fs::read(&block_path).unwrap();
        tampered[0] ^= 0xFF;
        fs::write(&block_path, &tampered).unwrap();
        assert!(serve_ipfs_block(&tmp.path, &desc.ipfs_cid).is_err());
    }

    #[test]
    fn wp17_wac_acl_etag_container_delete_and_qcdn_http307_offload() {
        let tmp = ScopedTempDir::new("wp17_solid_wac");
        let journal_path = tmp.path.join("solid_wp17.q42j");
        let mut sandbox = Tier3SolidAndEbpfSandbox {
            pod_root_uri: "https://web.civics.au/alice/".to_string(),
            owner_did_hash: q_hash("did:qi:alice"),
            ebpf_egress_ceiling_bytes: 4096,
            ebpf_egress_used_bytes: 0,
        };
        let ttl = "<https://web.civics.au/alice#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";
        handle_solid_ldp_put(&tmp.path, &journal_path, &mut sandbox, "alice", "profile/card.ttl", ttl).unwrap();

        let etag = compute_resource_etag(ttl.as_bytes());
        assert_eq!(etag, format!("\"{:08x}\"", crc32c_bytes(ttl.as_bytes())));

        assert!(evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:bob", WacPermission::Read));
        assert!(!evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:bob", WacPermission::Write));
        assert!(evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:alice", WacPermission::Control));

        let acl_ttl = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                       @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                       <#owner> a acl:Authorization ; acl:agent <did:qi:alice> ; acl:mode acl:Read, acl:Write, acl:Control .\n\
                       <#delegate> a acl:Authorization ; acl:agent <did:qi:guardian_bob> ; acl:mode acl:Read, acl:Write .\n\
                       <#public> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:mode acl:Read .\n";
        fs::write(tmp.path.join("solid/alice/.acl"), acl_ttl).unwrap();
        assert!(evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:guardian_bob", WacPermission::Write));
        assert!(!evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:guardian_bob", WacPermission::Control));
        assert!(!evaluate_wac_acl(&tmp.path, "alice", "profile/card.ttl", "did:qi:stranger", WacPermission::Write));

        let (_, container_bytes) = handle_solid_ldp_get(&tmp.path, "alice", "/", "text/turtle").unwrap();
        let container_str = String::from_utf8(container_bytes).unwrap();
        assert!(container_str.contains("a ldp:BasicContainer, ldp:Container"));
        assert!(container_str.contains("<profile/card.ttl>"));

        assert!(handle_solid_ldp_delete(&tmp.path, &journal_path, "alice", "profile/card.ttl", "did:qi:stranger").is_err());
        let del_quin = handle_solid_ldp_delete(&tmp.path, &journal_path, "alice", "profile/card.ttl", "did:qi:guardian_bob").unwrap();
        assert!(del_quin.verify_parity());
        assert_eq!((del_quin.predicate & 0xFF) as u8, OP_OBLIGATE);
        assert!(handle_solid_ldp_get(&tmp.path, "alice", "profile/card.ttl", "text/turtle").is_err());

        let seeders = vec!["https://seeder1.commons.au/".to_string()];
        assert_eq!(evaluate_qcdn_http307_offload(79, 100, &seeders, "/ipfs/bafkrei123"), None);
        assert_eq!(
            evaluate_qcdn_http307_offload(80, 100, &seeders, "/ipfs/bafkrei123"),
            Some("https://seeder1.commons.au/ipfs/bafkrei123".to_string())
        );
    }
}
