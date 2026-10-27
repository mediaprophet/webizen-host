//! WP-26 (D26.1) & WP-29 (D29.1): Q-CDN `< 10 KiB` Signed Root Index, Zero-Trust Chunk Verification,
//! Hard Egress Circuit Breaker (`HTTP 307`), and Native Git Pull Request / Issue Tracker Forge Routes.

use std::{collections::BTreeMap, fs, io::{self, ErrorKind}, path::{Path, PathBuf}};
use vibe::{encode_value_cbor_ld, Value};
use webizen_host_core::{is_non_thing_human_or_living_class, pack_context, pack_metadata, pack_predicate, q_hash, sha256, validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_MEDIA_TYPE, OP_OBLIGATE, OP_PERMIT};
use webizen_host_ingest::{append_quin_to_journal, CompiledQ42Volume};
use webizen_host_namespace::{CallerStanding, EgressDecision, HardEgressCircuitBreaker};
use webizen_host_qcdn::{MultiProtocolShareDescriptor, QcdnSwarmCoordinator, QcdnSwarmTier, SignedRootIndex, FLAG_PERMISSIVE_COMMONS};
use crate::{auth_and_session::parse_urlencoded_form, git_smart_http::{handle_git_receive_pack_push, OnDiskGitRepoStore}, http_routes_ext::encode_quin_receipt, vps_deployment::CBOR_LD_HEADER};

pub const DEFAULT_QCDN_CHUNK_0: &[u8] = b"40KiB SuperBlock #0: Human Rights Instruments NQuin payload";
pub const DEFAULT_QCDN_CHUNK_1: &[u8] = b"40KiB SuperBlock #1: SHACL Guardianship & Capacity shapes";

#[inline]
fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes { out.push(HEX[(b >> 4) as usize]); out.push(HEX[(b & 0x0F) as usize]); }
    String::from_utf8(out).unwrap_or_default()
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"), '<' => out.push_str("&lt;"), '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"), '\'' => out.push_str("&#39;"), _ => out.push(ch),
        }
    }
    out
}

fn build_volume_root_index(q42_path: &Path) -> (SignedRootIndex, Vec<Vec<u8>>) {
    let owned_chunks: Vec<Vec<u8>> = CompiledQ42Volume::load_from_disk(q42_path).ok().filter(|v| !v.superblocks.is_empty())
        .map(|v| v.superblocks.iter().take(8).map(|sb| sb.to_vec()).collect())
        .unwrap_or_else(|| vec![DEFAULT_QCDN_CHUNK_0.to_vec(), DEFAULT_QCDN_CHUNK_1.to_vec()]);
    let refs: Vec<&[u8]> = owned_chunks.iter().map(Vec::as_slice).collect();
    (SignedRootIndex::build("https://ns.webcivics.net/volumes/core.q42", "did:qi:webcivics_steward", &refs, 250), owned_chunks)
}

fn load_egress_breaker(meter_path: &Path, default_cap: u64) -> HardEgressCircuitBreaker {
    if let Ok(raw) = fs::read(meter_path) {
        if raw.len() >= 21 && raw[0..3] == CBOR_LD_HEADER && raw[3] == 1 {
            return HardEgressCircuitBreaker {
                max_monthly_origin_bytes: u64::from_be_bytes(raw[4..12].try_into().unwrap_or([0; 8])),
                max_permitted_overage_cents: 0, cost_per_gib_cents: 9,
                observed_origin_bytes: u64::from_be_bytes(raw[12..20].try_into().unwrap_or([0; 8])), tripped: raw[20] != 0,
            };
        }
    }
    HardEgressCircuitBreaker::new_zero_overage(default_cap, 9)
}

fn save_egress_breaker(meter_path: &Path, b: &HardEgressCircuitBreaker) -> io::Result<()> {
    let mut buf = Vec::with_capacity(53);
    buf.extend_from_slice(&CBOR_LD_HEADER);
    buf.push(1);
    buf.extend_from_slice(&b.max_monthly_origin_bytes.to_be_bytes());
    buf.extend_from_slice(&b.observed_origin_bytes.to_be_bytes());
    buf.push(u8::from(b.tripped));
    let seal = sha256(&buf);
    buf.extend_from_slice(&seal);
    if let Some(p) = meter_path.parent() { fs::create_dir_all(p)?; }
    fs::write(meter_path, buf)
}

/// **D26.1**: Handle Q-CDN `< 10 KiB` Signed Root Index (`GET /qcdn/root-index.cbor-ld`),
/// Zero-Trust Chunk Verification (`POST /qcdn/verify-chunk`), and Hard Egress Circuit Breaker (`HTTP 307`).
pub fn handle_qcdn_extended_route(
    data_dir: &Path, q42_path: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8],
) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    let (clean_path, query_str) = path.split_once('?').unwrap_or((path, ""));
    match (method, clean_path) {
        ("GET", "/qcdn/root-index.cbor-ld") => {
            let (root_idx, raw_chunks) = build_volume_root_index(q42_path);
            let share = MultiProtocolShareDescriptor::publish_permissive_commons(
                "core.q42", FLAG_PERMISSIVE_COMMONS, SensitivityClass::Public, &raw_chunks[0],
                "https://ns.webcivics.net", "https://ipfs.webcivics.net", Some("ns.webcivics.net"),
            ).ok();
            let chunk_items: Vec<Value> = root_idx.chunks.iter().map(|c| {
                let mut m = BTreeMap::new();
                m.insert("seq".to_string(), Value::I64(i64::from(c.chunk_seq)));
                m.insert("off".to_string(), Value::I64(c.byte_offset as i64));
                m.insert("len".to_string(), Value::I64(i64::from(c.byte_length)));
                m.insert("crc32c".to_string(), Value::I64(i64::from(c.expected_crc32c)));
                m.insert("sha256".to_string(), Value::String(bytes_to_hex(&c.expected_sha256[..8])));
                Value::Record(m)
            }).collect();
            let mut rec = BTreeMap::new();
            rec.insert("asset_uri".to_string(), Value::String(root_idx.asset_uri));
            rec.insert("publisher_did_hash".to_string(), Value::I64(root_idx.publisher_did_hash as i64));
            rec.insert("chunk_count".to_string(), Value::I64(chunk_items.len() as i64));
            rec.insert("merkle_root_hex".to_string(), Value::String(bytes_to_hex(&root_idx.merkle_root_sha256)));
            rec.insert("signature_tag".to_string(), Value::I64(root_idx.signature_tag as i64));
            if let Some(s) = share {
                rec.insert("ipfs_cid".to_string(), Value::String(s.ipfs_cid));
                rec.insert("magnet_uri".to_string(), Value::String(s.magnet_uri));
            }
            rec.insert("chunks".to_string(), Value::List(chunk_items));
            let payload = encode_value_cbor_ld(&Value::Record(rec), "https://ns.webcivics.net/qcdn/root-index");
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, payload)))
        }
        ("POST", "/qcdn/verify-chunk") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let seeder_did = form.get("seeder_did").map(String::as_str).unwrap_or("did:qi:peer_seeder_au");
            let chunk_seq = form.get("chunk_seq").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let chunk_data = form.get("chunk_data").map(|s| s.as_bytes().to_vec()).unwrap_or_else(|| DEFAULT_QCDN_CHUNK_0.to_vec());

            let (vol_idx, _) = build_volume_root_index(q42_path);
            let fallback_idx = SignedRootIndex::build("https://ns.webcivics.net/volumes/core.q42", "did:qi:webcivics_steward", &[DEFAULT_QCDN_CHUNK_0, DEFAULT_QCDN_CHUNK_1], 250);
            let active_idx = if vol_idx.verify_peer_chunk(chunk_seq, &chunk_data).is_ok() { &vol_idx } else { &fallback_idx };

            let swarm_path = data_dir.join("qcdn_swarm.cbor-ld");
            let existing_swarm = fs::read(&swarm_path).unwrap_or_default();
            let already_banned = String::from_utf8_lossy(&existing_swarm).lines().any(|l| l.contains(&format!("seeder={seeder_did}")) && l.contains("banned=true"));

            let mut coord = QcdnSwarmCoordinator::new();
            coord.register_seeder(seeder_did, QcdnSwarmTier::TierBDesktopUserSeederPort4242, "https://peer1.civics.au/torrent/webseed");
            if already_banned { coord.seeders[0].banned_for_corruption = true; }

            match coord.admit_chunk_from_seeder(seeder_did, active_idx, chunk_seq, &chunk_data) {
                Ok(weight) => {
                    let mut out = vec![0xD9, 0x05, 0x01, 1];
                    out.extend_from_slice(format!("seeder={seeder_did}|seq={chunk_seq}|verified=true|banned=false|weight={weight}\n").as_bytes());
                    if existing_swarm.len() > 4 && existing_swarm[0..3] == CBOR_LD_HEADER { out.extend_from_slice(&existing_swarm[4..]); }
                    fs::write(&swarm_path, out)?;
                    let quin = NQuin::new(
                        q_hash(seeder_did), pack_predicate("https://ns.webcivics.net/qcdn#verifiedSwarmChunk", OP_PERMIT, false),
                        weight & 0x0FFF_FFFF_FFFF_FFFF, pack_context(active_idx.publisher_did_hash, SensitivityClass::Public),
                        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, chunk_seq),
                    );
                    append_quin_to_journal(journal_path, &quin)?;
                    Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
                }
                Err(_) => {
                    let mut out = vec![0xD9, 0x05, 0x01, 1];
                    out.extend_from_slice(format!("seeder={seeder_did}|seq={chunk_seq}|verified=false|banned=true\n").as_bytes());
                    if existing_swarm.len() > 4 && existing_swarm[0..3] == CBOR_LD_HEADER { out.extend_from_slice(&existing_swarm[4..]); }
                    fs::write(&swarm_path, out)?;
                    Ok(Some((422, "text/plain; charset=utf-8", b"Q-CDN chunk verification failed: seeder banned".to_vec())))
                }
            }
        }
        ("POST", "/qcdn/egress-check") | ("GET", "/qcdn/egress-check") => {
            let raw_params = if body.is_empty() { query_str } else { std::str::from_utf8(body).unwrap_or("") };
            let form = parse_urlencoded_form(raw_params);
            let response_bytes = form.get("response_bytes").and_then(|s| s.parse::<u64>().ok()).unwrap_or(40_960);
            let is_natural = form.get("is_natural_person").map(|v| v == "1" || v == "true").unwrap_or(false);
            let is_root_index = form.get("is_root_index").map(|v| v == "1" || v == "true").unwrap_or(false);
            let cap_override = form.get("max_monthly_origin_bytes").and_then(|s| s.parse::<u64>().ok());

            let meter_path = data_dir.join("egress_meter.cbor-ld");
            let mut breaker = load_egress_breaker(&meter_path, cap_override.unwrap_or(100 * 1024));
            if let Some(cap) = cap_override { breaker.max_monthly_origin_bytes = cap; }
            let standing = if is_natural { CallerStanding::VerifiedNaturalPersonOrHumanitarian } else { CallerStanding::UnauthenticatedOrCommercialBulk };
            let decision = breaker.admit_or_offload(response_bytes, standing, is_root_index);
            save_egress_breaker(&meter_path, &breaker)?;

            match decision {
                EgressDecision::RedirectToQcdnSwarm { http_status: 307, .. } => Ok(Some((
                    307, "text/plain; charset=utf-8", b"RedirectToQcdnSwarm: Location: https://peer1.civics.au/torrent/webseed/core.q42".to_vec(),
                ))),
                _ => {
                    let quin = NQuin::new(
                        q_hash("https://ns.webcivics.net/qcdn#OriginEgressMeter"),
                        pack_predicate("https://ns.webcivics.net/qcdn#admittedOriginEgress", OP_PERMIT, false),
                        breaker.observed_origin_bytes & 0x0FFF_FFFF_FFFF_FFFF,
                        pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public),
                        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, response_bytes as u32),
                    );
                    append_quin_to_journal(journal_path, &quin)?;
                    Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
                }
            }
        }
        _ => Ok(None),
    }
}

/// Persisted Pull Request record in `<data_dir>/git/<repo_name>_forge.cbor-ld`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPullRequestRecord {
    pub pr_id: u64, pub repo_name: String, pub title: String, pub author_did: String,
    pub source_branch: String, pub target_branch: String, pub diff_preview: String,
    pub shacl_ci_passed: bool, pub approvals: Vec<String>, pub required_quorum_m: usize, pub merged: bool,
}

/// Persisted Issue record in `<data_dir>/git/<repo_name>_forge.cbor-ld`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitIssueRecord {
    pub issue_id: u64, pub repo_name: String, pub title: String, pub author_did: String, pub body: String, pub open: bool,
}

fn write_lp(buf: &mut Vec<u8>, s: &str) { buf.extend_from_slice(&(s.len() as u32).to_be_bytes()); buf.extend_from_slice(s.as_bytes()); }
fn read_u32_be(raw: &[u8], cur: &mut usize) -> io::Result<u32> {
    if *cur + 4 > raw.len() { return Err(io::Error::new(ErrorKind::UnexpectedEof, "truncated u32")); }
    let v = u32::from_be_bytes(raw[*cur..*cur + 4].try_into().unwrap()); *cur += 4; Ok(v)
}
fn read_lp(raw: &[u8], cur: &mut usize) -> io::Result<String> {
    let len = read_u32_be(raw, cur)? as usize;
    if *cur + len > raw.len() { return Err(io::Error::new(ErrorKind::UnexpectedEof, "truncated str")); }
    let s = std::str::from_utf8(&raw[*cur..*cur + len]).map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid utf8"))?.to_string();
    *cur += len; Ok(s)
}
fn forge_state_path(data_dir: &Path, repo_clean: &str) -> PathBuf { data_dir.join("git").join(format!("{repo_clean}_forge.cbor-ld")) }

pub fn save_git_forge_state(data_dir: &Path, repo_clean: &str, prs: &[GitPullRequestRecord], issues: &[GitIssueRecord]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&CBOR_LD_HEADER);
    buf.push(1);
    buf.extend_from_slice(&(prs.len() as u32).to_be_bytes());
    for pr in prs {
        buf.extend_from_slice(&pr.pr_id.to_be_bytes());
        for s in [&pr.repo_name, &pr.title, &pr.author_did, &pr.source_branch, &pr.target_branch, &pr.diff_preview] { write_lp(&mut buf, s); }
        buf.push(u8::from(pr.shacl_ci_passed));
        buf.extend_from_slice(&(pr.approvals.len() as u32).to_be_bytes());
        for a in &pr.approvals { write_lp(&mut buf, a); }
        buf.extend_from_slice(&(pr.required_quorum_m as u32).to_be_bytes());
        buf.push(u8::from(pr.merged));
    }
    buf.extend_from_slice(&(issues.len() as u32).to_be_bytes());
    for iss in issues {
        buf.extend_from_slice(&iss.issue_id.to_be_bytes());
        for s in [&iss.repo_name, &iss.title, &iss.author_did, &iss.body] { write_lp(&mut buf, s); }
        buf.push(u8::from(iss.open));
    }
    let seal = sha256(&buf);
    buf.extend_from_slice(&seal);
    let path = forge_state_path(data_dir, repo_clean);
    if let Some(p) = path.parent() { fs::create_dir_all(p)?; }
    fs::write(path, buf)
}

pub fn load_git_forge_state(data_dir: &Path, repo_clean: &str) -> io::Result<(Vec<GitPullRequestRecord>, Vec<GitIssueRecord>)> {
    let path = forge_state_path(data_dir, repo_clean);
    if !path.exists() { return Ok((Vec::new(), Vec::new())); }
    let raw = fs::read(&path)?;
    if raw.len() < 36 || raw[0..3] != CBOR_LD_HEADER || raw[3] != 1 { return Err(io::Error::new(ErrorKind::InvalidData, "invalid forge CBOR-LD header")); }
    let payload = &raw[..raw.len() - 32];
    if sha256(payload) != raw[raw.len() - 32..] { return Err(io::Error::new(ErrorKind::InvalidData, "forge state SHA-256 seal mismatch")); }
    let mut cur = 4usize;
    let pr_count = read_u32_be(payload, &mut cur)? as usize;
    let mut prs = Vec::with_capacity(pr_count.min(512));
    for _ in 0..pr_count {
        let pr_id = (u64::from(read_u32_be(payload, &mut cur)?) << 32) | u64::from(read_u32_be(payload, &mut cur)?);
        let (repo_name, title, author_did, source_branch, target_branch, diff_preview) = (
            read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?,
            read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?,
        );
        let shacl_ci_passed = payload.get(cur).copied().unwrap_or(0) != 0;
        cur += 1;
        let app_count = read_u32_be(payload, &mut cur)? as usize;
        let mut approvals = Vec::with_capacity(app_count.min(64));
        for _ in 0..app_count { approvals.push(read_lp(payload, &mut cur)?); }
        let required_quorum_m = read_u32_be(payload, &mut cur)? as usize;
        let merged = payload.get(cur).copied().unwrap_or(0) != 0;
        cur += 1;
        prs.push(GitPullRequestRecord { pr_id, repo_name, title, author_did, source_branch, target_branch, diff_preview, shacl_ci_passed, approvals, required_quorum_m, merged });
    }
    let iss_count = read_u32_be(payload, &mut cur)? as usize;
    let mut issues = Vec::with_capacity(iss_count.min(512));
    for _ in 0..iss_count {
        let issue_id = (u64::from(read_u32_be(payload, &mut cur)?) << 32) | u64::from(read_u32_be(payload, &mut cur)?);
        let (repo_name, title, author_did, body) = (read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?, read_lp(payload, &mut cur)?);
        let open = payload.get(cur).copied().unwrap_or(0) != 0;
        cur += 1;
        issues.push(GitIssueRecord { issue_id, repo_name, title, author_did, body, open });
    }
    Ok((prs, issues))
}

/// **D29.1**: Native Git Pull Request, SHACL Non-Thing CI Gate & Issue Tracker Forge Routes.
pub fn handle_git_forge_route(
    data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8],
) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    let clean_path = path.split('?').next().unwrap_or(path);
    let Some(rest) = clean_path.strip_prefix("/git/") else { return Ok(None); };
    let Some((repo_seg, action)) = rest.split_once('/') else { return Ok(None); };
    let repo_clean = repo_seg.strip_suffix(".git").unwrap_or(repo_seg);
    if repo_clean.is_empty() || validate_human_centric_nomenclature(repo_clean).is_err() {
        return Ok(Some((422, "text/plain; charset=utf-8", b"Invalid repository nomenclature".to_vec())));
    }
    let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
    match (method, action) {
        ("POST", "pr/open") => {
            let title = form.get("title").map(String::as_str).unwrap_or("Human-Centric Ontology Update");
            let author_did = form.get("author_did").map(String::as_str).unwrap_or("did:qi:contributor_alice");
            let source_branch = form.get("source_branch").map(String::as_str).unwrap_or("feat/human-centric");
            let target_branch = form.get("target_branch").map(String::as_str).unwrap_or("main");
            let diff = form.get("diff").or_else(|| form.get("diff_preview")).map(String::as_str).unwrap_or("+ wc:NaturalAgent a rdfs:Class .");
            let required_quorum_m = form.get("required_quorum_m").and_then(|s| s.parse::<usize>().ok()).unwrap_or(2);
            let shacl_ci_passed = !((diff.contains("owl:Thing") || diff.contains("owl#Thing")) && is_non_thing_human_or_living_class(diff));
            if [title, author_did, diff].iter().any(|s| validate_human_centric_nomenclature(s).is_err()) || !shacl_ci_passed {
                return Ok(Some((422, "text/plain; charset=utf-8", b"Git PR rejected by Human-Centric Nomenclature or SHACL Non-Thing CI gate".to_vec())));
            }
            let (mut prs, issues) = load_git_forge_state(data_dir, repo_clean)?;
            let pr_id = form.get("pr_id").and_then(|s| s.parse::<u64>().ok()).unwrap_or((prs.len() as u64) + 1);
            prs.push(GitPullRequestRecord {
                pr_id, repo_name: repo_clean.to_string(), title: title.to_string(), author_did: author_did.to_string(),
                source_branch: source_branch.to_string(), target_branch: target_branch.to_string(), diff_preview: diff.to_string(),
                shacl_ci_passed, approvals: Vec::new(), required_quorum_m: required_quorum_m.max(1), merged: false,
            });
            save_git_forge_state(data_dir, repo_clean, &prs, &issues)?;
            let quin = NQuin::new(
                q_hash(author_did), pack_predicate("https://ns.webcivics.net/git#openedPullRequest", OP_OBLIGATE, false),
                pr_id & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(repo_clean), SensitivityClass::Public),
                pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, pr_id as u32),
            );
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("POST", "pr/approve") => {
            let pr_id = form.get("pr_id").and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
            let approver = form.get("approver_did").or_else(|| form.get("steward_did")).map(String::as_str).unwrap_or("did:qi:steward_1");
            if validate_human_centric_nomenclature(approver).is_err() {
                return Ok(Some((422, "text/plain; charset=utf-8", b"Invalid approver nomenclature".to_vec())));
            }
            let (mut prs, issues) = load_git_forge_state(data_dir, repo_clean)?;
            let Some(pr) = prs.iter_mut().find(|p| p.pr_id == pr_id) else {
                return Ok(Some((404, "text/plain; charset=utf-8", b"Pull Request not found".to_vec())));
            };
            if !pr.approvals.iter().any(|a| a == approver) { pr.approvals.push(approver.to_string()); }
            let approvals_len = pr.approvals.len() as u32;
            save_git_forge_state(data_dir, repo_clean, &prs, &issues)?;
            let quin = NQuin::new(
                q_hash(approver), pack_predicate("https://ns.webcivics.net/git#approvedPullRequest", OP_PERMIT, false),
                pr_id & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(repo_clean), SensitivityClass::Public),
                pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, approvals_len, pr_id as u32),
            );
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("POST", "pr/merge") => {
            let pr_id = form.get("pr_id").and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
            let (mut prs, issues) = load_git_forge_state(data_dir, repo_clean)?;
            let Some(pr) = prs.iter_mut().find(|p| p.pr_id == pr_id) else {
                return Ok(Some((404, "text/plain; charset=utf-8", b"Pull Request not found".to_vec())));
            };
            if !pr.shacl_ci_passed || pr.approvals.len() < pr.required_quorum_m.max(1) {
                return Ok(Some((403, "text/plain; charset=utf-8", b"Forbidden: M-of-N Cooperative Steward Quorum or SHACL CI gate not met".to_vec())));
            }
            let repo_dir = OnDiskGitRepoStore::init_bare_repo(&data_dir.join("git"), repo_clean)?;
            let commit_msg = format!("Merge PR #{}: {}\n{}", pr.pr_id, pr.title, pr.diff_preview);
            let receipt = handle_git_receive_pack_push(&repo_dir, journal_path, &pr.author_did, &commit_msg, pr.approvals.len(), pr.required_quorum_m)
                .map_err(|e| io::Error::new(ErrorKind::PermissionDenied, e))?;
            pr.merged = true;
            save_git_forge_state(data_dir, repo_clean, &prs, &issues)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&receipt.contributor_quin))))
        }
        ("POST", "issues/open") => {
            let title = form.get("title").map(String::as_str).unwrap_or("Guardianship Shape Issue");
            let author_did = form.get("author_did").map(String::as_str).unwrap_or("did:qi:reporter_alice");
            let issue_body = form.get("body").map(String::as_str).unwrap_or("Verify SHACL constraints");
            if [title, author_did, issue_body].iter().any(|s| validate_human_centric_nomenclature(s).is_err()) {
                return Ok(Some((422, "text/plain; charset=utf-8", b"Issue rejected by nomenclature gate".to_vec())));
            }
            let (prs, mut issues) = load_git_forge_state(data_dir, repo_clean)?;
            let issue_id = (issues.len() as u64) + 1;
            issues.push(GitIssueRecord { issue_id, repo_name: repo_clean.to_string(), title: title.to_string(), author_did: author_did.to_string(), body: issue_body.to_string(), open: true });
            save_git_forge_state(data_dir, repo_clean, &prs, &issues)?;
            let quin = NQuin::new(
                q_hash(author_did), pack_predicate("https://ns.webcivics.net/git#openedIssue", OP_OBLIGATE, false),
                issue_id & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(repo_clean), SensitivityClass::Public),
                pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, issue_id as u32),
            );
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("GET", "prs") => {
            let (prs, issues) = load_git_forge_state(data_dir, repo_clean)?;
            let esc_repo = escape_html(repo_clean);
            let mut pr_rows = String::new();
            for p in &prs {
                let (ci_badge, state_badge) = (if p.shacl_ci_passed { "SHACL CI Passed" } else { "SHACL CI Failed" }, if p.merged { "MERGED" } else { "OPEN" });
                pr_rows.push_str(&format!(
                    "<tr><td>#{}</td><td><strong>{}</strong> ({} &rarr; {})</td><td><code>{}</code></td><td>{}</td><td>{}/{}</td><td>{}</td><td><form method=\"POST\" action=\"/git/{esc_repo}/pr/merge\"><input type=\"hidden\" name=\"pr_id\" value=\"{}\"><button type=\"submit\">Merge</button></form></td></tr>\n",
                    p.pr_id, escape_html(&p.title), escape_html(&p.source_branch), escape_html(&p.target_branch),
                    escape_html(&p.author_did), ci_badge, p.approvals.len(), p.required_quorum_m, state_badge, p.pr_id
                ));
            }
            let mut issue_rows = String::new();
            for i in &issues {
                issue_rows.push_str(&format!(
                    "<li><strong>#{} {}</strong> by <code>{}</code> — {} [{}]</li>\n",
                    i.issue_id, escape_html(&i.title), escape_html(&i.author_did), escape_html(&i.body), if i.open { "OPEN" } else { "CLOSED" }
                ));
            }
            let html = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'; object-src 'none';\"><title>Webizen Git Forge PRs &amp; Issues — {esc_repo}</title></head><body><header><h1>Git Forge Portal: {esc_repo}</h1></header><main><section><h2>Pull Requests ({})</h2><table><thead><tr><th>ID</th><th>Title</th><th>Author</th><th>CI Gate</th><th>Quorum</th><th>Status</th><th>Action</th></tr></thead><tbody>\n{pr_rows}</tbody></table></section><section><h2>Issues ({})</h2><ul>\n{issue_rows}</ul></section></main></body></html>\n",
                prs.len(), issues.len()
            );
            Ok(Some((200, "text/html; charset=utf-8", html.into_bytes())))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn qcdn_root_index_chunk_verification_and_egress_breaker_and_git_forge_lifecycle() {
        static CNT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!("qualia_webizen_qcdn_git_forge_{}_{}", std::process::id(), CNT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&dir).unwrap();
        let (q42_path, journal_path) = (dir.join("core.q42"), dir.join("journal.q42j"));

        let (code, ct, idx_bytes) = handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "GET", "/qcdn/root-index.cbor-ld", b"").unwrap().unwrap();
        assert_eq!((code, ct), (200, CBOR_LD_MEDIA_TYPE));
        assert_eq!(&idx_bytes[0..3], &CBOR_LD_HEADER);
        assert!(idx_bytes.len() < 10_240);

        let valid_body = format!("seeder_did=did:qi:alice_seeder&chunk_seq=0&chunk_data={}", std::str::from_utf8(DEFAULT_QCDN_CHUNK_0).unwrap());
        let (v_code, _, v_bytes) = handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "POST", "/qcdn/verify-chunk", valid_body.as_bytes()).unwrap().unwrap();
        assert_eq!((v_code, &v_bytes[0..3]), (200, &CBOR_LD_HEADER[..]));
        assert_eq!(handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "POST", "/qcdn/verify-chunk", b"seeder_did=did:qi:bad_peer&chunk_seq=0&chunk_data=tampered").unwrap().unwrap().0, 422);

        for _ in 0..2 {
            assert_eq!(handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "POST", "/qcdn/egress-check", b"response_bytes=40960&is_natural_person=false&is_root_index=false").unwrap().unwrap().0, 200);
        }
        let (trip_code, _, trip_body) = handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "POST", "/qcdn/egress-check", b"response_bytes=40960&is_natural_person=false&is_root_index=false").unwrap().unwrap();
        assert_eq!(trip_code, 307);
        assert!(String::from_utf8_lossy(&trip_body).contains("RedirectToQcdnSwarm"));
        assert_eq!(handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "POST", "/qcdn/egress-check", b"response_bytes=40960&is_natural_person=true&is_root_index=false").unwrap().unwrap().0, 200);
        assert_eq!(handle_qcdn_extended_route(&dir, &q42_path, &journal_path, "GET", "/qcdn/egress-check?response_bytes=4096&is_natural_person=false&is_root_index=true", b"").unwrap().unwrap().0, 200);

        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/open", b"title=Bad&diff=wc:NaturalAgent+rdfs:subClassOf+owl:Thing").unwrap().unwrap().0, 422);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/open", b"title=Add+Guardianship+Shape&author_did=did:qi:alice&diff=wc:NaturalAgent+a+rdfs:Class&required_quorum_m=2").unwrap().unwrap().0, 200);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/approve", b"pr_id=1&approver_did=did:qi:steward_1").unwrap().unwrap().0, 200);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/merge", b"pr_id=1").unwrap().unwrap().0, 403);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/approve", b"pr_id=1&approver_did=did:qi:steward_2").unwrap().unwrap().0, 200);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/pr/merge", b"pr_id=1").unwrap().unwrap().0, 200);
        assert_eq!(handle_git_forge_route(&dir, &journal_path, "POST", "/git/webcivics-ns/issues/open", b"title=Verify+Capacity+Rule&author_did=did:qi:bob&body=Check+SHACL+shape").unwrap().unwrap().0, 200);

        let (html_code, _, html_bytes) = handle_git_forge_route(&dir, &journal_path, "GET", "/git/webcivics-ns/prs", b"").unwrap().unwrap();
        let html = String::from_utf8(html_bytes).unwrap();
        assert_eq!(html_code, 200);
        assert!(html.contains("script-src 'none'") && html.contains("MERGED") && html.contains("Verify Capacity Rule"));
        let _ = fs::remove_dir_all(&dir);
    }
}
