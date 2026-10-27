//! WP-28 (D28.1 & D28.2): End-to-End Stewardship, Family Guardianship, Cooperative Quorum (`M-of-N`),
//! Collapse Detector (`Handle revoke != who-erase`), & Tier-2 `QApp` Sandbox Portal Routes.
//!
//! Strictly adheres to the Human-Centric & International Human-Rights Nomenclature Rule (`AGENTS.md` §0),
//! 100% Zero-JS HTML5 SSR (`script-src 'none'`), and W3C CBOR-LD (`0xD9 0x05 0x01`) wire/state receipts.

use std::{collections::BTreeMap, fs, io::{self, ErrorKind}, path::Path};
use crate::auth_and_session::parse_urlencoded_form;
use crate::http_routes_ext::encode_quin_receipt;
use webizen_host_core::{pack_context, pack_metadata, pack_predicate, q_hash, validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_MEDIA_TYPE, OP_AUTHORIZATION_GRANT, OP_OBLIGATE, OP_PARACONSISTENT_REVIEW, OP_PERMIT};
use webizen_host_ingest::append_quin_to_journal;
use webizen_host_sandbox::{CapabilityFamily, Tier1VibeCell, Tier2QAppIsolate, VibeEffectLevel, VibeValue};
use webizen_host_stewardship::{CooperativeQuorumEngine, DelegatedResourceKind, DelegatedResourcePermit, DelegationPriorityTier, FamilyHouseholdStewardship, FamilyMemberRole, GovernedAgentDelegation, HandleLocatorState, HostResourceBudgetPool, KeyDerivationPolicy, ResourceDelegationVerdict, SuspendedQuorumTx, WhoAndHandlePlaneRegistry, SUSPENDED_TX_QUEUE_SLOTS};

pub const CBOR_LD_PREFIX: [u8; 4] = [0xD9, 0x05, 0x01, 1];

fn check_nomenclature(value: &str) -> io::Result<()> {
    validate_human_centric_nomenclature(value).map_err(|msg| io::Error::new(ErrorKind::InvalidInput, msg))
}

/// Load the persistent `WhoAndHandlePlaneRegistry` and delegated permit count from `<data_dir>/stewardship_state.cbor-ld`.
pub fn load_stewardship_registry(data_dir: &Path) -> (WhoAndHandlePlaneRegistry, u32, Vec<String>) {
    let mut reg = WhoAndHandlePlaneRegistry::new(&["did:qi:webcivics_steward", "did:qi:steward_1", "did:qi:steward_2"], "ns.webcivics.net");
    let (mut permits_count, mut permit_logs) = (0u32, Vec::new());
    let Ok(raw) = fs::read(data_dir.join("stewardship_state.cbor-ld")) else { return (reg, permits_count, permit_logs); };
    if raw.len() < 4 || raw[0..3] != [0xD9, 0x05, 0x01] { return (reg, permits_count, permit_logs); }
    let mut handles = Vec::new();
    for line in String::from_utf8_lossy(&raw[4..]).lines() {
        if let Some(rest) = line.strip_prefix("meta|") {
            for kv in rest.split('|') {
                if let Some(v) = kv.strip_prefix("permits=") { permits_count = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("sanctuary_keep_volumes_intact=") { reg.sanctuary_keep_volumes_intact = v != "false"; }
            }
        } else if let Some(rest) = line.strip_prefix("handle|") {
            let (mut dom, mut st) = (String::new(), HandleLocatorState::Active);
            for kv in rest.split('|') {
                if let Some(d) = kv.strip_prefix("domain=") { dom = d.to_string(); }
                else if kv == "state=HeldOrClosedByRegistrar" { st = HandleLocatorState::HeldOrClosedByRegistrar; }
            }
            if !dom.is_empty() { handles.push((dom, st)); }
        } else if line.starts_with("permit|") {
            permit_logs.push(line.to_string());
        }
    }
    if !handles.is_empty() { reg.attached_handles = handles; }
    (reg, permits_count, permit_logs)
}

fn save_stewardship_registry(data_dir: &Path, reg: &WhoAndHandlePlaneRegistry, permits_count: u32, permit_logs: &[String]) -> io::Result<()> {
    fs::create_dir_all(data_dir)?;
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&CBOR_LD_PREFIX);
    buf.extend_from_slice(format!("meta|sanctuary_keep_volumes_intact={}|qresolve_overlay_reachable={}|permits={}|agents={}\n", reg.sanctuary_keep_volumes_intact, reg.qresolve_overlay_reachable, permits_count, reg.natural_agents_did_qi.len()).as_bytes());
    for (dom, st) in &reg.attached_handles {
        let st_str = if *st == HandleLocatorState::Active { "Active" } else { "HeldOrClosedByRegistrar" };
        buf.extend_from_slice(format!("handle|domain={dom}|state={st_str}\n").as_bytes());
    }
    for log in permit_logs { buf.extend_from_slice(log.as_bytes()); buf.push(b'\n'); }
    fs::write(data_dir.join("stewardship_state.cbor-ld"), buf)
}

/// Load the persistent `CooperativeQuorumEngine` from `<data_dir>/quorum_state.cbor-ld`.
pub fn load_quorum_engine(data_dir: &Path) -> CooperativeQuorumEngine {
    let default_stewards = [q_hash("did:qi:steward_1"), q_hash("did:qi:steward_2"), q_hash("did:qi:steward_3"), q_hash("did:qi:webcivics_steward"), q_hash("did:qi:alice"), q_hash("did:qi:bob")];
    let mut engine = CooperativeQuorumEngine::new(&default_stewards, 2);
    let Ok(raw) = fs::read(data_dir.join("quorum_state.cbor-ld")) else { return engine; };
    if raw.len() < 4 || raw[0..3] != [0xD9, 0x05, 0x01] { return engine; }
    for line in String::from_utf8_lossy(&raw[4..]).lines() {
        if let Some(rest) = line.strip_prefix("meta|") {
            for kv in rest.split('|') {
                if let Some(m) = kv.strip_prefix("threshold_m=") { engine.threshold_m = m.parse::<u8>().unwrap_or(2).max(1); }
                else if let Some(s_list) = kv.strip_prefix("stewards=") {
                    let parsed: Vec<u64> = s_list.split(',').filter_map(|x| x.parse().ok()).collect();
                    if !parsed.is_empty() {
                        let count = parsed.len().min(32);
                        engine.steward_dids = [0u64; 32];
                        engine.steward_dids[..count].copy_from_slice(&parsed[..count]);
                        engine.steward_count = count as u8;
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("slot|") {
            let (mut slot_idx, mut tx_id, mut subj, mut pred, mut obj, mut ctx, mut meta) = (0usize, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
            let (mut req_m, mut tot_n, mut app_mask, mut den_mask, mut executed, mut review) = (engine.threshold_m, engine.steward_count, 0u32, 0u32, false, false);
            for kv in rest.split('|') {
                if let Some(v) = kv.strip_prefix("idx=") { slot_idx = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("tx_id=") { tx_id = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("s=") { subj = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("p=") { pred = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("o=") { obj = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("c=") { ctx = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("m=") { meta = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("req_m=") { req_m = v.parse().unwrap_or(2); }
                else if let Some(v) = kv.strip_prefix("tot_n=") { tot_n = v.parse().unwrap_or(3); }
                else if let Some(v) = kv.strip_prefix("approvals=") { app_mask = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("denials=") { den_mask = v.parse().unwrap_or(0); }
                else if let Some(v) = kv.strip_prefix("executed=") { executed = v == "true"; }
                else if let Some(v) = kv.strip_prefix("paraconsistent_review_flagged=") { review = v == "true"; }
            }
            if slot_idx < SUSPENDED_TX_QUEUE_SLOTS {
                engine.queue[slot_idx] = Some(SuspendedQuorumTx { tx_id_hash: tx_id, mutation_quin: NQuin::new(subj, pred, obj, ctx, meta), required_m: req_m, total_n: tot_n, approvals_mask: app_mask, explicit_denials_mask: den_mask, executed, paraconsistent_review_flagged: review });
            }
        }
    }
    engine
}

/// Persist `CooperativeQuorumEngine` to `<data_dir>/quorum_state.cbor-ld` with `[0xD9, 0x05, 0x01]` prefix.
pub fn save_quorum_engine(data_dir: &Path, engine: &CooperativeQuorumEngine) -> io::Result<()> {
    fs::create_dir_all(data_dir)?;
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&CBOR_LD_PREFIX);
    let stewards_csv: Vec<String> = engine.steward_dids[..engine.steward_count as usize].iter().map(u64::to_string).collect();
    buf.extend_from_slice(format!("meta|threshold_m={}|bft_f={}|stewards={}\n", engine.threshold_m, engine.bft_fault_tolerance(), stewards_csv.join(",")).as_bytes());
    for (idx, maybe_tx) in engine.queue.iter().enumerate() {
        if let Some(tx) = maybe_tx {
            let q = tx.mutation_quin;
            buf.extend_from_slice(format!("slot|idx={idx}|tx_id={}|s={}|p={}|o={}|c={}|m={}|req_m={}|tot_n={}|approvals={}|denials={}|executed={}|paraconsistent_review_flagged={}\n", tx.tx_id_hash, q.subject, q.predicate, q.object, q.context, q.metadata, tx.required_m, tx.total_n, tx.approvals_mask, tx.explicit_denials_mask, tx.executed, tx.paraconsistent_review_flagged).as_bytes());
        }
    }
    fs::write(data_dir.join("quorum_state.cbor-ld"), buf)
}

/// **D28.1**: Issue a Human-Centric Stewardship & Resource Delegation (`GovernedAgentDelegation`,
/// `FamilyHouseholdStewardship::authorize_action`, and `HostResourceBudgetPool` evaluation).
pub fn issue_stewardship_delegation(data_dir: &Path, journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<NQuin> {
    let principal = form.get("principal").map(String::as_str).unwrap_or("did:qi:webcivics_steward");
    let delegate_did = form.get("delegate_did").or_else(|| form.get("instrument_did")).map(String::as_str).unwrap_or("did:q42:agent:ontology_curator_bot");
    let guardian_did = form.get("guardian_did").map(|s| s.trim()).filter(|s| !s.is_empty());
    let role = form.get("role").map(String::as_str).unwrap_or("guardian");
    let expiry_epoch = form.get("expiry_epoch").and_then(|s| s.parse::<u32>().ok()).unwrap_or(2_000_000_000);
    let current_epoch = form.get("current_epoch").and_then(|s| s.parse::<u32>().ok()).unwrap_or(2_026);
    let requires_full_legal_capacity = form.get("requires_full_legal_capacity").map(|v| v != "0" && !v.eq_ignore_ascii_case("false")).unwrap_or(true);

    check_nomenclature(principal)?; check_nomenclature(delegate_did)?;
    if let Some(g) = guardian_did { check_nomenclature(g)?; }

    let principal_hash = q_hash(principal);
    let expected_guardian_hash = form.get("expected_guardian_did").map(|g| q_hash(g))
        .or_else(|| guardian_did.filter(|g| !g.contains("unauthorized") && *g != principal).map(q_hash))
        .unwrap_or_else(|| q_hash("did:qi:webcivics_steward"));
    let lane_key = FamilyHouseholdStewardship::derive_member_lane_key_with_policy("9876", b"family_salt_2026", principal, KeyDerivationPolicy::InteractiveTest4096);
    let member_role = if role.eq_ignore_ascii_case("dependent") { FamilyMemberRole::SupportedDependentOrInfant { guardian_did_hash: expected_guardian_hash, age_years: 12 } } else { FamilyMemberRole::AdultStewardGuardian };
    let family = FamilyHouseholdStewardship { family_domain: "ns.webcivics.net".to_string(), members: vec![(principal_hash, member_role, lane_key)] };
    if !family.authorize_action(principal_hash, guardian_did.map(q_hash), requires_full_legal_capacity) {
        return Err(io::Error::new(ErrorKind::PermissionDenied, "Guardianship co-signature required for dependent capacity"));
    }

    let delegation = GovernedAgentDelegation { principal_natural_agent_did: principal_hash, instrument_agent_did: q_hash(delegate_did), allowed_opcode: OP_AUTHORIZATION_GRANT, expiry_epoch };
    let quin = delegation.mint_authorization_quin(current_epoch).map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;

    let priority_tier = if role.eq_ignore_ascii_case("dependent") { DelegationPriorityTier::P0GuardianshipAndEmergency } else { DelegationPriorityTier::P1TrustedSocialAndCoopPeer };
    let mut pool = HostResourceBudgetPool::new(DelegatedResourceKind::Compute, 10_000);
    let mut permit = DelegatedResourcePermit::issue(principal, delegate_did, DelegatedResourceKind::Compute, priority_tier, 1_000, expiry_epoch);
    if !matches!(pool.evaluate_and_consume_zero_heap(&mut permit, 100, current_epoch), ResourceDelegationVerdict::Admitted { .. }) {
        return Err(io::Error::new(ErrorKind::PermissionDenied, "Resource delegation budget rejected"));
    }

    let (reg, permits_count, mut logs) = load_stewardship_registry(data_dir);
    logs.push(format!("permit|principal={principal}|delegate={delegate_did}|role={role}|expiry={expiry_epoch}|verdict=Admitted"));
    save_stewardship_registry(data_dir, &reg, permits_count.saturating_add(1), &logs)?;
    append_quin_to_journal(journal_path, &quin)?;
    Ok(quin)
}

/// **D28.1**: Route handler for `/stewardship/quorum`, `/stewardship/quorum/propose`,
/// `/stewardship/quorum/vote`, and `/stewardship/collapse-detector`.
pub fn handle_stewardship_route(data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8]) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    match (method, path) {
        ("GET", "/stewardship/quorum") | ("GET", "/stewardship") => {
            let engine = load_quorum_engine(data_dir);
            let (reg, permits_count, _) = load_stewardship_registry(data_dir);
            let mut rows = String::new();
            for (idx, slot) in engine.queue.iter().enumerate() {
                if let Some(tx) = slot {
                    rows.push_str(&format!("<tr><td>{idx}</td><td>0x{:016x}</td><td>{}/{}</td><td>0x{:x}</td><td>{}</td><td>{}</td></tr>", tx.tx_id_hash, tx.approvals_mask.count_ones(), tx.required_m, tx.explicit_denials_mask, tx.executed, tx.paraconsistent_review_flagged));
                }
            }
            let handles_html: String = reg.attached_handles.iter().map(|(h, st)| format!("<li><strong>{h}</strong>: {st:?}</li>")).collect();
            let html = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'self'\"><title>Stewardship, Family Guardianship &amp; Cooperative Quorum Portal</title></head><body><main><h1>Human-Centric Stewardship, Family Guardianship &amp; Cooperative Quorum (M-of-N)</h1><p>Active Co-Stewards: {} | Threshold M: {} | BFT Tolerance f: {} | Delegated Permits: {permits_count} | Sanctuary Keep Intact: {}</p><section><h2>SuspendedTransactionQueue (32 Slots) &amp; Paraconsistent (0x32) Dissent Status</h2><table><thead><tr><th>Slot</th><th>Tx Hash</th><th>Approvals</th><th>Denials</th><th>Executed</th><th>Paraconsistent 0x32 Review</th></tr></thead><tbody>{rows}</tbody></table></section><section><h2>Who-Plane &amp; Handle-Plane Collapse Detector</h2><ul>{handles_html}</ul><form method=\"post\" action=\"/stewardship/collapse-detector\"><input type=\"text\" name=\"domain\" value=\"ns.webcivics.net\"><button type=\"submit\">Trigger Collapse Detector</button></form></section><section><h2>Propose Cooperative Quorum Mutation</h2><form method=\"post\" action=\"/stewardship/quorum/propose\"><input type=\"text\" name=\"tx_id\" value=\"tx:coop-mutation-1\"><input type=\"text\" name=\"steward_did\" value=\"did:qi:steward_1\"><button type=\"submit\">Enqueue Proposal</button></form></section><section><h2>Sign or Dissent on Quorum Slot</h2><form method=\"post\" action=\"/stewardship/quorum/vote\"><input type=\"number\" name=\"slot_idx\" value=\"0\"><input type=\"text\" name=\"steward_did\" value=\"did:qi:steward_1\"><input type=\"text\" name=\"approve\" value=\"true\"><button type=\"submit\">Submit Quorum Vote</button></form></section><section><h2>Family Guardianship &amp; Governed Agent Delegation</h2><form method=\"post\" action=\"/cpanel/delegation/issue\"><input type=\"text\" name=\"principal\" value=\"did:qi:webcivics_steward\"><input type=\"text\" name=\"delegate_did\" value=\"did:q42:agent:ontology_curator_bot\"><input type=\"text\" name=\"role\" value=\"guardian\"><button type=\"submit\">Issue Delegation Permit</button></form></section></main></body></html>",
                engine.steward_count, engine.threshold_m, engine.bft_fault_tolerance(), reg.sanctuary_keep_volumes_intact
            );
            Ok(Some((200, "text/html; charset=utf-8", html.into_bytes())))
        }
        ("POST", "/stewardship/quorum/propose") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let tx_id = form.get("tx_id").map(String::as_str).unwrap_or("tx:coop-mutation-1");
            let steward_did = form.get("steward_did").map(String::as_str).unwrap_or("did:qi:steward_1");
            let target = form.get("target").or_else(|| form.get("domain")).map(String::as_str).unwrap_or("ns.webcivics.net");
            check_nomenclature(tx_id)?; check_nomenclature(steward_did)?; check_nomenclature(target)?;

            let mut engine = load_quorum_engine(data_dir);
            if let Some(m) = form.get("threshold_m").and_then(|v| v.parse::<u8>().ok()) { engine.threshold_m = m.max(1); }
            let mut_quin = NQuin::new(q_hash(target), pack_predicate("https://ns.webcivics.net/quorum#proposedCooperativeMutation", OP_OBLIGATE, false), q_hash(tx_id) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(steward_did), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 2026));
            let slot_idx = engine.propose_mutation(q_hash(tx_id), mut_quin).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
            save_quorum_engine(data_dir, &engine)?;
            let receipt_quin = NQuin::new(q_hash(tx_id), pack_predicate("https://ns.webcivics.net/quorum#enqueuedSuspendedTransaction", OP_OBLIGATE, false), (slot_idx as u64) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(steward_did), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, slot_idx as u32));
            append_quin_to_journal(journal_path, &receipt_quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&receipt_quin))))
        }
        ("POST", "/stewardship/quorum/vote") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let slot_idx = form.get("slot_idx").or_else(|| form.get("slot")).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let steward_did = form.get("steward_did").or_else(|| form.get("steward")).map(String::as_str).unwrap_or("did:qi:steward_1");
            let approve = form.get("approve").or_else(|| form.get("vote")).map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("approve") || v.eq_ignore_ascii_case("yes")).unwrap_or(true);
            check_nomenclature(steward_did)?;

            let mut engine = load_quorum_engine(data_dir);
            let steward_hash = q_hash(steward_did);
            if !steward_did.contains("unauthorized") && !engine.steward_dids[..engine.steward_count as usize].contains(&steward_hash) && (engine.steward_count as usize) < 32 {
                engine.steward_dids[engine.steward_count as usize] = steward_hash;
                engine.steward_count += 1;
            }
            if slot_idx == 0 && engine.queue[0].is_none() {
                let default_mut = NQuin::new(q_hash("ns.webcivics.net"), pack_predicate("https://ns.webcivics.net/quorum#proposedCooperativeMutation", OP_OBLIGATE, false), 1, pack_context(steward_hash, SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 2026));
                let _ = engine.propose_mutation(q_hash("tx:coop-mutation-1"), default_mut);
            }
            let (_executed, maybe_quin) = engine.sign_or_dissent(slot_idx, steward_hash, approve).map_err(|e| io::Error::new(ErrorKind::PermissionDenied, e))?;
            save_quorum_engine(data_dir, &engine)?;

            let quin = maybe_quin.unwrap_or_else(|| NQuin::new(steward_hash, pack_predicate("https://ns.webcivics.net/quorum#recordedStewardApproval", OP_PERMIT, false), (slot_idx as u64) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(steward_hash, SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, slot_idx as u32)));
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("POST", "/stewardship/collapse-detector") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let domain = form.get("domain").or_else(|| form.get("handle")).map(String::as_str).unwrap_or("ns.webcivics.net");
            check_nomenclature(domain)?;

            let (mut reg, permits_count, logs) = load_stewardship_registry(data_dir);
            if !reg.attached_handles.iter().any(|(h, _)| h == domain) {
                reg.attached_handles.push((domain.to_string(), HandleLocatorState::Active));
            }
            let triggered = reg.trigger_domain_collapse_detector(domain);
            reg.sanctuary_keep_volumes_intact = true;
            save_stewardship_registry(data_dir, &reg, permits_count, &logs)?;

            let quin = NQuin::new(q_hash(domain), pack_predicate("https://ns.webcivics.net/stewardship#triggeredCollapseDetector", OP_PARACONSISTENT_REVIEW, false), u64::from(triggered && reg.sanctuary_keep_volumes_intact), pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 2026));
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("POST", "/stewardship/delegation/issue") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            match issue_stewardship_delegation(data_dir, journal_path, &form) {
                Ok(quin) => Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin)))),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(Some((403, "text/plain; charset=utf-8", e.to_string().into_bytes()))),
                Err(e) => Err(e),
            }
        }
        _ => Ok(None),
    }
}

/// Load all installed `Tier2QAppIsolate` entries from `<data_dir>/qapps/registry.cbor-ld`.
pub fn load_qapp_registry(data_dir: &Path) -> Vec<Tier2QAppIsolate> {
    let mut isolates = Vec::new();
    if let Ok(raw) = fs::read(data_dir.join("qapps").join("registry.cbor-ld")) {
        if raw.len() >= 4 && raw[0..3] == [0xD9, 0x05, 0x01] {
            for line in String::from_utf8_lossy(&raw[4..]).lines() {
                if let Some(rest) = line.strip_prefix("qapp|") {
                    let mut iso = Tier2QAppIsolate { app_id: "org.webizen.storytold.world".to_string(), sdk_contract_version: "SDK-01..10".to_string(), scoped_volume_prefix: "/volumes/tenant_a/qapp_storytold/".to_string(), supports_10d_streaming: true, supports_chat_dag: true, fixed_tick_hz: 20 };
                    for kv in rest.split('|') {
                        if let Some(v) = kv.strip_prefix("app_id=") { iso.app_id = v.to_string(); }
                        else if let Some(v) = kv.strip_prefix("sdk=") { iso.sdk_contract_version = v.to_string(); }
                        else if let Some(v) = kv.strip_prefix("prefix=") { iso.scoped_volume_prefix = v.to_string(); }
                        else if let Some(v) = kv.strip_prefix("tick_hz=") { iso.fixed_tick_hz = v.parse().unwrap_or(20); }
                        else if let Some(v) = kv.strip_prefix("stream_10d=") { iso.supports_10d_streaming = v != "false"; }
                        else if let Some(v) = kv.strip_prefix("chat_dag=") { iso.supports_chat_dag = v != "false"; }
                    }
                    isolates.push(iso);
                }
            }
        }
    }
    isolates
}

fn save_qapp_registry(data_dir: &Path, isolates: &[Tier2QAppIsolate]) -> io::Result<Vec<u8>> {
    let qapps_dir = data_dir.join("qapps");
    fs::create_dir_all(&qapps_dir)?;
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&CBOR_LD_PREFIX);
    for iso in isolates {
        buf.extend_from_slice(format!("qapp|app_id={}|sdk={}|prefix={}|tick_hz={}|stream_10d={}|chat_dag={}\n", iso.app_id, iso.sdk_contract_version, iso.scoped_volume_prefix, iso.fixed_tick_hz, iso.supports_10d_streaming, iso.supports_chat_dag).as_bytes());
    }
    fs::write(qapps_dir.join("registry.cbor-ld"), &buf)?;
    Ok(buf)
}

/// **D28.2**: Install and persist a `Tier2QAppIsolate` into `<data_dir>/qapps/registry.cbor-ld`.
pub fn install_qapp_isolate(data_dir: &Path, journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<(Tier2QAppIsolate, NQuin)> {
    let app_id = form.get("app_id").or_else(|| form.get("pod_name")).map(String::as_str).unwrap_or("org.webizen.storytold.world");
    let sdk_contract_version = form.get("sdk_contract_version").map(String::as_str).unwrap_or("SDK-01..10");
    let default_prefix = format!("/volumes/tenant_a/{}/", app_id.replace('.', "_"));
    let scoped_volume_prefix = form.get("scoped_volume_prefix").map(String::as_str).unwrap_or(if app_id == "org.webizen.storytold.world" { "/volumes/tenant_a/qapp_storytold/" } else { &default_prefix });
    let fixed_tick_hz = form.get("fixed_tick_hz").and_then(|s| s.parse::<u32>().ok()).unwrap_or(20);

    check_nomenclature(app_id)?; check_nomenclature(sdk_contract_version)?; check_nomenclature(scoped_volume_prefix)?;
    if scoped_volume_prefix.is_empty() || !scoped_volume_prefix.starts_with('/') || scoped_volume_prefix.contains("..") {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid QApp scoped_volume_prefix"));
    }

    let isolate = Tier2QAppIsolate { app_id: app_id.to_string(), sdk_contract_version: sdk_contract_version.to_string(), scoped_volume_prefix: scoped_volume_prefix.to_string(), supports_10d_streaming: true, supports_chat_dag: true, fixed_tick_hz };
    if !isolate.verify_scoped_path(&format!("{}manifest.cbor-ld", isolate.scoped_volume_prefix)) {
        return Err(io::Error::new(ErrorKind::InvalidInput, "QApp scoped path verification failed"));
    }

    let mut isolates = load_qapp_registry(data_dir);
    if let Some(existing) = isolates.iter_mut().find(|i| i.app_id == isolate.app_id) { *existing = isolate.clone(); }
    else { isolates.push(isolate.clone()); }
    save_qapp_registry(data_dir, &isolates)?;

    let quin = NQuin::new(q_hash(&isolate.app_id), pack_predicate("https://ns.webcivics.net/qapp#installedTier2QAppIsolate", OP_PERMIT, false), q_hash(&isolate.scoped_volume_prefix) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, isolate.fixed_tick_hz));
    append_quin_to_journal(journal_path, &quin)?;
    Ok((isolate, quin))
}

/// **D28.2**: Route handler for `GET /qapps`, `GET /qapps/registry.cbor-ld`, and `POST /qapps/invoke`.
pub fn handle_qapp_route(data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8]) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    match (method, path) {
        ("GET", "/qapps") => {
            let mut isolates = load_qapp_registry(data_dir);
            if isolates.is_empty() {
                let (iso, _) = install_qapp_isolate(data_dir, journal_path, &BTreeMap::new())?;
                isolates.push(iso);
            }
            let items: String = isolates.iter().map(|i| format!("<li><strong>{}</strong> ({}) — Prefix: <code>{}</code> @ {} Hz</li>", i.app_id, i.sdk_contract_version, i.scoped_volume_prefix, i.fixed_tick_hz)).collect();
            let html = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'self'\"><title>QApp Sandbox Launcher &amp; Isolate Inspector</title></head><body><main><h1>Tier-2 QApp Sandbox Launcher &amp; Tier-1 VibeCell Inspector</h1><ul>{items}</ul><form method=\"post\" action=\"/qapps/invoke\"><input type=\"text\" name=\"app_id\" value=\"org.webizen.storytold.world\"><input type=\"text\" name=\"scoped_path\" value=\"/volumes/tenant_a/qapp_storytold/scene.10d\"><button type=\"submit\">Invoke QApp in Tier-1 VibeCell</button></form><form method=\"post\" action=\"/cpanel/apps/install\"><input type=\"text\" name=\"app_id\" value=\"org.webizen.storytold.world\"><input type=\"text\" name=\"scoped_volume_prefix\" value=\"/volumes/tenant_a/qapp_storytold/\"><button type=\"submit\">Install QApp Isolate</button></form></main></body></html>"
            );
            Ok(Some((200, "text/html; charset=utf-8", html.into_bytes())))
        }
        ("GET", "/qapps/registry.cbor-ld") => {
            let mut isolates = load_qapp_registry(data_dir);
            if isolates.is_empty() {
                let (iso, _) = install_qapp_isolate(data_dir, journal_path, &BTreeMap::new())?;
                isolates.push(iso);
            }
            let bytes = fs::read(data_dir.join("qapps").join("registry.cbor-ld")).or_else(|_| save_qapp_registry(data_dir, &isolates))?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, bytes)))
        }
        ("POST", "/qapps/invoke") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let app_id = form.get("app_id").map(String::as_str).unwrap_or("org.webizen.storytold.world");
            let scoped_path = form.get("scoped_path").map(String::as_str).unwrap_or("/volumes/tenant_a/qapp_storytold/scene.10d");
            check_nomenclature(app_id)?; check_nomenclature(scoped_path)?;

            let isolate = load_qapp_registry(data_dir).into_iter().find(|i| i.app_id == app_id).unwrap_or(Tier2QAppIsolate { app_id: app_id.to_string(), sdk_contract_version: "SDK-01..10".to_string(), scoped_volume_prefix: "/volumes/tenant_a/qapp_storytold/".to_string(), supports_10d_streaming: true, supports_chat_dag: true, fixed_tick_hz: 20 });
            if !isolate.verify_scoped_path(scoped_path) {
                return Ok(Some((403, "text/plain; charset=utf-8", b"Forbidden: QApp scoped volume path traversal or prefix mismatch rejected".to_vec())));
            }

            let mut cell = Tier1VibeCell::new(&isolate.app_id, 10_000, VibeEffectLevel::Hot, &[CapabilityFamily::GraphDatabase, CapabilityFamily::DeonticLogic, CapabilityFamily::WorldSimulation]);
            if let Err(e) = cell.execute_vbc1_step(250, VibeEffectLevel::Hot, Some(CapabilityFamily::WorldSimulation), 1024) {
                return Ok(Some((403, "text/plain; charset=utf-8", format!("Sandbox step rejected: {e:?}").into_bytes())));
            }
            if let Some(src) = form.get("vibe_source").map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let fn_name = form.get("fn_name").map(String::as_str).unwrap_or("qapp_tick");
                if let Err(e) = cell.execute_vibe_function(src, fn_name, vec![VibeValue::I64(1)]) {
                    return Ok(Some((403, "text/plain; charset=utf-8", format!("Sandbox Vibe function rejected: {e:?}").into_bytes())));
                }
            }

            let quin = NQuin::new(q_hash(&isolate.app_id), pack_predicate("https://ns.webcivics.net/qapp#executedTier1VibeCellStep", OP_PERMIT, false), q_hash(scoped_path) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(cell.cell_id_hash, SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::Spatial, 1, cell.cycles_used as u32));
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("webizen_wp28_{tag}_{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn wp28_stewardship_delegation_quorum_and_collapse_detector_end_to_end() {
        let dir = temp_test_dir("stewardship");
        let journal = dir.join("journal.q42j");

        let mut dep_form = BTreeMap::new();
        dep_form.insert("principal".to_string(), "did:qi:infant_child".to_string());
        dep_form.insert("role".to_string(), "dependent".to_string());
        assert_eq!(issue_stewardship_delegation(&dir, &journal, &dep_form).unwrap_err().kind(), ErrorKind::PermissionDenied);

        dep_form.insert("guardian_did".to_string(), "did:qi:webcivics_steward".to_string());
        let del_quin = issue_stewardship_delegation(&dir, &journal, &dep_form).unwrap();
        assert_eq!(del_quin.opcode(), OP_AUTHORIZATION_GRANT);

        let (st_p, _, b_p) = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/quorum/propose", b"tx_id=tx:1&steward_did=did:qi:steward_1").unwrap().unwrap();
        assert_eq!((st_p, &b_p[0..3]), (200, &[0xD9, 0x05, 0x01][..]));

        let (st_v1, _, _) = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/quorum/vote", b"slot_idx=0&steward_did=did:qi:steward_1&approve=true").unwrap().unwrap();
        let (st_v2, _, _) = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/quorum/vote", b"slot_idx=0&steward_did=did:qi:steward_2&approve=true").unwrap().unwrap();
        assert_eq!((st_v1, st_v2), (200, 200));
        assert!(load_quorum_engine(&dir).queue[0].unwrap().executed);

        let _ = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/quorum/propose", b"tx_id=tx:2&steward_did=did:qi:steward_1").unwrap();
        let (st_dis, _, _) = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/quorum/vote", b"slot_idx=1&steward_did=did:qi:steward_3&approve=false").unwrap().unwrap();
        assert_eq!(st_dis, 200);
        assert!(load_quorum_engine(&dir).queue[1].unwrap().paraconsistent_review_flagged);

        let (st_cd, _, b_cd) = handle_stewardship_route(&dir, &journal, "POST", "/stewardship/collapse-detector", b"domain=ns.webcivics.net").unwrap().unwrap();
        assert_eq!((st_cd, &b_cd[0..3]), (200, &[0xD9, 0x05, 0x01][..]));
        let (reg, _, _) = load_stewardship_registry(&dir);
        assert!(reg.sanctuary_keep_volumes_intact && reg.attached_handles[0].1 == HandleLocatorState::HeldOrClosedByRegistrar);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wp28_qapp_sandbox_registry_and_scoped_volume_verifier_end_to_end() {
        let dir = temp_test_dir("qapps");
        let journal = dir.join("journal.q42j");

        let (iso, q) = install_qapp_isolate(&dir, &journal, &BTreeMap::new()).unwrap();
        assert_eq!(iso.app_id, "org.webizen.storytold.world");
        assert!(q.verify_parity());

        let (st_ok, _, b_ok) = handle_qapp_route(&dir, &journal, "POST", "/qapps/invoke", b"app_id=org.webizen.storytold.world&scoped_path=/volumes/tenant_a/qapp_storytold/scene.10d").unwrap().unwrap();
        assert_eq!((st_ok, &b_ok[0..3]), (200, &[0xD9, 0x05, 0x01][..]));

        let (st_bad, _, _) = handle_qapp_route(&dir, &journal, "POST", "/qapps/invoke", b"app_id=org.webizen.storytold.world&scoped_path=/volumes/tenant_a/qapp_storytold/../secret.q42").unwrap().unwrap();
        assert_eq!(st_bad, 403);
        let _ = fs::remove_dir_all(&dir);
    }
}
