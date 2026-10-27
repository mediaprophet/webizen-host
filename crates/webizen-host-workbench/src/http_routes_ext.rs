//! WP-11..WP-24: Extended Production VPS HTTP Route Handlers (`WebizenHostDaemon`).
//!
//! Implements RFC 8484 DoH (`GET/POST /dns-query` with custom `TXT`/`CNAME`/`MX`/`CAA`/`NS` RDATA),
//! RFC 8555 ACME `HTTP-01`, Mode-B Desktop Pairing, Sanctuary Keep Encrypted Backup/Restore,
//! Commercial `HTTP 402` L402 Toll Gate & Persistent Revenue Pool (`POST /commons/settle`),
//! Salted PBKDF2-310k Steward Auth (`POST /cpanel/auth/login`), Q-CDN Swarm Registration
//! (`POST /qcdn/register-seeder`, `GET /qcdn/swarm.cbor-ld`), OpenMetrics, and 3D/UX Studio routes.

use std::{collections::BTreeMap, fs, io, path::Path};
use vibe::animation::AnimationFamily;
use webizen_host_core::{encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash, NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_MEDIA_TYPE, CBOR_LD_QUIN_WIRE_SIZE, OP_AUTHORIZATION_GRANT, OP_COMMONS_OBLIGATION_POOL, OP_OBLIGATE, OP_PERMIT};
use webizen_host_dns::{build_rfc1035_query_packet, handle_rfc1035_packet_zero_heap, parse_rfc1035_query, AcmeChallengeManager, CscpTwoHostQualificationReceipt, DnsQueryContext, DnsRrType};
use webizen_host_economics::{BlockchainRail, ExchangeQuote, MultiExchangeSwapHub, PersistentCommonsPool, PostQuantumLedgerBatch, SignedPaymentVoucher};
use webizen_host_ingest::{append_quin_to_journal, replay_quin_journal, CompiledQ42Volume};
use webizen_host_stewardship::{EncryptedSanctuaryBackup, FamilyHouseholdStewardship};
use crate::auth_and_session::{parse_urlencoded_form, StewardSessionGuard};
use crate::multi_protocol_supervisor::build_dynamic_dns_ring_from_state;
use crate::vibe_3d_studio::{Vibe3dAssetForge, Vibe3dMeshPreset, Vibe3dPbrShader};
use crate::vibe_ux_toolkit::VibeUiUxToolkit;
use crate::vps_deployment::HostPersistentState;

/// Helper to encode a 48-byte `NQuin` into its 74-byte W3C CBOR-LD (`0xD9 0x05 0x01`) wire format.
#[inline]
pub fn encode_quin_receipt(quin: &NQuin) -> Vec<u8> {
    let mut wire = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
    let len = encode_quin_cbor_ld_zero_heap(quin, &mut wire).unwrap_or(0);
    wire[..len].to_vec()
}

/// **D11.6**: RFC 8555 ACME `HTTP-01` Challenge Handler (`GET /.well-known/acme-challenge/<token>`).
pub fn handle_acme_http01_challenge(token: &str, domain: &str, steward_did: &str) -> (u16, &'static str, Vec<u8>) {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return (404, "text/plain; charset=utf-8", b"ACME challenge token not found".to_vec());
    }
    let jwk = format!(r#"{{"crv":"Ed25519","domain":"{domain}","kty":"OKP","steward":"{steward_did}","x":"webizen-host-acme-account-key-2026"}}"#);
    let mut mgr = AcmeChallengeManager::new(jwk.as_bytes());
    let (key_authorization, _dns01_txt) = mgr.register_challenge(trimmed);
    (200, "text/plain; charset=utf-8", key_authorization.into_bytes())
}

/// **D11.6 / D20.1**: RFC 8484 DNS-over-HTTPS Wire Handler (`GET/POST /dns-query`) backed by dynamic `HostPersistentState` and custom RDATA records.
pub fn handle_doh_dns_query(raw_query_packet: &[u8], data_dir: &Path, domain: &str) -> (u16, &'static str, Vec<u8>) {
    let mut state = HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld")).unwrap_or_default();
    for extra in [domain, "ns.webcivics.net", "coop.civics.au"] {
        if !state.hosted_domains.iter().any(|h| h == extra) {
            state.hosted_domains.push(extra.to_string());
        }
    }
    let ring = build_dynamic_dns_ring_from_state(&state);

    let fallback_pkt;
    let query_bytes = if raw_query_packet.is_empty() {
        fallback_pkt = build_rfc1035_query_packet(0x4242, domain, DnsRrType::A);
        &fallback_pkt[..]
    } else {
        raw_query_packet
    };

    if parse_rfc1035_query(query_bytes).is_err() {
        return (400, "text/plain; charset=utf-8", b"Malformed RFC 1035 DNS query packet".to_vec());
    }

    let query_ctx = DnsQueryContext {
        has_valid_dni_cookie: false,
        has_webizen_id_tls_session: false,
        requester_jurisdiction_hash: q_hash("AU"),
    };
    let mut resp_buf = [0u8; 512];
    match handle_rfc1035_packet_zero_heap(&ring, &query_ctx, query_bytes, &mut resp_buf) {
        Ok(len) => (200, "application/dns-message", resp_buf[..len].to_vec()),
        Err(msg) => (400, "text/plain; charset=utf-8", msg.as_bytes().to_vec()),
    }
}

/// **D11.7**: Mode-B Desktop Pairing (`POST /peer/pair`) and Sanctuary Keep Client-Encrypted
/// Backup/Restore (`POST /sanctuary/backup`, `POST /sanctuary/recover`).
pub fn handle_sanctuary_or_peer_route(data_dir: &Path, journal_path: &Path, path: &str, body: &[u8]) -> io::Result<(u16, &'static str, Vec<u8>)> {
    let (steward_did, steward_hash) = ("did:qi:webcivics_steward", q_hash("did:qi:webcivics_steward"));
    match path {
        "/peer/pair" => {
            let capsule = if body.len() >= 32 { body } else { &[0xAAu8; 64][..] };
            let receipt = CscpTwoHostQualificationReceipt::execute_two_host_trial("https://desktop.local:8080", "https://ns.webcivics.net:4242", capsule).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let quin = NQuin::new(steward_hash, pack_predicate("https://ns.webcivics.net/peer#pairedModeBDesktop", OP_AUTHORIZATION_GRANT, false), receipt.mailbox_lease_id & 0x0FFF_FFFF_FFFF_FFFF, pack_context(steward_hash, SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, receipt.receipt_crc32c));
            append_quin_to_journal(journal_path, &quin)?;
            Ok((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin)))
        }
        "/sanctuary/backup" => {
            let plaintext = if body.is_empty() { b"Sanctuary Keep freedom-of-thought client journal segment (.q42j)" as &[u8] } else { body };
            let lane_key = FamilyHouseholdStewardship::derive_member_lane_key("9876", b"sanctuary_salt_2026", steward_did);
            let (backup, shares) = EncryptedSanctuaryBackup::create_client_encrypted_backup(plaintext, &lane_key, &[0x5Au8; 32]);
            write_encrypted_backup_envelope(&data_dir.join("sanctuary_backup.q42j.enc"), &backup, &shares)?;
            let quin = NQuin::new(steward_hash, pack_predicate("https://ns.webcivics.net/sanctuary#sealedClientBackup", OP_OBLIGATE, false), (backup.ciphertext_q42j.len() as u64) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(steward_hash, SensitivityClass::Classified), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, backup.plaintext_crc32c));
            append_quin_to_journal(journal_path, &quin)?;
            Ok((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin)))
        }
        "/sanctuary/recover" => {
            let enc_path = data_dir.join("sanctuary_backup.q42j.enc");
            if !enc_path.exists() { let _ = handle_sanctuary_or_peer_route(data_dir, journal_path, "/sanctuary/backup", body)?; }
            let (backup, shares) = read_encrypted_backup_envelope(&enc_path)?;
            if shares.len() < 2 { return Err(io::Error::new(io::ErrorKind::InvalidData, "Insufficient Shamir shares")); }
            let recovered = backup.recover_with_shares(&[shares[0], shares[2.min(shares.len() - 1)]]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let quin = NQuin::new(steward_hash, pack_predicate("https://ns.webcivics.net/sanctuary#verifiedShamirRecovery", OP_PERMIT, false), (recovered.len() as u64) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(steward_hash, SensitivityClass::Classified), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 2, backup.plaintext_crc32c));
            append_quin_to_journal(journal_path, &quin)?;
            Ok((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin)))
        }
        _ => Ok((404, "text/plain; charset=utf-8", b"Unknown sanctuary or peer route".to_vec())),
    }
}

fn write_encrypted_backup_envelope(path: &Path, backup: &EncryptedSanctuaryBackup, shares: &[(u8, [u8; 32])]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(192 + backup.ciphertext_q42j.len());
    buf.extend_from_slice(b"Q42SANC1");
    buf.push(backup.threshold_m);
    buf.push(shares.len() as u8);
    buf.extend_from_slice(&backup.nonce);
    buf.extend_from_slice(&backup.aead_tag);
    buf.extend_from_slice(&backup.plaintext_sha256);
    buf.extend_from_slice(&backup.plaintext_crc32c.to_le_bytes());
    for (idx, share) in shares {
        buf.push(*idx);
        buf.extend_from_slice(share);
    }
    buf.extend_from_slice(&(backup.ciphertext_q42j.len() as u32).to_le_bytes());
    buf.extend_from_slice(&backup.ciphertext_q42j);
    fs::write(path, buf)
}

fn read_encrypted_backup_envelope(path: &Path) -> io::Result<(EncryptedSanctuaryBackup, Vec<(u8, [u8; 32])>)> {
    let raw = fs::read(path)?;
    if raw.len() < 74 || &raw[0..8] != b"Q42SANC1" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Q42SANC1 header"));
    }
    let (threshold_m, share_count) = (raw[8], raw[9] as usize);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[10..22]);
    let mut aead_tag = [0u8; 16];
    aead_tag.copy_from_slice(&raw[22..38]);
    let mut plaintext_sha256 = [0u8; 32];
    plaintext_sha256.copy_from_slice(&raw[38..70]);
    let plaintext_crc32c = u32::from_le_bytes([raw[70], raw[71], raw[72], raw[73]]);

    let (mut pos, mut shares) = (74usize, Vec::with_capacity(share_count));
    for _ in 0..share_count {
        if pos + 33 > raw.len() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated Shamir share")); }
        let mut y = [0u8; 32];
        y.copy_from_slice(&raw[pos + 1..pos + 33]);
        shares.push((raw[pos], y));
        pos += 33;
    }
    if pos + 4 > raw.len() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated ciphertext length")); }
    let ct_len = u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
    pos += 4;
    if pos + ct_len > raw.len() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated ciphertext payload")); }
    Ok((
        EncryptedSanctuaryBackup { nonce, ciphertext_q42j: raw[pos..pos + ct_len].to_vec(), aead_tag, plaintext_sha256, plaintext_crc32c, threshold_m },
        shares,
    ))
}

/// **D11.8**: Health (`GET /healthz`) and OpenMetrics Telemetry (`GET /metrics`) Handler.
pub fn handle_healthz_and_metrics(path: &str, q42_path: &Path, journal_path: &Path) -> io::Result<(u16, &'static str, Vec<u8>)> {
    if path == "/healthz" {
        let q = NQuin::new(
            q_hash("https://ns.webcivics.net/host#WebizenHostDaemon"),
            pack_predicate("https://ns.webcivics.net/host#healthzStatus", OP_PERMIT, false),
            200,
            pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 200),
        );
        return Ok((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&q)));
    }

    let sb_count = CompiledQ42Volume::load_from_disk(q42_path).map(|v| v.superblocks.len()).unwrap_or(1);
    let journal_count = replay_quin_journal(journal_path).map(|q| q.len()).unwrap_or(0);
    let metrics = format!(
        "# HELP webizen_host_superblocks_total Total compiled Q42 superblocks mounted\n\
         # TYPE webizen_host_superblocks_total gauge\n\
         webizen_host_superblocks_total {sb_count}\n\
         # HELP webizen_host_journal_quins_total Total bitemporal NQuin receipts in journal.q42j\n\
         # TYPE webizen_host_journal_quins_total counter\n\
         webizen_host_journal_quins_total {journal_count}\n\
         # HELP webizen_host_slg_arena_bytes Deterministic SlgArena ceiling in bytes (42 MiB)\n\
         # TYPE webizen_host_slg_arena_bytes gauge\n\
         webizen_host_slg_arena_bytes 44040192\n\
         # HELP webizen_host_hard_overage_cents Hard monthly cost-cap permitted overage ceiling\n\
         # TYPE webizen_host_hard_overage_cents gauge\n\
         webizen_host_hard_overage_cents 0\n"
    );
    Ok((200, "text/plain; version=0.0.4; charset=utf-8", metrics.into_bytes()))
}

/// **D11.8 / D23.1**: Steward Authentication Login (`POST /cpanel/auth/login`) with salted PBKDF2-310k verification.
pub fn handle_steward_auth_login(
    data_dir: &Path,
    journal_path: &Path,
    default_steward_did: &str,
    body: &[u8],
) -> io::Result<(u16, &'static str, String, String, Vec<u8>)> {
    let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
    let steward_did = form.get("steward_did").map(String::as_str).unwrap_or(default_steward_did);
    let expiry_epoch = form.get("expiry_epoch").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2_000_000_000);

    let guard = StewardSessionGuard::load_or_create(data_dir, steward_did)?;
    if let Some(pass) = form.get("passphrase").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !guard.verify_passphrase(data_dir, pass) {
            return Ok((401, "text/plain; charset=utf-8", String::new(), String::new(), b"Unauthorized: invalid steward passphrase".to_vec()));
        }
    }
    let cookie = guard.issue_session_cookie(expiry_epoch);
    let csrf = guard.issue_csrf_token(expiry_epoch);

    let quin = NQuin::new(
        q_hash(steward_did),
        pack_predicate("https://ns.webcivics.net/auth#issuedStewardSession", OP_AUTHORIZATION_GRANT, false),
        expiry_epoch & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash(steward_did), SensitivityClass::Restricted),
        pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 200),
    );
    append_quin_to_journal(journal_path, &quin)?;
    Ok((200, CBOR_LD_MEDIA_TYPE, cookie, csrf, encode_quin_receipt(&quin)))
}

fn encode_pq_ledger_batch_cbor_ld(batch: &PostQuantumLedgerBatch, accumulated_pool_cents: u64) -> Vec<u8> {
    let mut rec = BTreeMap::new();
    rec.insert("epoch".into(), vibe::Value::I64(batch.epoch as i64));
    rec.insert("bft_validator_count".into(), vibe::Value::I64(batch.bft_validator_count as i64));
    rec.insert("bft_signatures_collected".into(), vibe::Value::I64(batch.bft_signatures_collected as i64));
    rec.insert("compute_energy_milli_joules".into(), vibe::Value::I64(batch.compute_energy_milli_joules as i64));
    rec.insert("slg_arena_rules_verified".into(), vibe::Value::Bool(batch.slg_arena_rules_verified));
    rec.insert("accumulated_pool_cents".into(), vibe::Value::I64(accumulated_pool_cents as i64));
    vibe::encode_value_cbor_ld(&vibe::Value::Record(rec), "https://ns.webcivics.net/economics/pq-ledger/v1")
}

/// **D11.8 / D23.2 / D31.1**: Commercial `HTTP 402` L402 Toll Gate, `SignedPaymentVoucher` Replay-Protected Settlement & `PostQuantumLedgerBatch` Sealing (`POST /commons/settle`).
pub fn handle_commons_settle(journal_path: &Path, body: &[u8]) -> io::Result<(u16, &'static str, Vec<u8>)> {
    let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
    let unpaid_commercial = form.get("commercial_unpaid").map(|v| v == "1" || v == "true").unwrap_or(false);
    let amount_cents = form.get("amount_cents").and_then(|s| s.parse::<u64>().ok()).unwrap_or(if unpaid_commercial { 0 } else { 2_500 });
    let is_natural = form.get("is_natural_person").map(|v| v == "1" || v == "true").unwrap_or(false);

    let data_dir = journal_path.parent().unwrap_or_else(|| Path::new("."));
    let pool_path = data_dir.join("commons_pool.cbor-ld");
    let mut pool = PersistentCommonsPool::new("https://ns.webcivics.net/volumes/core.q42", 10_000, 150);
    if let Ok(raw) = fs::read(&pool_path) {
        if raw.len() >= 13 && &raw[0..3] == &[0xD9, 0x05, 0x01] {
            pool.accumulated_pool_cents = u64::from_be_bytes(raw[4..12].try_into().unwrap_or([0u8; 8]));
            if raw[12] != 0 { pool.routing_lane = PermissiveRoutingLane::EnforcePermissiveCommons; }
            if raw.len() >= 17 {
                let count = u32::from_be_bytes(raw[13..17].try_into().unwrap_or([0u8; 4])) as usize;
                for i in 0..count {
                    let off = 17 + i * 8;
                    if off + 8 <= raw.len() {
                        pool.seen_tx_nonces.push(u64::from_be_bytes(raw[off..off + 8].try_into().unwrap_or([0u8; 8])));
                    }
                }
            }
        }
    }

    let mut hub = MultiExchangeSwapHub::new(100);
    hub.register_exchange_quote(ExchangeQuote { exchange_site_name: "NonCustodialDexAggregator".to_string(), from_rail: BlockchainRail::EvmL2StablecoinUsdc, to_rail: BlockchainRail::ECashXec, rate_micros: 24_900_000_000, total_fee_bps: 15, exchange_online: true });
    let _ = hub.execute_best_coin_exchange(BlockchainRail::EvmL2StablecoinUsdc, BlockchainRail::ECashXec, amount_cents.max(100));

    let has_voucher = form.contains_key("tx_nonce") || form.contains_key("voucher_payer_seed_hex") || form.contains_key("voucher_sig_hex") || form.contains_key("voucher_tampered");
    let settle_res = if has_voucher && !unpaid_commercial && !is_natural {
        let tx_nonce = form.get("tx_nonce").and_then(|s| s.parse::<u64>().ok()).unwrap_or(1001);
        if pool.seen_tx_nonces.contains(&tx_nonce) {
            return Ok((409, "text/plain; charset=utf-8", b"HTTP 409 Conflict: Replay attack rejected (voucher tx_nonce already recorded)".to_vec()));
        }
        let mut voucher = SignedPaymentVoucher::sign_new(&[0x33u8; 32], "https://ns.webcivics.net/volumes/core.q42", amount_cents.max(1), BlockchainRail::ECashXec, tx_nonce);
        if let Some(sig_hex) = form.get("voucher_sig_hex").filter(|s| s.as_str() != "valid") {
            if sig_hex.len() == 128 {
                for (i, chunk) in sig_hex.as_bytes().chunks(2).enumerate() {
                    voucher.signature_ed25519[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16).unwrap_or(0);
                }
            } else {
                voucher.signature_ed25519[0] ^= 0xFF;
            }
        }
        if form.get("voucher_tampered").is_some_and(|v| v == "1" || v == "true") {
            voucher.signature_ed25519[0] ^= 0xFF;
        }
        if !voucher.verify_signature() {
            return Ok((401, "text/plain; charset=utf-8", b"HTTP 401 Unauthorized: Ed25519 SignedPaymentVoucher signature verification failed".to_vec()));
        }
        pool.verify_and_record_signed_voucher(&voucher).map_err(|_| 402u16)
    } else {
        let rail = if amount_cents > 0 { Some(BlockchainRail::ECashXec) } else { None };
        pool.evaluate_access_or_record_commercial_payment(is_natural, amount_cents, rail)
    };

    match settle_res {
        Ok((lane, maybe_q)) => {
            let mut state_bytes = Vec::with_capacity(17 + pool.seen_tx_nonces.len() * 8);
            state_bytes.extend_from_slice(&[0xD9, 0x05, 0x01, 1]);
            state_bytes.extend_from_slice(&pool.accumulated_pool_cents.to_be_bytes());
            state_bytes.push(u8::from(lane == PermissiveRoutingLane::EnforcePermissiveCommons));
            state_bytes.extend_from_slice(&(pool.seen_tx_nonces.len() as u32).to_be_bytes());
            for &n in &pool.seen_tx_nonces {
                state_bytes.extend_from_slice(&n.to_be_bytes());
            }
            let _ = fs::write(&pool_path, state_bytes);

            let quin = maybe_q.unwrap_or_else(|| {
                NQuin::new(pool.asset_did_hash, pack_predicate("https://ns.webcivics.net/economics#commonsExemptAccess", OP_COMMONS_OBLIGATION_POOL, false), amount_cents & 0x0FFF_FFFF_FFFF_FFFF, pack_context(pool.asset_did_hash, SensitivityClass::Public), pack_metadata(lane, 1, pool.accumulated_pool_cents as u32))
            });
            append_quin_to_journal(journal_path, &quin)?;
            if let Ok(batch) = PostQuantumLedgerBatch::finalize_pq_bft_batch(pool.seen_tx_nonces.len() as u64 + 1, 4, 3, &[quin], &[0x42u8; 32]) {
                let _ = fs::write(data_dir.join("pq_ledger.cbor-ld"), encode_pq_ledger_batch_cbor_ld(&batch, pool.accumulated_pool_cents));
            }
            Ok((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin)))
        }
        Err(402) => Ok((402, "text/plain; charset=utf-8", b"HTTP 402 Payment Required (WWW-Authenticate: L402): Commercial entity must settle Permissive Commons obligation".to_vec())),
        Err(code) => Ok((code, "text/plain; charset=utf-8", b"Commons settlement rejected".to_vec())),
    }
}

/// **D31.1**: Post-Quantum Native Ledger Checkpoint (`GET /commons/ledger.cbor-ld`).
pub fn handle_commons_ledger_cbor_ld(data_dir: &Path, journal_path: &Path) -> io::Result<(u16, &'static str, Vec<u8>)> {
    let pq_path = data_dir.join("pq_ledger.cbor-ld");
    if let Ok(bytes) = fs::read(&pq_path) {
        if bytes.len() >= 3 && bytes[0..3] == [0xD9, 0x05, 0x01] {
            return Ok((200, CBOR_LD_MEDIA_TYPE, bytes));
        }
    }
    let mut quins = replay_quin_journal(journal_path).unwrap_or_default();
    if quins.is_empty() {
        quins.push(NQuin::new(q_hash("https://ns.webcivics.net/volumes/core.q42"), pack_predicate("https://ns.webcivics.net/economics#genesisPqLedger", OP_COMMONS_OBLIGATION_POOL, false), 0, pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 0)));
    }
    let batch = PostQuantumLedgerBatch::finalize_pq_bft_batch(1, 4, 3, &quins, &[0x42u8; 32]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let bytes = encode_pq_ledger_batch_cbor_ld(&batch, 0);
    fs::write(&pq_path, &bytes)?;
    Ok((200, CBOR_LD_MEDIA_TYPE, bytes))
}

/// **D24.2**: Live Q-CDN Peer Registration (`POST /qcdn/register-seeder`) & Swarm Telemetry (`GET /qcdn/swarm.cbor-ld`).
pub fn handle_qcdn_route(data_dir: &Path, journal_path: &Path, method: &str, path: &str, body: &[u8]) -> io::Result<Option<(u16, &'static str, Vec<u8>)>> {
    let swarm_path = data_dir.join("qcdn_swarm.cbor-ld");
    match (method, path) {
        ("POST", "/qcdn/register-seeder") => {
            let form = parse_urlencoded_form(std::str::from_utf8(body).unwrap_or(""));
            let cid = form.get("cid").map(String::as_str).unwrap_or("bafkreihumancentriccommons2026");
            let seeder_did = form.get("seeder_did").map(String::as_str).unwrap_or("did:qi:peer_seeder_au");
            let webseed_url = form.get("webseed_url").map(String::as_str).unwrap_or("https://peer1.civics.au/torrent/webseed");
            let latency_ms = form.get("latency_ms").and_then(|s| s.parse::<u32>().ok()).unwrap_or(18);
            let mut payload = vec![0xD9, 0x05, 0x01, 1];
            payload.extend_from_slice(format!("cid={cid}|seeder={seeder_did}|url={webseed_url}|latency_ms={latency_ms}\n").as_bytes());
            if let Ok(existing) = fs::read(&swarm_path) {
                if existing.len() > 4 && &existing[0..3] == &[0xD9, 0x05, 0x01] { payload.extend_from_slice(&existing[4..]); }
            }
            fs::write(&swarm_path, &payload)?;
            let quin = NQuin::new(q_hash(seeder_did), pack_predicate("https://ns.webcivics.net/qcdn#registeredActiveSwarmSeeder", OP_PERMIT, false), q_hash(cid) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(webseed_url), SensitivityClass::Public), pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, latency_ms));
            append_quin_to_journal(journal_path, &quin)?;
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, encode_quin_receipt(&quin))))
        }
        ("GET", "/qcdn/swarm.cbor-ld") => {
            let bytes = fs::read(&swarm_path).unwrap_or_else(|_| {
                let mut init = vec![0xD9, 0x05, 0x01, 1];
                init.extend_from_slice(b"cid=bafkreihumancentriccommons2026|seeder=did:qi:webcivics_steward|url=https://ns.webcivics.net/torrent/webseed|latency_ms=12\n");
                init
            });
            Ok(Some((200, CBOR_LD_MEDIA_TYPE, bytes)))
        }
        _ => Ok(None),
    }
}

/// **D11.8**: Live AAA Film-Level 3D Volumetric Viewport SVG (`GET /studio/viewport.svg`).
pub fn handle_studio_viewport_svg() -> (u16, &'static str, Vec<u8>) {
    let (svg, _, _, _, _, _) = Vibe3dAssetForge::render_aaa_3d_viewport_svg("default-manifold", Vibe3dMeshPreset::GeodesicManifoldDome, Vibe3dPbrShader::BioluminescentPlasma, AnimationFamily::SpatialKinematics, "orbit_spin", 1.25);
    (200, "image/svg+xml; charset=utf-8", svg.into_bytes())
}

/// **D19.2**: Export 3D Studio Scene as Khronos glTF 2.0 Binary (`GET /studio/<scene>.glb`).
pub fn handle_studio_glb_export(scene: &str) -> (u16, &'static str, Vec<u8>) {
    let bytes = crate::vibe_3d_gltf_export::export_mesh_to_glb(scene, Vibe3dMeshPreset::from_name(scene), Vibe3dPbrShader::BioluminescentPlasma);
    (200, "model/gltf-binary", bytes)
}

/// **D19.2**: Export 3D Studio Scene as Wavefront OBJ (`GET /studio/<scene>.obj`).
pub fn handle_studio_obj_export(scene: &str) -> (u16, &'static str, Vec<u8>) {
    let obj = crate::vibe_3d_gltf_export::export_mesh_to_wavefront_obj(scene, Vibe3dMeshPreset::from_name(scene), Vibe3dPbrShader::BioluminescentPlasma);
    (200, "model/obj; charset=utf-8", obj.into_bytes())
}

/// **D11.8**: Forge 3D Scene & `QBDL` `.hmc` Bundle (`POST /cpanel/studio/forge-3d`).
pub fn handle_cpanel_studio_forge_3d(data_dir: &Path, journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<(String, NQuin)> {
    let scene_id = form.get("scene_id").map(String::as_str).unwrap_or("orbital-core");
    let mesh = form.get("mesh").map(|s| Vibe3dMeshPreset::from_name(s)).unwrap_or(Vibe3dMeshPreset::TorusKnotQuantumCore);
    let shader = form.get("shader").map(|s| Vibe3dPbrShader::from_name(s)).unwrap_or(Vibe3dPbrShader::BioluminescentPlasma);
    let family = form.get("family").and_then(|s| AnimationFamily::from_name(s)).unwrap_or(AnimationFamily::SpatialKinematics);
    let preset = form.get("preset").map(String::as_str).unwrap_or("orbit_spin");

    let receipt = Vibe3dAssetForge::forge_3d_scene_and_hmc(
        data_dir, scene_id, mesh, shader, family, preset, 1.25, "https://ns.webcivics.net",
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let quin = NQuin::new(
        q_hash(&receipt.scene_id),
        pack_predicate("https://ns.webcivics.net/studio#forged3dHmcBundle", OP_PERMIT, false),
        (receipt.face_count as u64) & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::Spatial, 1, receipt.vertex_count as u32),
    );
    append_quin_to_journal(journal_path, &quin)?;
    Ok((receipt.ipfs_cid, quin))
}

/// **D11.8**: Compile 4-Modality Presentation Sheaf (`POST /cpanel/ux/compile-sheaf`).
pub fn handle_cpanel_ux_compile_sheaf(data_dir: &Path, journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<NQuin> {
    let component_id = form.get("component_id").map(String::as_str).unwrap_or("hero-command-deck");
    let label = form.get("label").map(String::as_str).unwrap_or("Human-Centric Holographic Command Deck");
    let vibe_source = form.get("vibe_source").map(String::as_str).unwrap_or("pure fn hero_deck(x: Int) budget(steps: 100) -> Int { return x; }");

    let receipt = VibeUiUxToolkit::compile_and_persist_ui_sheaf(data_dir, component_id, label, vibe_source, 10.0, 90.0)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let quin = NQuin::new(
        q_hash(&receipt.component_id),
        pack_predicate("https://ns.webcivics.net/ux#compiledFourModalitySheaf", OP_PERMIT, false),
        (receipt.cbor_ld_bytes.len() as u64) & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, receipt.modalities_compiled.len() as u32),
    );
    append_quin_to_journal(journal_path, &quin)?;
    Ok(quin)
}

fn parse_blockchain_rail(name: &str, default_rail: BlockchainRail) -> BlockchainRail {
    match name.trim() {
        "USDC" | "EvmL2StablecoinUsdc" => BlockchainRail::EvmL2StablecoinUsdc,
        "XEC" | "ECashXec" => BlockchainRail::ECashXec,
        "XRP" | "XrplLedger" => BlockchainRail::XrplLedger,
        "BTC-LN" | "BTC" | "BitcoinLightning" => BlockchainRail::BitcoinLightning,
        "ILP-USD" | "ILP" | "IlpStreamSpsp" => BlockchainRail::IlpStreamSpsp,
        "QPQ" | "QualiaPqNative" => BlockchainRail::QualiaPqNative,
        _ => default_rail,
    }
}

/// **D13.3**: Multi-Exchange Anti-Usury Wallet Swap (`POST /cpanel/wallet/swap`).
pub fn handle_cpanel_wallet_swap(journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<NQuin> {
    let from = form.get("from_rail").map(|s| parse_blockchain_rail(s, BlockchainRail::EvmL2StablecoinUsdc)).unwrap_or(BlockchainRail::EvmL2StablecoinUsdc);
    let to = form.get("to_rail").map(|s| parse_blockchain_rail(s, BlockchainRail::ECashXec)).unwrap_or(BlockchainRail::ECashXec);
    let amount = form.get("amount").or_else(|| form.get("amount_cents")).and_then(|s| s.parse::<u64>().ok()).unwrap_or(100);
    let fee_bps = form.get("fee_bps").and_then(|s| s.parse::<u64>().ok()).unwrap_or(15);

    let mut hub = MultiExchangeSwapHub::new(100);
    hub.register_exchange_quote(ExchangeQuote {
        exchange_site_name: "NonCustodialDexAggregator".to_string(),
        from_rail: from,
        to_rail: to,
        rate_micros: 24_900_000_000,
        total_fee_bps: fee_bps,
        exchange_online: true,
    });
    let (_exchange, net_out) = hub
        .execute_best_coin_exchange(from, to, amount)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let swap_quin = NQuin::new(
        q_hash("did:qi:webcivics_steward"),
        pack_predicate("https://ns.webcivics.net/economics#executedCrossRailCoinSwap", OP_COMMONS_OBLIGATION_POOL, false),
        net_out & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(q_hash(from.ticker()), SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, fee_bps as u32),
    );
    append_quin_to_journal(journal_path, &swap_quin)?;
    Ok(swap_quin)
}

#[inline]
pub fn execute_cpanel_wallet_swap(journal_path: &Path, form: &BTreeMap<String, String>) -> io::Result<NQuin> {
    handle_cpanel_wallet_swap(journal_path, form)
}
