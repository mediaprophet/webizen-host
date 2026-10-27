//! `webizen-hostd` — Live Multi-Protocol Human-Centric Host Daemon & Turnkey Retail VPS CLI Entrypoint.
//!
//! Supports:
//! - `--init-vps <data_dir>`: Initializes `core.q42`, `journal.q42j`, `host_state.cbor-ld`,
//!   `tls/`, `git/`, and `deploy/` (`webizen-hostd.service`, `nftables-qpolicy.conf`, `install-vps.sh`,
//!   `Caddyfile`, `Containerfile`, `backup-cron.sh`, `cloud-init.yaml`, `build-deb.sh`).
//! - `--setup-noninteractive <data_dir> [domain] [steward_did] [passphrase]`: Completes 4-step retail
//!   setup headlessly (`complete_retail_setup` + salted PBKDF2-310k verifier + TLS cert + `deploy/`).
//! - `--check-config <data_dir>`: Loads and verifies `host_state.cbor-ld` (`SHA-256`),
//!   `core.q42` (`CRC-32C`), and `journal.q42j` (`CRC-32C` + `NQuin` parity) integrity.
//! - `--verify-vps-readiness <data_dir>` / `--verify-retail-readiness <data_dir>` / `--doctor <data_dir>`:
//!   Executes the live multi-protocol VPS readiness & encrypted snapshot/restore doctor.
//! - `--upgrade-rollback <data_dir>`: Restores and verifies the latest encrypted `.q42snap` snapshot.
//! - `--snapshot-backup <data_dir> <out_snap_path>` & `--restore-backup <snap_path> <target_dir>`.
//! - `--add-domain <data_dir> <domain> [rr_type] [value]` & `--add-mail-alias <data_dir> <alias> <did> <sender>`.
//! - `--ingest-ttl <data_dir> <ttl_file_path>` & `--serve [data_dir]`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use webizen_host_ingest::{replay_quin_journal, CompiledQ42Volume};
use webizen_host_workbench::retail_setup_wizard::complete_retail_setup;
use webizen_host_workbench::vps_deployment::CustomDnsRecord;
use webizen_host_workbench::{
    create_encrypted_vps_snapshot, ingest_ttl_file_into_q42, restore_encrypted_vps_snapshot,
    run_vps_doctor_diagnostics, HostPersistentState, MultiProtocolVpsConfig,
    MultiProtocolVpsSupervisor, WebizenHostDaemon,
};

fn default_data_dir() -> PathBuf {
    std::env::var("WEBIZEN_HOST_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("webizen-host-data"))
}

fn default_snapshot_passphrase() -> Vec<u8> {
    std::env::var("WEBIZEN_SNAPSHOT_PASSPHRASE")
        .unwrap_or_else(|_| "webizen-human-centric-steward-passphrase-2026".to_string())
        .into_bytes()
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(|s| s.as_str()) {
        Some("--init-vps") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let daemon = WebizenHostDaemon::new(data_dir.clone())?;
            let state = HostPersistentState::load_cbor_ld(&daemon.state_path)?;
            println!(
                "Initialized Human-Centric VPS data directory at {} (domain: {}, steward: {}, volume: {}, journal: {})",
                data_dir.display(), state.primary_domain, state.steward_did_qi,
                daemon.q42_path.display(), daemon.journal_path.display()
            );
            Ok(())
        }
        Some("--setup-noninteractive") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let domain = args.get(2).cloned().unwrap_or_else(|| "coop.civics.au".to_string());
            let steward_did = args.get(3).cloned().unwrap_or_else(|| "did:qi:steward".to_string());
            let passphrase = args.get(4).cloned().unwrap_or_else(|| "HumanCentricStewardPass2026!".to_string());
            let daemon = WebizenHostDaemon::new(data_dir.clone())?;
            let mut form = BTreeMap::new();
            form.insert("primary_domain".to_string(), domain.clone());
            form.insert("steward_did_qi".to_string(), steward_did.clone());
            form.insert("passphrase".to_string(), passphrase);
            let _ = complete_retail_setup(&data_dir, &daemon.journal_path, &form)?;
            println!(
                "Completed headless retail setup at {} (domain: {}, steward: {})",
                data_dir.display(), domain, steward_did
            );
            Ok(())
        }
        Some("--check-config") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let state = HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld"))?;
            let vol = CompiledQ42Volume::load_from_disk(&data_dir.join("core.q42"))?;
            let journal_quins = replay_quin_journal(&data_dir.join("journal.q42j"))?;
            println!(
                "Verified Webizen-Host integrity at {} (domain: {}, superblocks: {}, journal_quins: {})",
                data_dir.display(), state.primary_domain, vol.superblocks.len(), journal_quins.len()
            );
            Ok(())
        }
        Some("--verify-vps-readiness") | Some("--verify-retail-readiness") | Some("--doctor") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let receipt_bytes = WebizenHostDaemon::verify_full_vps_readiness(&data_dir)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let doctor_bytes = run_vps_doctor_diagnostics(&data_dir)?;
            fs::write(data_dir.join("retail_readiness_receipt.cbor-ld"), &receipt_bytes)?;
            println!(
                "Verified Human-Centric Retail VPS readiness & encrypted snapshot doctor at {} (readiness receipt: {} B, doctor receipt: {} B)",
                data_dir.display(), receipt_bytes.len(), doctor_bytes.len()
            );
            Ok(())
        }
        Some("--upgrade-rollback") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let _ = WebizenHostDaemon::new(data_dir.clone())?;
            let snap_path = data_dir.join("backups").join("vps_snapshot.q42snap");
            let pass = default_snapshot_passphrase();
            if !snap_path.exists() {
                if let Some(p) = snap_path.parent() { fs::create_dir_all(p)?; }
                let _ = create_encrypted_vps_snapshot(&data_dir, &pass, &[0x42u8; 16], &snap_path)?;
            }
            let (restored_files, _) = restore_encrypted_vps_snapshot(&snap_path, &pass, &data_dir)?;
            println!("Verified atomic upgrade rollback of {} files from {}", restored_files, snap_path.display());
            Ok(())
        }
        Some("--snapshot-backup") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let out_snap = args.get(2).map(PathBuf::from).unwrap_or_else(|| data_dir.join("backups").join("vps_snapshot.q42snap"));
            let _ = WebizenHostDaemon::new(data_dir.clone())?;
            let pass = default_snapshot_passphrase();
            let receipt = create_encrypted_vps_snapshot(&data_dir, &pass, &[0x42u8; 16], &out_snap)?;
            println!(
                "Sealed encrypted VPS snapshot at {} (files: {}, encrypted_bytes: {})",
                receipt.snapshot_path.display(), receipt.file_count, receipt.encrypted_size_bytes
            );
            Ok(())
        }
        Some("--restore-backup") => {
            let snap_path = args.get(1).map(PathBuf::from).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing <snap_path>")
            })?;
            let target_dir = args.get(2).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let pass = default_snapshot_passphrase();
            let (restored_files, _) = restore_encrypted_vps_snapshot(&snap_path, &pass, &target_dir)?;
            println!("Restored {} verified files from {} into {}", restored_files, snap_path.display(), target_dir.display());
            Ok(())
        }
        Some("--add-domain") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let domain = args.get(2).cloned().unwrap_or_else(|| "coop.civics.au".to_string());
            let daemon = WebizenHostDaemon::new(data_dir.clone())?;
            let mut state = HostPersistentState::load_cbor_ld(&daemon.state_path)?;
            if !state.hosted_domains.contains(&domain) {
                state.hosted_domains.push(domain.clone());
            }
            if let (Some(rr_type), Some(value)) = (args.get(3), args.get(4)) {
                state.custom_dns_records.push(CustomDnsRecord { name: domain.clone(), rr_type: rr_type.clone(), ttl: 300, value: value.clone() });
            }
            state.save_cbor_ld(&daemon.state_path)?;
            println!("Added hosted domain {} to {}", domain, daemon.state_path.display());
            Ok(())
        }
        Some("--add-mail-alias") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let alias = args.get(2).cloned().unwrap_or_else(|| "bob@civics.au".to_string());
            let did = args.get(3).cloned().unwrap_or_else(|| "did:qi:bob".to_string());
            let sender = args.get(4).cloned().unwrap_or_else(|| "alice@bob.tld".to_string());
            let daemon = WebizenHostDaemon::new(data_dir.clone())?;
            let mut state = HostPersistentState::load_cbor_ld(&daemon.state_path)?;
            state.mail_aliases.push((alias.clone(), did.clone(), sender.clone()));
            state.save_cbor_ld(&daemon.state_path)?;
            println!("Added relationship mail alias {} -> {} ({})", alias, sender, did);
            Ok(())
        }
        Some("--ingest-ttl") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            let ttl_path = args.get(2).map(PathBuf::from).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing <ttl_file_path>")
            })?;
            let (superblocks, lexicon_entries) = ingest_ttl_file_into_q42(&data_dir, &ttl_path)?;
            println!(
                "Ingested ontology {} into {} (superblocks: {}, lexicon_entries: {})",
                ttl_path.display(), data_dir.join("core.q42").display(), superblocks, lexicon_entries
            );
            Ok(())
        }
        Some("--serve") => {
            let data_dir = args.get(1).map(PathBuf::from).unwrap_or_else(default_data_dir);
            serve_multi_protocol_daemon(data_dir)
        }
        _ => {
            let data_dir = args.first().map(PathBuf::from).unwrap_or_else(default_data_dir);
            serve_multi_protocol_daemon(data_dir)
        }
    }
}

fn serve_multi_protocol_daemon(data_dir: PathBuf) -> std::io::Result<()> {
    let mut cfg = MultiProtocolVpsConfig::production_defaults(data_dir);
    if let Ok(v) = std::env::var("WEBIZEN_HOST_BIND") { cfg.http_bind = v; }
    if let Ok(v) = std::env::var("WEBIZEN_DNS_BIND") { cfg.dns_bind = v; }
    if let Ok(v) = std::env::var("WEBIZEN_SMTP_BIND") { cfg.smtp_bind = v; }
    if let Ok(v) = std::env::var("WEBIZEN_SANCTUARY_BIND") { cfg.sanctuary_bind = v; }
    let mut handle = MultiProtocolVpsSupervisor::spawn(cfg)?;
    println!(
        "webizen-hostd multi-protocol supervisor active (HTTP: {}, UDP DNS: {}, TCP SMTP: {}, Sanctuary Loopback: {})",
        handle.http_addr, handle.dns_addr, handle.smtp_addr, handle.sanctuary_addr
    );
    for t in handle.threads.drain(..) { let _ = t.join(); }
    Ok(())
}
