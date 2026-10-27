# WP-12: Full Production Multi-Protocol VPS Supervisor, Live SSR State Hydration, JMAP/Maildir Engine, Complete Git Clone/Upload-Pack & Encrypted VPS Snapshot/Restore Plan

_Status: COMPLETED & VERIFIED (45/45 Workspace Tests Passing, 37/37 `.rs` Files `< 500` Lines, 24-Point `webizen-hostd --doctor` & Encrypted `.q42snap` Snapshot/Restore Verified)_

## 0. Architectural & Human-Centric Invariants

1. **Human-Centric & Human-Rights Nomenclature**: Strictly zero occurrences of forbidden `sov*` terminology across all code, comments, CLI flags, systemd/nftables/Caddy configs, and tests.
2. **Native W3C CBOR-LD (`0xD9 0x05 0x01` / `0xD9 0x05 0x02`)**: All state receipts, health checks, JMAP mailbox responses, and `.q42j` journal records use native W3C CBOR-LD binary wire format instead of JSON.
3. **Zero JavaScript (`script-src 'none'`)**: All browser control-panel views, live SSR state hydration, and interactive 3D/UX studios operate with 100% pure HTML5/CSS3/SVG + deterministic VibeScript (`VBC1`).
4. **File Size Hygiene (`AGENTS.md` §0-B)**: Every `.rs` implementation file in the workspace must remain strictly `< 500` lines.

---

## 1. Comprehensive To-Do List & Swarm Work Breakdown

### Swarm A — Multi-Protocol Concurrent VPS Supervisor & Dynamic Hot-Reload (`crates/webizen-host-workbench/src/multi_protocol_supervisor.rs`)
- [x] **D12.1**: Implement `MultiProtocolVpsConfig` and `MultiProtocolVpsSupervisor` in `crates/webizen-host-workbench/src/multi_protocol_supervisor.rs` (`< 450` lines):
  - Concurrently binds and supervises:
    1. **HTTP/1.1 + DoH + Solid LDP + IPFS + WebSeed + Git Smart HTTP + Control Panel** listener (`http_bind`, default `0.0.0.0:4242` or `127.0.0.1:0` in tests) with bounded multi-threaded request handling.
    2. **Authoritative UDP DNS (`RFC 1035`)** listener (`dns_bind`, default `0.0.0.0:5353` or `127.0.0.1:0` in tests) that dynamically syncs hosted domains from `HostPersistentState` into `NQuinDnsZoneRing` on every query or state update.
    3. **Inbound/Submission TCP SMTP (`RFC 5321`)** listener (`smtp_bind`, default `0.0.0.0:2525` or `127.0.0.1:0` in tests) that dynamically reloads `mail_aliases` from `HostPersistentState` (`host_state.cbor-ld`) on each session so newly created `bob@alice.tld` aliases work immediately without daemon restart.
    4. **Loopback-Only Sanctuary Keep Listener** (`sanctuary_bind`, default `127.0.0.1:8080` or `127.0.0.1:0` in tests) with socket-level `SanctuaryLoopbackGuard` (`peer_addr.ip().is_loopback()`) that physically rejects non-loopback connections while serving `/sanctuary/backup`, `/sanctuary/recover`, and `/sanctuary/status`.
  - Provide clean graceful shutdown across all 4 concurrent protocol listeners (`shutdown: Arc<AtomicBool>`).
  - Write unit tests proving concurrent HTTP + UDP DNS + TCP SMTP + Sanctuary Loopback operation and dynamic hot-reload when a new domain or mail alias is added via HTTP `POST /cpanel/domains/add` and `POST /cpanel/email/add`.

### Swarm B — Live Dynamic SSR State Hydration & Zero-JS Browser Form Negotiation (`crates/webizen-host-workbench/src/live_ssr_hydration.rs`)
- [x] **D12.2**: Implement `LiveWorkbenchHydrator` and `LiveHostTelemetrySummary` in `crates/webizen-host-workbench/src/live_ssr_hydration.rs` (`< 450` lines):
  - Inspects live on-disk state in `<data_dir>`:
    - `HostPersistentState` (`primary_domain`, `steward_did_qi`, `hosted_domains`, `mail_aliases`, `git_repos`, `delegated_permits_count`)
    - Spooled emails in `<data_dir>/maildir/new` and `<data_dir>/maildir/cur`
    - Forged 3D `.hmc` scenes in `<data_dir>/studio/*.hmc`
    - Compiled 4-modality UI sheaves in `<data_dir>/ux/*.cbor-ld`
    - Total parity-verified `NQuin` receipts in `<data_dir>/journal.q42j`
  - Dynamically hydrates the Zero-JS HTML control panel (`render_hydrated_workbench_html(&data_dir, flash_banner)`) so that every newly added domain, relationship email alias, bare Git repository, spooled email, forged `.hmc` 3D scene, and compiled `.cbor-ld` UI sheaf appears live in the served HTML (`GET /`, `GET /cpanel`, and `Accept: text/html` form submissions) while preserving `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'`.
  - Write unit tests verifying that adding a domain, alias, Git repo, or 3D scene immediately appears in the hydrated `GET /cpanel` HTML output with zero JavaScript.

### Swarm C — JMAP-over-CBOR-LD & Maildir Inbox/Cur/Sent API + Outbound DKIM Submission (`crates/webizen-host-workbench/src/jmap_maildir_api.rs`)
- [x] **D12.3**: Implement `JmapMaildirEngine`, `MailMessageSummary`, and `OutboundDkimSubmissionReceipt` in `crates/webizen-host-workbench/src/jmap_maildir_api.rs` (`< 450` lines):
  - `list_mailbox_cbor_ld(mail_root, filter_alias)`: Scans `maildir/new`, `maildir/cur`, and `maildir/sent`, parses RFC 5322 headers (`From`, `To`, `Subject`, `Date`, `DKIM-Signature`), and encodes the mailbox list as W3C CBOR-LD (`0xD9 0x05 0x01`).
  - `read_and_mark_seen(mail_root, message_id)`: Reads a message from `maildir/new/<id>.eml`, atomically moves it to `maildir/cur/<id>.eml`, and returns the full RFC 5322 message + CBOR-LD receipt.
  - `submit_outbound_dkim_email(mail_root, journal_path, domain, selector, signing_seed, from_addr, to_addr, subject, body_text)`:
    - Validates human-centric nomenclature and synthesizes an RFC 5322 message.
    - Signs the message using `sign_email_dkim` (`Ed25519-SHA256` relaxed/relaxed DKIM).
    - Persists the signed message to `maildir/sent/<id>.eml` and `maildir/outbox/<id>.eml`.
    - Appends a 48-byte `NQuin` outbound mail provenance receipt to `journal.q42j`.
  - HTTP route handler `handle_jmap_mail_route(data_dir, journal_path, method, path, body)` supporting:
    - `GET /mail/inbox` (CBOR-LD mailbox summary)
    - `GET /mail/message/<id>` (reads message & transitions `new/` → `cur/`)
    - `POST /mail/send` and `POST /cpanel/email/send` (DKIM-signed outbound submission)
  - Write unit tests verifying inbound SMTP spool → `GET /mail/inbox` → `GET /mail/message/<id>` (`new` to `cur` transition) → `POST /mail/send` (`DKIM-Signature` verification + `.q42j` journal receipt).

### Swarm D — Git Smart HTTP `git-upload-pack` (`git clone`/`fetch`), Encrypted Full-VPS Snapshot/Restore (`.q42snap`) & 24-Point VPS Doctor (`crates/webizen-host-workbench/src/vps_backup_and_git_pack.rs`, `http_daemon.rs`, `bin/webizen-hostd.rs`)
- [x] **D12.4**: Implement `handle_git_upload_pack_fetch`, `serve_git_repo_bundle`, `EncryptedVpsSnapshotEngine`, and `run_vps_doctor_diagnostics` in `crates/webizen-host-workbench/src/vps_backup_and_git_pack.rs` (`< 450` lines):
  - **Git Smart HTTP Clone/Fetch (`POST /git/<repo>/git-upload-pack` & `GET /git/<repo>/bundle`)**:
    - Parses client `want <oid>` pkt-lines, reads the loose commit/tree/blob objects from `OnDiskGitRepoStore`, and returns a valid `application/x-git-upload-pack-result` pkt-line `NAK\n` + `PACK` v2 stream (with SHA-256 trailer) so `git clone` / `git fetch` works end-to-end.
    - Serves portable `.bundle` files on `GET /git/<repo>/bundle` with HTTP 206 `Range` support for WebTorrent WebSeed.
  - **ChaCha20-Poly1305 Encrypted Full-VPS Snapshot & Restore (`.q42snap`)**:
    - `create_encrypted_vps_snapshot(data_dir, passphrase, salt, out_snap_path)`: Collects all relative files under `data_dir` (`host_state.cbor-ld`, `core.q42`, `journal.q42j`, `maildir/`, `git/`, `solid/`, `studio/`, `ux/`, `tls/`), computes a binary SHA-256 Merkle root over all file digests, derives a 256-bit key via `pbkdf2_hmac_sha256`, encrypts the archive with `chacha20_poly1305_encrypt` (`QSNAP1` header + W3C CBOR-LD `0xD90501` metadata), and writes `out_snap_path`.
    - `restore_encrypted_vps_snapshot(snap_path, passphrase, salt, target_dir)`: Decrypts and verifies the ChaCha20-Poly1305 tag + SHA-256 Merkle root (failing closed on any bit tamper) and deterministically reconstructs the entire VPS data directory on a target host.
  - **Wire into `WebizenHostDaemon` (`http_daemon.rs`), `bin/webizen-hostd.rs`, and 24-Point `verify_full_vps_readiness`**:
    - Wire `/mail/inbox`, `/mail/message/*`, `/mail/send`, `/cpanel/email/send`, `POST /git/<repo>/git-upload-pack`, `GET /git/<repo>/bundle`, `POST /cpanel/backup/snapshot`, and `LiveWorkbenchHydrator` into `http_daemon.rs` (keeping `http_daemon.rs` `< 500` lines).
    - Expand `bin/webizen-hostd.rs` with `--doctor`, `--snapshot-backup`, `--restore-backup`, `--add-domain`, `--add-mail-alias`, and multi-protocol `--serve` via `MultiProtocolVpsSupervisor`.
    - Expand `verify_full_vps_readiness` to verify all **24 points** including `MultiProtocolVpsSupervisor` dynamic DNS/SMTP hot-reload, `LiveWorkbenchHydrator` SSR output, JMAP `/mail/inbox` + `/mail/send` DKIM signing, `POST /git/<repo>/git-upload-pack` clone packfile, and encrypted `.q42snap` full-VPS snapshot & restore round-trip!
