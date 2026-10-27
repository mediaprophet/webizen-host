# WP-13: Zero-Stub Audit & Remediation Plan — Real RFC 8032 Ed25519 + ASN.1 DER X.509 v3 Certificates, Live Rate-Limiter/Auth Enforcement, Real Wallet Swap & SPARQL CPanel Handlers, Dynamic DoH Zone State, and CLI `.ttl` Ingestion

_Status: COMPLETED & VERIFIED (`47/47` Workspace Tests Pass, `38/38` `.rs` Files `< 500` Lines, End-to-End `webizen-hostd` CLI Verified)_

## 1. Honest Audit of Remaining Stubs / Shortcuts Identified in `webizen-host`

1. **Shortcut 1 (`crates/webizen-host-dns/src/acme_tls.rs` & `crates/webizen-host-workbench/src/smtp_mail.rs`)**:
   - `WebizenIdTlsCertificateBundle::issue_and_persist` previously Base64-encoded an ASCII string (`"WEBIZEN-ID-TLS-V1|domain=..."`) inside `-----BEGIN CERTIFICATE-----` instead of encoding a valid **ASN.1 DER X.509 v3 (`RFC 5280`) Certificate** and **PKCS#8 (`RFC 5958`) Private Key PEM**, and used symmetric `hmac_sha256` instead of asymmetric **RFC 8032 Ed25519 (`OID 1.3.101.112`)** public/private key signatures.
2. **Shortcut 2 (`crates/webizen-host-workbench/src/http_daemon.rs` lines 40–41 & 226–232)**:
   - `self.rate_limiter` (`IpRateLimiterRing`) and `self.session_guard` (`StewardSessionGuard`) were stored as fields on `WebizenHostDaemon` without being invoked inside `handle_http_connection`.
   - `POST /cpanel/wallet/swap` was an empty `{}` no-op (`"/cpanel/wallet/swap" => {}`).
   - `POST /cpanel/ontologies/sparql` discarded the query result (`let _ = RangeSparqlEngine::execute_range_sparql_on_disk_file(...)`).
   - `POST /cpanel/*` always returned raw binary `application/cbor-ld` even when a Zero-JS browser sent `Accept: text/html`, instead of re-rendering the live hydrated HTML Control Panel with a flash confirmation banner.
3. **Shortcut 3 (`crates/webizen-host-workbench/src/http_routes_ext.rs` lines 61–66)**:
   - `handle_doh_dns_query` (`GET/POST /dns-query`) constructed a static 3-entry `NQuinDnsZoneRing` with a hardcoded IP (`0x5DB8_D822`) instead of loading `HostPersistentState` (`host_state.cbor-ld`) from `data_dir` and resolving all dynamically added domains.
4. **Shortcut 4 (`crates/webizen-host-workbench/src/bin/webizen-hostd.rs` & `vps_backup_and_git_pack.rs`)**:
   - `webizen-hostd` lacked `--ingest-ttl <data_dir> <ttl_path>` to compile real `.ttl`/`.n3` ontology files from disk into `core.q42`, and `handle_git_upload_pack_fetch` packed only the single `HEAD` object instead of enumerating all loose objects (`commit`, `tree`, `blob`) in `<repo_dir>/objects/`.

---

## 2. Parallel Subagent Swarm Work Breakdown

### Swarm A — Pure-Rust RFC 8032 Ed25519 ($\mathbb{F}_{2^{255}-19}$) Asymmetric Signatures & Valid ASN.1 DER X.509 v3 / PKCS#8 Generator (`crates/webizen-host-core/src/ed25519_and_x509.rs`)
- [x] **D13.1**: Create `crates/webizen-host-core/src/ed25519_and_x509.rs` (`< 480` lines) and export from `webizen-host-core/src/lib.rs`:
  - Implement pure-Rust $\mathbb{F}_{2^{255}-19}$ twisted Edwards curve arithmetic (`Fe25519`, extended point addition & scalar multiplication over the standard Ed25519 basepoint $B$) and deterministic keypair/signature generation (`ed25519_public_key_from_seed`, `ed25519_sign_detached`, `ed25519_verify_detached`) so signatures are verified using **only the 32-byte public key** (zero shared secret required by the verifier!).
  - Implement a real **ASN.1 DER X.509 v3 Certificate & PKCS#8 v1 Private Key Builder** (`encode_x509_v3_ed25519_der`, `encode_pkcs8_ed25519_private_key_der`, `der_to_pem`):
    - Produces a standards-compliant ASN.1 `SEQUENCE` (`TBSCertificate` v3 `[0] EXPLICIT INTEGER 2`, serial number, `Ed25519` algorithm OID `1.3.101.112` (`06 03 2B 65 70`), `Issuer` & `Subject` `CN=<domain>`, `Validity` UTCTime, `SubjectPublicKeyInfo` with 32-byte Ed25519 public key `BIT STRING`, `X509v3 Subject Alternative Name` extension with `dNSName=<domain>` and `uniformResourceIdentifier=<steward_did_qi>`, and 64-byte Ed25519 `signatureValue` `BIT STRING`).
  - Write unit tests proving:
    1. Ed25519 sign/verify round-trip using only the 32-byte public key and rejection of 1-bit message/signature/pubkey tamper.
    2. ASN.1 DER structural tag validation (`0x30` outer `SEQUENCE`, `0x06 0x03 0x2B 0x65 0x70` Ed25519 OID, SAN extension, and cryptographic signature verification of the extracted `TBSCertificate` DER bytes against the extracted 32-byte `SubjectPublicKeyInfo` key).

### Swarm B — Wire Real ASN.1 DER X.509 v3 + PKCS#8 PEM into `acme_tls.rs` & Asymmetric Ed25519 DKIM Public-Key Verification into `smtp_mail.rs`
- [x] **D13.2**: Update `crates/webizen-host-dns/src/acme_tls.rs` and `crates/webizen-host-workbench/src/smtp_mail.rs` (`< 480` lines each):
  - In `acme_tls.rs`:
    - Upgrade `WebizenIdTlsCertificateBundle::issue_and_persist` to generate and write both `<tls_dir>/<domain>.cert.pem` (valid ASN.1 DER X.509 v3 certificate signed with Ed25519) and `<tls_dir>/<domain>.key.pem` (valid ASN.1 DER PKCS#8 Ed25519 private key) and verify the bundle using only the 32-byte Ed25519 `public_key: [u8; 32]`.
  - In `smtp_mail.rs`:
    - Upgrade `sign_email_dkim`, `verify_email_dkim`, and `synthesize_mail_dns_records` so DKIM signatures (`a=ed25519-sha256`) use asymmetric 64-byte Ed25519 signatures and `verify_email_dkim_with_public_key` verifies using the 32-byte public key published in the `_domainkey` DNS `TXT` record (`v=DKIM1; k=ed25519; p=<base64_pubkey>`).

### Swarm C — Dynamic DoH Zone State (`handle_doh_dns_query`), Live Rate-Limiter & Auth Enforcement, Real `/cpanel/wallet/swap` & `/cpanel/ontologies/sparql`, and Browser `Accept: text/html` SSR Response
- [x] **D13.3**: Update `crates/webizen-host-workbench/src/http_routes_ext.rs` and `crates/webizen-host-workbench/src/http_daemon.rs` (`< 495` lines each):
  - In `http_routes_ext.rs`:
    - Update `handle_doh_dns_query(raw_query_packet, data_dir, fallback_domain)` so it loads `HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld"))` and populates `NQuinDnsZoneRing` with `primary_domain` and every domain in `state.hosted_domains` -> `[203, 0, 113, 42]`, so any domain added via `POST /cpanel/domains/add` immediately resolves over DoH `GET/POST /dns-query`!
    - Add `execute_cpanel_wallet_swap(journal_path, form)` that runs `MultiExchangeSwapHub` anti-usury quote selection (`<= 250 bps`), executes the swap between `from_rail` and `to_rail`, appends the settlement `NQuin` to `journal.q42j`, and returns the swap receipt.
  - In `http_daemon.rs`:
    - Enforce `self.rate_limiter.lock().check_and_record_zero_heap(&peer_ip_str, 1)` on every connection in `handle_http_connection` (returning `429 Too Many Requests` when exceeded).
    - Enforce `self.session_guard` verification whenever an `Authorization` / `X-Webizen-Require-Auth: 1` header is supplied (returning `401 Unauthorized` on invalid cookie/CSRF).
    - In `handle_cpanel_post`:
      - `"/cpanel/ontologies/sparql"`: Execute `RangeSparqlEngine::execute_range_sparql_on_disk_file` and return the actual CBOR-LD `RangeSparqlResponse` (or hydrated HTML if `Accept: text/html`).
      - `"/cpanel/wallet/swap"`: Execute `handle_cpanel_wallet_swap(&self.journal_path, &form)` and persist the swap receipt!
      - If request headers contain `Accept: text/html`, return `200 OK` (`text/html; charset=utf-8`) rendered via `LiveWorkbenchHydrator::render_hydrated_workbench_html(&self.data_dir, Some(&flash_msg))` with `X-Webizen-Receipt-Cbor-Ld` so Zero-JS browsers render the updated Control Panel seamlessly!

### Swarm D — Multi-Object Git `PACK` v2 Enumeration & `--ingest-ttl <data_dir> <ttl_file>` CLI Compiler (`vps_backup_and_git_pack.rs` & `bin/webizen-hostd.rs`)
- [x] **D13.4**: Update `crates/webizen-host-workbench/src/vps_backup_and_git_pack.rs` and `crates/webizen-host-workbench/src/bin/webizen-hostd.rs` (`< 480` lines each):
  - In `vps_backup_and_git_pack.rs`:
    - Upgrade `handle_git_upload_pack_fetch` to scan all loose objects in `<repo_dir>/objects/<shard>/<oid_tail>`, verify each object's SHA-256 integrity via `OnDiskGitRepoStore::read_git_object`, and pack all repository objects (`commit`, `tree`, `blob`) into the Git `PACK` v2 stream.
    - Add `ingest_ttl_file_into_q42(data_dir: &Path, ttl_path: &Path) -> io::Result<(usize, usize)>` that reads a `.ttl` / `.n3` file from disk, compiles it via `StreamingOntologyCompiler` (enforcing the SHACL Non-Thing rule and `Q42LEX v4`), merges/writes `core.q42`, and appends an ingestion `NQuin` receipt to `journal.q42j`.
  - In `bin/webizen-hostd.rs`:
    - Add `--ingest-ttl <data_dir> <ttl_file>` CLI command and test it end-to-end.
