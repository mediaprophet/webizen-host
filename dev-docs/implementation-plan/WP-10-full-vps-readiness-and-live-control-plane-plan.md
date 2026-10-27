# WP-10 (P0): Complete VPS Production Readiness — Unified Multi-Protocol Daemon, Authenticated Control-Panel POST Mutations, Solid/IPFS/WebSeed Endpoints & Automated Self-Test

**Work Package ID:** `WP-10`  
**Priority:** `P0` (Final Pre-Deployment Gate for Live Internet-Facing VPS Hosting)  
**Depends On:** [`WP-01`](./WP-01-large-ontology-streaming-compiler.md)–[`WP-09`](./WP-09-vps-production-deployment-swarm-plan.md)  
**Target Repository:** `C:\github\webizen-host`

---

## 1. Comprehensive To-Do List of Remaining VPS Deployment Deliverables

While `WP-01` through `WP-09` implemented the cryptographic primitives, `.q42` disk storage, `vibe` sandbox execution, RFC 1035 UDP DNS, RFC 5321 TCP SMTP, and Git Smart HTTP modules, deploying on a real internet-facing VPS requires uniting these modules into a **single shared-state multi-protocol server** with **authenticated Control Panel `<form method="post">` mutations across all 10 pages**, **live W3C Solid LDP / IPFS / WebTorrent WebSeed endpoints**, and an **automated 12-point `--verify-vps-readiness` self-test**:

### Swarm A — Steward Session Authentication (`did:qi` HMAC Cookie + CSRF Gate) & Zero-Heap Per-IP Rate Limiter (`auth_and_session.rs`)
- [x] **D10.1 — Cryptographic Steward Session & CSRF Token Manager (`StewardSessionGuard`)**:
  - Issue and verify `HttpOnly; SameSite=Strict` steward session cookies (`DNI_SESSION=<expiry_epoch>|<steward_did>|<hmac_sha256_hex>`) signed with a per-host 32-byte secret key persisted in `<data_dir>/tls/session_secret.key`.
  - Derive deterministic, constant-time verified CSRF tokens (`hmac_sha256(session_key, session_cookie)`) required for all state-mutating `POST /cpanel/*` requests.
- [x] **D10.2 — Zero-Heap (`HotZeroHeap`) 256-Slot Per-IP Token-Bucket Rate Limiter (`IpRateLimiterRing`)**:
  - Track per-IP request budgets in a fixed 256-slot cache-line-aligned array (`[IpBucketSlot; 256]`) with zero heap allocation, rejecting DoS / brute-force bursts with `HTTP 429 Too Many Requests` (or SMTP `421` / DNS drop).

### Swarm B — Live W3C Solid LDP Pod Server (`/solid/*`), IPFS Content-Addressed Gateway (`/ipfs/*`), & WebTorrent HTTP-206 WebSeed (`/torrent/webseed/*`) (`solid_ipfs_webseed.rs`)
- [x] **D10.3 — W3C Solid LDP Pod Read/Write Endpoint (`SolidPodDiskGateway`)**:
  - `PUT /solid/<pod>/<resource.ttl>` & `POST /solid/<pod>/<resource.ttl>`: Parse incoming W3C Turtle triples, enforce `Tier3SolidAndEbpfSandbox` bandwidth ceilings and the SHACL Non-Thing / Human-Centric Nomenclature rules, persist 48-byte `NQuin`s + `.ttl` to `<data_dir>/solid/<pod>/<resource.ttl>`, and append provenance `NQuin`s to `journal.q42j`.
  - `GET /solid/<pod>/<resource.ttl>`: Content-negotiated response (`application/cbor-ld` Tag `0xD90501`, `text/turtle`, or `application/q42`) with `Link: <http://www.w3.org/ns/ldp#Resource>; rel="type"` and `WAC-Allow` headers.
- [x] **D10.4 — IPFS Content-Addressed Block Gateway & WebTorrent `HTTP 206` WebSeed Handler (`P2pWebSeedGateway`)**:
  - Publish files/bundles into `<data_dir>/files/<name>` with `MultiProtocolShareDescriptor` (`bafkrei...` SHA-256 raw CIDv1 + `magnet:?xt=urn:btih:...&ws=...`).
  - `GET /ipfs/<cid>`: Verify SHA-256 block integrity against the requested `<cid>` and stream the verified bytes.
  - `GET /torrent/webseed/<name>` (with optional `Range: bytes=start-end`): Serve `206 Partial Content` slices from disk for WebTorrent clients.

### Swarm C — Interactive Zero-JS HTML `<form method="post">` Controls Across All 10 Control Panel Pages (`assets/index.html` & `persona_ui.rs`)
- [x] **D10.5 — Live HTML `<form method="post">` Action Controls on All 10 Pages (`assets/index.html`)**:
  - Keep 100% Zero-JavaScript (`script-src 'none'`, zero `<script>` JS tags, zero `on*=` attributes) while adding native HTML `<form method="post" action="/cpanel/...">` submission controls to every Control Panel module:
    1. `#page-domains`: `POST /cpanel/domains/add` (add domain + `A`/`AAAA`/`TXT` DNS record).
    2. `#page-email`: `POST /cpanel/email/add` (issue `bob@alice.tld` relationship alias or `receipts@alice.tld` programmable hook).
    3. `#page-files`: `POST /cpanel/files/publish` (publish permissive-commons file to IPFS + WebTorrent + HTTP-206).
    4. `#page-ontologies`: `POST /cpanel/ontologies/sparql` (execute on-disk Range-SPARQL query).
    5. `#page-apps`: `POST /cpanel/apps/install` (provision W3C Solid Pod or `SDK-01..10` QApp).
    6. `#page-security`: `POST /cpanel/security/issue-cert` (issue/rotate `WebizenID-TLS` + ACME challenge).
    7. `#page-wallet`: `POST /cpanel/wallet/swap` (execute anti-usury Multi-Exchange coin swap).
    8. `#page-jobs`: `POST /cpanel/jobs/backup` (seal ChaCha20-Poly1305 AEAD Sanctuary Keep `.q42j` backup + $\text{GF}(2^8)$ Shamir shares).
    9. `#page-delegation`: `POST /cpanel/delegation/issue` (issue `P0..P3` compute/bandwidth/storage delegation permit).
    10. `#page-git`: `POST /cpanel/git/create-repo` (initialize on-disk bare Git repository `<name>.git`).

### Swarm D — Unified Multi-Service Runtime (`HTTP + UDP DNS + TCP SMTP`), Complete `/cpanel/*` Form Handlers, Container/Caddy Deployment Configs & 12-Point `--verify-vps-readiness` CLI (`vps_deployment.rs`, `http_daemon.rs`, `webizen-hostd.rs`)
- [x] **D10.6 — Shared-State Unified Multi-Service Supervisor (`WebizenHostDaemon`)**:
  - Connect the HTTP/1.1 daemon, the live UDP RFC 1035 DNS server (`wire_dns`), and the live TCP RFC 5321 SMTP server (`smtp_mail`) to the same on-disk `HostPersistentState` (`host_state.cbor-ld`), `NQuinDnsZoneRing`, and `RelationshipScopedMailAlias` registry so Control Panel mutations take effect immediately across HTTP, DNS, SMTP, Git, and Solid.
  - Handle all 10 `POST /cpanel/*` form submissions (`application/x-www-form-urlencoded`), persisting updates to `host_state.cbor-ld` and `journal.q42j`.
- [x] **D10.7 — Container, Reverse-Proxy TLS (`Caddyfile`), & Automated Backup Scripts (`vps_deployment.rs`)**:
  - Extend `write_linux_vps_deployment_bundle` to also generate:
    - `<data_dir>/deploy/Caddyfile` (automatic HTTPS/HTTP3 reverse proxy forwarding `:443` to `127.0.0.1:4242` with strict security headers).
    - `<data_dir>/deploy/Containerfile` & `<data_dir>/deploy/docker-compose.yml` (hardened OCI container deployment).
    - `<data_dir>/deploy/backup-cron.sh` (daily ChaCha20-Poly1305 + SHA-256 verified backup script).
- [x] **D10.8 — 12-Point End-to-End VPS Readiness Verifier (`webizen-hostd --verify-vps-readiness <dir>`)**:
  - Add `--verify-vps-readiness <dir>` to `webizen-hostd` (and a callable library function `verify_full_vps_readiness(data_dir)`) that boots the live HTTP daemon, live UDP DNS server, and live TCP SMTP server on ephemeral loopback sockets, executes 12 end-to-end protocol checks (Control Panel Zero-JS HTML, CBOR-LD state, `HTTP 206` Range slice, Range-SPARQL CBOR-LD, `/cpanel/*` POST mutations, UDP RFC 1035 DNS query, TCP RFC 5321 SMTP delivery + spammer quarantine, Git Smart HTTP `info/refs` + `receive-pack`, W3C Solid LDP `PUT`/`GET`, IPFS `/ipfs/<cid>` + WebTorrent `/torrent/webseed/*`, Sanctuary Keep ChaCha20-Poly1305 + Shamir recovery, and deployment bundle audit), and writes `<data_dir>/vps_readiness_receipt.cbor-ld` (`0xD9 0x05 0x01`).
