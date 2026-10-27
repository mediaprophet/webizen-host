# WP-09 (P0): Production VPS Deployment To-Do List & 4-Swarm Implementation Plan

**Work Package ID:** `WP-09`  
**Priority:** `P0` (Mandatory Pre-Deployment Completion Gate for Live Linux VPS Hosting)  
**Target Repository:** `C:\github\webizen-host`  
**Nomenclature Invariant:** Strictly Human-Centric / International Human-Rights terminology (zero use of prohibited terms).  
**Native Wire Format:** W3C CBOR-LD (`application/cbor-ld`, Tag `0xD90501`) and `.q42` v4 binary `NQuin` slices.

---

## 1. Comprehensive VPS Deployment Gap Analysis & To-Do Checklist

Before `webizen-host` can be deployed as a live internet-facing VPS replacing cPanel, GitHub, and commercial CDNs, the following **4 Production Subsystems (20 concrete deliverables)** must be implemented with real wire protocols, real on-disk persistence, and end-to-end socket tests:

### Swarm 1 — RFC 1035 Wire-Format DNS Server (`:53`) & ACME / `WebizenID-TLS` Provisioner (`webizen-host-dns`)
- [x] **D1.1 — RFC 1035 Binary DNS Packet Parser & Builder (`wire_dns.rs`)**:
  - Parse standard 12-byte RFC 1035 DNS headers, QNAME label compression (`0xC0` pointers), `QTYPE` (`A=1`, `NS=2`, `CNAME=5`, `SOA=6`, `MX=15`, `TXT=16`, `AAAA=28`, `SRV=33`, `CAA=257`), and `QCLASS` (`IN=1`) in zero/bounded stack memory.
  - Serialize authoritative DNS response packets (`QR=1, AA=1, RCODE=0` or `NXDOMAIN=3` / `REFUSED=5` when `SplitHorizonFirewall` blocks an internal-only record) directly from `DnsZoneTable` `NQuin` records.
- [x] **D1.2 — Live UDP DNS Socket Responder (`serve_udp_dns_once` / `spawn_udp_dns_server`)**:
  - Bind a real `std::net::UdpSocket` (`127.0.0.1:0` in tests, `:53` in production), process binary RFC 1035 UDP queries through `SplitHorizonFirewall` and `DnsZoneTable`, and return wire-valid DNS answers.
- [x] **D1.3 — ACME (`RFC 8555` HTTP-01 & DNS-01) Challenge Engine & `WebizenID-TLS` Certificate Generator (`acme_tls.rs`)**:
  - Compute RFC 8555 JWK thumbprints, HTTP-01 key authorizations (`token.base64url(sha256(jwk_thumbprint))` served at `/.well-known/acme-challenge/<token>`), and DNS-01 `_acme-challenge.<domain>` `TXT` digests (`base64url(sha256(key_auth))`).
  - Generate deterministic `WebizenID-TLS` X.509v3 / PEM certificate bundles binding the steward's `did:qi` identity and domain SANs, persisted to `<data_dir>/tls/<domain>.pem`.

### Swarm 2 — Live SMTP (`:25`/`:587`) Server, DKIM (`RFC 6376`) Signer/Verifier & On-Disk Maildir Spool (`webizen-host-workbench/src/smtp_mail.rs`)
- [x] **D2.1 — RFC 5321 SMTP Wire Protocol State Machine & Live TCP Server**:
  - Implement a real SMTP state machine (`220 <domain> ESMTP Webizen-Host`, `EHLO`, `MAIL FROM:<...>`, `RCPT TO:<...>`, `DATA ... \r\n.\r\n`, `QUIT`) over `std::net::TcpListener`.
  - At `RCPT TO` / `DATA`, enforce the `bob@alice.tld` counterparty lock (`RelationshipScopedMailAlias::evaluate_inbound_envelope` + VibeScript `web.route_mail`):
    - Authorized counterparty → `250 2.1.5 Ok` + spool to disk.
    - Unauthorized sender to `bob@alice.tld` → `550 5.7.1 Relationship alias bob@alice.tld locked to counterparty; leak source pinpointed: bob` + append quarantine `NQuin` to `.q42j`.
- [x] **D2.2 — RFC 6376 DKIM Signer & Verifier + SPF/DMARC Record Synthesizer**:
  - Compute `relaxed/relaxed` body hash (`bh=`) using FIPS 180-4 SHA-256 and sign/verify `DKIM-Signature` headers.
  - Generate authoritative SPF (`v=spf1 mx -all`), DKIM (`v=DKIM1; k=ed25519; p=...`), and DMARC (`v=DMARC1; p=reject`) DNS `TXT` records for every hosted domain.
- [x] **D2.3 — On-Disk Maildir Spool & CBOR-LD Envelope Index**:
  - Persist delivered messages to `<data_dir>/mail/<domain>/<local_part>/<msg_sha256>.eml` alongside a W3C CBOR-LD (`0xD90501`) metadata receipt (`<msg_sha256>.cbor-ld`) and support listing/reading messages for Webmail/JMAP.

### Swarm 3 — On-Disk Git Object/Pack Store & Git Smart HTTP (`git-upload-pack` / `git-receive-pack`) (`webizen-host-workbench/src/git_smart_http.rs`)
- [x] **D3.1 — On-Disk Bare Git Repository Layout & Content-Addressed Object Store**:
  - Create real bare repository directories on disk (`<data_dir>/git/<repo>.git/{HEAD, config, refs/heads/main, objects/, bundles/}`).
  - Store and retrieve content-addressed Git objects (`blob`, `tree`, `commit`) with SHA-256 content hashes and verify integrity on read.
- [x] **D3.2 — Git Smart HTTP Pkt-Line Protocol (`info/refs`, `git-upload-pack`, `git-receive-pack`)**:
  - Implement RFC-compliant Git 4-hex-digit pkt-line framing (`encode_pkt_line`, `decode_pkt_lines`, flush packet `0000`).
  - Serve `GET /git/<repo>.git/info/refs?service=git-upload-pack` (`application/x-git-upload-pack-advertisement`) and `GET /git/<repo>.git/info/refs?service=git-receive-pack` (`application/x-git-receive-pack-advertisement`).
  - Handle `POST /git/<repo>.git/git-receive-pack` gated by the M-of-N Steward Quorum and SHACL Non-Thing / Human-Centric Nomenclature CI checks, updating `refs/heads/main`, exporting a P2P `.bundle` (`MultiProtocolShareDescriptor` for IPFS + WebTorrent + HTTP 206), and appending a contributor provenance `NQuin` to `<data_dir>/journal.q42j`.

### Swarm 4 — Persistent Host State (`host_state.cbor-ld`), Full 10-Module HTTP Daemon Routes, Turnkey Linux VPS Installer & CLI (`webizen-host-workbench`)
- [x] **D4.1 — On-Disk Persistent Host Configuration (`vps_deployment.rs`)**:
  - Persist and reload hosted domains, DNS zones, `bob@alice.tld` relationship mail aliases, P2P resource delegation permits, Git repositories, and Commons Obligation Pools in `<data_dir>/host_state.cbor-ld` (`0xD9 0x05 0x01` W3C CBOR-LD header + SHA-256 integrity seal).
- [x] **D4.2 — Production Linux VPS Provisioning Bundle Generator (`<data_dir>/deploy/`)**:
  - Generate verified deployment artifacts on `--init-vps`:
    - `webizen-hostd.service` (hardened `systemd` service unit with `ProtectSystem=strict`, `NoNewPrivileges=true`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`).
    - `nftables-qpolicy.conf` (firewall rules enforcing Sanctuary Keep `:8080` isolation and rate-limiting `:53`, `:80`, `:443`, `:25`, `:4242`).
    - `install-vps.sh` (idempotent Ubuntu/Debian setup script).
- [x] **D4.3 — Full Live HTTP Daemon Routes (`http_daemon.rs`) & CLI (`webizen-hostd.rs`)**:
  - Upgrade `WebizenHostDaemon` to serve all live endpoints over TCP:
    - `GET /` & `GET /cpanel` (10-page Zero-JS Control Panel executed via `vibe`)
    - `GET /health` (CBOR-LD health & subsystem readiness receipt)
    - `GET /api/state.cbor-ld` (Zero-heap 74-byte CBOR-LD state `NQuin`)
    - `GET /.well-known/acme-challenge/<token>` (ACME HTTP-01 challenge responder)
    - `GET /ns/<term>` (Content-negotiated Virtual Namespace: `application/q42`, `application/cbor-ld`, `application/n-triples`, `text/turtle`, `text/html` + Hard Egress Circuit Breaker `HTTP 307`)
    - `GET /volumes/core.q42` (`HTTP 206 Partial Content` byte-range serving from disk)
    - `POST /sparql` (On-disk `RangeSparqlEngine` returning `application/cbor-ld`)
    - `POST /mail/evaluate` & `POST /cpanel/email/add` (Relationship mail gate + persistent alias creation)
    - `POST /permit/evaluate` & `POST /cpanel/delegation/issue` (P2P resource permit gate + persistent permit issuance)
    - `GET /git/<repo>.git/info/refs` & `POST /git/<repo>.git/git-receive-pack` (Git Smart HTTP + quorum/CI gate)
  - Support `webizen-hostd --init-vps <dir>`, `webizen-hostd --check-config <dir>`, and `webizen-hostd --serve <dir>` in `src/bin/webizen-hostd.rs`.
