# WP-08B: Complete cPanel / WHM Replacement Pages & Three-Persona Functional Specification

**Work Package ID:** `WP-08B` (Detailed UI/UX & Functional Page Specification for [`WP-08`](./WP-08-poet-admin-workbench-and-turnkey-installer.md))  
**Target Repositories & Crates:**  
- `webizen-host`: `crates/webizen-host-workbench/` (`src/persona_ui.rs`, `assets/index.html`)  
- `rust-app-framework`: Dioxus / Poet desktop, web (WASM), and native UI components  
- `qualiaDB`: `crates/poet/`, `crates/qualia-cli/`  

---

## 1. Architectural Overview: A Real Multi-Page Control Panel (Not a Brochure)

To replace cPanel, WHM, and Plesk in daily operation, the **Webizen-Host Workbench** is structured as a **full-screen, left-sidebar-navigated control panel application** with **8 dedicated management pages**:

1. **Domains & DNS** *(replaces cPanel Domains, Subdomains, Addon Domains & Zone Editor)*
2. **Email & Aliases** *(replaces cPanel Email Accounts, Forwarders, Email Routing, Deliverability/DKIM & Webmail)*
3. **Files, IPFS & Storage** *(replaces cPanel File Manager, Disk Usage, FTP Accounts & Git Version Control)*
4. **Ontologies & Databases** *(replaces cPanel MySQL Databases, phpMyAdmin & Remote SQL)*
5. **Apps & Solid Pods** *(replaces Softaculous, Application Manager, Node.js/PHP Selector & WP Toolkit)*
6. **SSL, Identity & Security** *(replaces cPanel SSL/TLS Status, Let's Encrypt AutoSSL, SSH Access, IP Blocker & ModSecurity)*
7. **Wallet, Exchanges & Billing** *(replaces WHMCS / Billing, Bandwidth Quota & Payment Gateways)*
8. **Jobs, Cron & Metrics** *(replaces cPanel Cron Jobs, Resource Usage, Raw Access Logs, Error Logs & Backup Wizard)*

### Persistent Global Top Bar & Persona Switcher

Every page in the control panel shares a persistent top bar containing:
- **Active Host & Pairing Status**: e.g., `ns.webcivics.net (:443 / :4242)` paired with local **Sanctuary Keep** (`:8080`).
- **Three-Persona Mode Toggle (`Novice` | `Tech Geek` | `Developer`)**:
  - Switching personas **stays on the current sidebar page** and immediately adapts the density, terminology, tables, and action tools on that page.
  - **1. Novice ("Everyday Steward & Family")**: Guided 1-click wizards, plain-English explanations, safe defaults, and automatic background handling of DNS, TLS, and peer-sharing.
  - **2. Tech Geek ("Sysadmin, Network & Multi-Chain Operator")**: Full tabular editors, DNS record tables, IPFS/WebTorrent/HTTP-206 seeding toggles, DKIM/SPF/DMARC diagnostics, multi-exchange routing books, and M-of-N quorum queues.
  - **3. Developer ("QualiaDB Engine, Range-SPARQL & Sandbox Studio")**: Direct access to 48-byte `NQuin` bit-fields, `RangeSparqlEngine` (`HTTP 206` + `BIDX` SuperBlock pruning), `PCAT` (`0x0080`) byte-range catalogues, VibeScript (`VBC1`) `u64` cycle budgets, 42 MiB `SlgArena` memory telemetry, and `ML-DSA-65` post-quantum journal receipts.

---

## 2. Page-by-Page Functional Specification Across All Three Personas

### Page 1: Domains & DNS (`ControlPanelPage::DomainsAndDns`)

| Persona Tier | Controls, Tables & Actions Shown on Page 1 |
|---|---|
| **1. Novice** | • **My Connected Websites & Domains Table**: Shows `ns.webcivics.net`, `family.webcivics.net` with green "Online & HTTPS Protected" badges.<br>• **1-Click "Add Domain or Subdomain" Wizard**: Enter domain name → automatically configures DNS, HTTPS certificate, and peer-CDN protection.<br>• **Family & Community Visibility Selector**: Simple dropdown per domain (`Public Website`, `Friends & Co-op Members Only`, `Family Only`). |
| **2. Tech Geek** | • **Full Authoritative DNS Zone Editor Table**: Add/edit/delete `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `CAA`, plus Webizen native `QRoute` (QDNF IPv6 `fd00:42::/32`), `QDid` (`did:qi` binding), and `QPolicy` records.<br>• **Split-Horizon & Protocol Listeners Bar**: Toggle `:53 UDP/TCP`, `DoH (:443)`, `DoT (:853)`, `DoQ (:853 QUIC)` and edit Split-Horizon rules (e.g., return public IP `203.0.113.42` to WAN, return WireGuard/MASQUE ULA `fd00:42::1` to authenticated guardian mesh).<br>• **DNSSEC & DANE TLSA Key Rollover Controls**. |
| **3. Developer** | • **HotZeroHeap `NQuin` DNS Ring Inspector**: Inspect the live 48-byte `NQuin` records inside `net/dns/` (`subject = q_hash(fqdn)`, `predicate = record_type_opcode`, `object = packed_ip_or_q42lex_token`, `context = SensitivityClass`, `parity = XOR`).<br>• **Zero-Allocation Lookup Benchmark Runner**: Test `O(1)` `q_hash()` resolution latency and verify `0 B` heap allocation (`AllocationClass::HotZeroHeap`). |

---

### Page 2: Email & Aliases (`ControlPanelPage::EmailAndAliases`) — Canonical `bob@alice.tld` Relationship Mail & Programmable Aliases

| Persona Tier | Controls, Tables & Actions Shown on Page 2 |
|---|---|
| **1. Novice** | • **Relationship-Centric Email (`bob@alice.tld`, `sunrise-school@alice.tld`, `clinic@alice.tld`)**: Instead of a single user inbox (`alice@alice.tld`) given to everyone, the local-part before `@alice.tld` names the **relationship / counterparty (`bob@alice.tld`)** and is locked to Bob's authorized sender address / `did:qi`. If a third party or spammer tries to email `bob@alice.tld`, it is automatically blocked at the gate and pinpoints which contact leaked the address.<br>• **1-Click Programmable & Purpose Aliases**: Create smart addresses like `receipts@alice.tld` (auto-files bills/invoices into your `.q42` Finance volume), `hello@alice.tld` (general-purpose filtered), or `burner-48h@alice.tld` (auto-expiring). |
| **2. Tech Geek** | • **Interactive SMTP/JMAP Relationship Gate Simulator & Routing Table**: Test inbound envelope evaluation (`evaluate_inbound_envelope`) across `CounterpartyRelationship` (`bob@alice.tld`), `ProgrammablePipeline` (`receipts@alice.tld`), `GeneralPurposeFiltered` (`hello@alice.tld`), and `EphemeralBurner`.<br>• **Email Deliverability & Authenticity Panel**: Live verification & 1-click regeneration of `DKIM` (Ed25519 + RSA-2048), `SPF`, `DMARC`, `ARC`, and `DANE/MTA-STS` DNS records. |
| **3. Developer** | • **N3 Relationship Whitelist & Programmable `VBC1` Hook Editor**: Edit streaming N3 rules (`=>`, `~>`, `^>`) and deterministic VibeScript (`VBC1`) hooks that evaluate incoming SMTP/JMAP envelopes against `did:qi` relationship graphs (`qualia-client-core/src/mail`) or ingest attachments directly into `.q42` volumes. |

---

### Page 3: Files, IPFS & Storage (`ControlPanelPage::FilesAndStorage`)

| Persona Tier | Controls, Tables & Actions Shown on Page 3 |
|---|---|
| **1. Novice** | • **Two Clear Folders — "Public Website Files" vs. "Private Sanctuary Keep"**: Visual file browser with drag-and-drop Upload, New Folder, Rename, Share Link, and Delete.<br>• **Automatic Safety Lock**: Anything placed in **Sanctuary Keep** shows a purple lock badge (*"Stays strictly on your local computer — blocked from public internet sharing"*).<br>• **1-Click Community Boost Toggle**: Simple switch on large public files (videos, PDFs, datasets) to share bandwidth with peers so downloads stay fast and free. |
| **2. Tech Geek** | • **Full Directory & Content-Addressed Volume File Manager**: Browse `/public_html`, `/volumes/*.q42`, `/bundles/*.hmc`, `/pods/*` with permissions, byte size, `CRC-32C`, and modification timestamps.<br>• **Per-File Multi-Protocol Seeding Matrix (`IPFS`, `IPNS`, `WebTorrent`, `HTTP 206 Range`)**: Copy or toggle `ipfs://bafkrei...`, `ipns://...`, `magnet:?xt=urn:btih:...&ws=...&xs=urn:cid:...`, and `HTTP 206 Partial Content` byte-range serving per file.<br>• **Three-Tier `Q-CDN` Swarm Seeder Table**: View active Tier-A (Co-op VPS), Tier-B (`:4242` Desktop), and Tier-C (Browser WebRTC/OPFS) seeders and ban corrupted peers. |
| **3. Developer** | • **`PCAT` (`FLAG_PAYLOAD_CATALOGUE = 0x0080`) & `QBDL` `.hmc` Binary Inspector**: Inspect exact `[offset, length, crc32c]` catalogue entries inside `.q42` v4 volumes and 64-byte `HmcHeader` (`HMC\x04`) manifold records.<br>• **Test `HTTP 206` / Partial-CAR Byte-Range Fetch (`Fetch10dService`)**: Issue a custom `Range: bytes=start-end` request and verify `SHA-256` + `CRC-32C` zero-copy slice extraction. |

---

### Page 4: Ontologies & Databases (`ControlPanelPage::OntologiesAndDatabases`)

| Persona Tier | Controls, Tables & Actions Shown on Page 4 |
|---|---|
| **1. Novice** | • **Installed Knowledge Libraries & App Databases**: Friendly list of active libraries (e.g., *WebCivics Human-Rights Dictionary*, *Family Address Book Graph*, *Community Co-op Directory*).<br>• **1-Click "Add Knowledge Library" Catalog**: Pick from curated community ontologies or paste a link → automatically checks if a verified copy is already on the network so it installs in seconds without slowing down your server. |
| **2. Tech Geek** | • **`.q42` v4 Volume & `.q42j` Journal Manager (Replaces MySQL / phpMyAdmin)**: Table of all mounted volumes, SuperBlock counts, `Q42LEX v4` dictionary sizes, and `.q42j` WAL journals.<br>• **"Verify-Before-Rebuild" & Over-Time Ontology Ingestion Pipeline (`WP-01`)**: Add any large Git/HTTP/IPFS ontology (`>100 MB` `WebCivics/ns`), inspect network peer candidate hashes (`canonical_source_sha256` + `CRC-32C` + SHACL Non-Thing check), adopt verified network artifacts in 0 CPU cycles, or configure background chunk budgets (`max_chunks_per_tick`) for incremental compilation over time. |
| **3. Developer** | • **Interactive Range-Backed SPARQL / SPARQL-Star Studio (`RangeSparqlEngine`)**: Full query editor supporting `SELECT`, `ASK`, `CONSTRUCT`, and `DESCRIBE` over local or remote `.q42` volumes via `HTTP 206` / `IPFS` range reads, displaying live **`BIDX` `FieldRangeIndex` SuperBlock pruning telemetry** (e.g., `1 / 240` 40 KiB SuperBlocks fetched = `99.58%` bandwidth saved).<br>• **48-Byte `NQuin` Bit-Field & SHACL Non-Thing Uplift Inspector**: Click any query result to inspect `subject`, `predicate` (opcode `0x10+`), `object` (60-bit `Q42LEX v4` token + inline tag), `context`, `metadata`, XOR `parity`, and verify that `NaturalAgent` / kinship classes never subclass `owl:Thing`. |

---

### Page 5: Apps & Solid Pods (`ControlPanelPage::AppsAndSolidPods`)

| Persona Tier | Controls, Tables & Actions Shown on Page 5 |
|---|---|
| **1. Novice** | • **1-Click App & Personal Storage Installer (Replaces Softaculous)**: Install *Personal & Family Solid Storage Pod*, *Poet Collaborative Notes & Wiki*, *Community Chat (`qualia-chat`)*, *ActivityPub Social Feed*, or *Static Website / Blog* in one click.<br>• **My Installed Apps Table**: Simple `Open App`, `Update`, and `Backup` buttons. |
| **2. Tech Geek** | • **Three-Tier Sandbox & Reverse-Proxy App Manager (`WP-04`)**: Manage **Tier-1** (Inline VibeScript `VBC1`), **Tier-2** (Native QApps & WASM Workers), and **Tier-3** (OCI / Linux Containers & Legacy Reverse-Proxy apps with W3C Solid LDP `:8443` + ActivityPub bridge).<br>• **Per-App Resource & Capability Policy Table**: Configure domain bindings, storage quotas, network egress permissions, and automatic version rollbacks (`q42/app_registry/`). |
| **3. Developer** | • **`qualia-app-contract` (`SDK-01..10`) Manifest & `VBC1` Bytecode Debugger**: Inspect/edit capability lease manifests (`CapabilityLease`), test deterministic `u64` cycle budget exhaustion (`FailClosed`), and inspect WASM / WGSL shader cache signatures. |

---

### Page 6: SSL, Identity & Security (`ControlPanelPage::SslIdentityAndSecurity`)

| Persona Tier | Controls, Tables & Actions Shown on Page 6 |
|---|---|
| **1. Novice** | • **Automatic HTTPS & Connection Security Status**: Green checkmarks confirming all websites and email addresses have active, auto-renewing encryption.<br>• **Pair My Computer / Phone (`:8080 ⇄ :4242`)**: 1-click pairing code / QR generator to link your home computer's **Sanctuary Keep** with your VPS.<br>• **Family Guardianship & Trusted Recovery Contacts**: Manage who can help recover your account (2-of-3 family/friends) and manage safe-space boundaries for dependent children. |
| **2. Tech Geek** | • **Dual-Authority Certificate Manager (Let's Encrypt ACME + `WebizenID-TLS` CA)**: View renewal dates, force ACME reissue, or issue `WebizenID-TLS` client/device certificates (`SAN = did:qi:...`).<br>• **M-of-N Cooperative Quorum & `SuspendedTransactionQueue` (32-Slot)**: Review and co-sign pending high-impact zone/treasury changes (`2-of-3` or `3-of-5` co-stewards).<br>• **SSH Keys, WireGuard / MASQUE (`CSCP-08`) Peers & Paraconsistent Quarantine Firewall**. |
| **3. Developer** | • **Zero-Knowledge Proof (`Groth16 over BLS12-381`) & Post-Quantum Key Inspector**: Test `deontic_access` circuit proofs, verify `Argon2id + HKDF-SHA256` (`derive_lane_key_argon2_hkdf`) Sanctuary Keep key derivation, and run the **Who-Plane Collapse Detector** (`WP-05`) across graph mutations. |

---

### Page 7: Wallet, Exchanges & Billing (`ControlPanelPage::WalletExchangesAndBilling`)

| Persona Tier | Controls, Tables & Actions Shown on Page 7 |
|---|---|
| **1. Novice** | • **Monthly Bill Shield Slider (`$0.00` Overage Guaranteed)**: Simple slider locking in your maximum monthly VPS budget (`$5/mo–$40/mo`), showing how much free community peer-sharing has saved you this month.<br>• **Simple Multi-Currency Wallet & Community Credits**: View balances and convert coins in 1 click using the best verified low-fee exchange rate. |
| **2. Tech Geek** | • **Multi-Blockchain Treasury & Payment Rail Manager (`WP-07`)**: Configure live wallets and payment channels across **`eCash (XEC)`**, **`XRP Ledger (XRP)`**, **`USDC (EVM L2)`**, **`Bitcoin Lightning (BOLT11/12)`**, **`ILP-STREAM`**, and **`QualiaPQ-Ledger`**.<br>• **Multi-Exchange Swap Desk (`MultiExchangeSwapHub`)**: Live comparison table across connected exchange sites (`NonCustodialDexAggregator`, `InstantSwapBridge`, `RegionalRegulatedFiatCryptoDesk`, `DirectAtomicCrossChain`) with automatic `check_usury` (`<= 250 bps`) enforcement.<br>• **Permissive Commons `10x` Obligation Pool & `Q-CDN` Seeder Revenue Ledger**. |
| **3. Developer** | • **Post-Quantum `.q42j` Settlement Receipt & `socioeconomics.rs` Inspector**: Inspect hybrid `Ed25519 + ML-DSA-65 (FIPS 204)` / `SLH-DSA (FIPS 205)` journal anchors (`QualiaPqJournalAnchor`), replay `CommonsObligation` Quins (`replay_obligation_pool_journal`), and verify `< 15 mJ` zero-PoW batch settlement telemetry. |

---

### Page 8: Jobs, Cron & Metrics (`ControlPanelPage::JobsCronAndMetrics`)

| Persona Tier | Controls, Tables & Actions Shown on Page 8 |
|---|---|
| **1. Novice** | • **Simple Server Health & Automatic Maintenance**: Friendly gauges for Storage Used, Monthly Bandwidth Shield, and Automatic Nightly Encrypted Backups.<br>• **Background Tasks List**: Plain-English progress of any library updates or backups running quietly in the background. |
| **2. Tech Geek** | • **Over-Time Ontology Ingestion Queue & Cron / Tick Scheduler**: Pause, resume, or adjust chunk budgets for background ontology compilation jobs, scheduled backups, and periodic peer syncs.<br>• **System Resource & Bandwidth Telemetry (`MeterKind`)**: Live CPU, RAM, NVMe I/O, Origin Egress vs. `Q-CDN` Offloaded Bytes, and system service status (`:53`, `:443`, `:4242`, `:8443`). |
| **3. Developer** | • **42 MiB `SlgArena` Sentinel Profiler & Deterministic 20 Hz Tick Inspector**: Live per-tenant `SlgArena` slot utilization (`917,504` max `NQuin` slots), Tier-1 `HotZeroHeap` allocation counter (`0` heap allocs), Tier-2 `ColdBounded` 256 MiB workspace arena high-water mark, and cryptographically signed `.q42j` audit trail viewer. |

---

### Page 9: Social-Web / P2P Resource Delegation Permits & Priority Budgets (`ControlPanelPage::ResourceDelegationAndBudgets`)

| Persona Tier | Controls, Tables & Actions Shown on Page 9 |
|---|---|
| **1. Novice** | • **Share My Spare Server Power with Family & Co-op Friends**: Simple sliders and 1-click toggles to grant trusted friends, family members, or community groups a slice of spare **Compute**, **Bandwidth**, or **Backup Storage**.<br>• **Automatic Priority Protection**: Plain-language guarantee that **Family & Emergency (`P0`)** always gets 100% priority—if your server gets busy, guest/community tasks automatically slow down first so your own apps never lag. |
| **2. Tech Geek** | • **Delegated Resource Permit Table (`DelegatedResourcePermit`)**: Issue, edit, or revoke per-peer `Compute`, `Bandwidth`, and `Storage` permits bound to `did:qi` identities with epoch quotas and expiry timestamps.<br>• **Four-Tier Priority & Budget Load-Shedding Matrix (`P0`..`P3`)**: Configure automatic host budget saturation thresholds (`P0 Guardianship/Emergency <= 100%`, `P1 Trusted Social/Co-op Peer <= 95%`, `P2 Federated Commons <= 80%`, `P3 Public Best-Effort <= 50%`) and simulate load-shedding under traffic spikes. |
| **3. Developer** | • **48-Byte `NQuin` Deontic Permit & `DEFEATER_BIT` (`1 << 63`) Inspector**: Inspect compiled `OP_PERMIT (0x11)` and `OP_FORBID (0x12)` resource delegation Quins (`resource_delegation.rs`), test `HotZeroHeap` `evaluate_and_consume_zero_heap`, and author linear-logic (`-o`) N3 budget consumption rules. |

---

### Page 10: Webizen Git Forge (`Q-Git` — Full Decentralized GitHub Alternative) (`ControlPanelPage::GitForgeAndRepositories`)

| Persona Tier | Controls, Tables & Actions Shown on Page 10 |
|---|---|
| **1. Novice** | • **1-Click Project & Ontology Repository Creator**: Create a public, co-op, or private family repository in one click, browse files and `README.md`, or mirror an existing Git project.<br>• **Automatic Community Backup & Sharing**: Public projects are automatically shared across peers so anyone can download your code or ontology without costing you bandwidth. |
| **2. Tech Geek** | • **Full Git Forge UI (Repositories, File Tree, Branches, Commits, Pull Requests, Issues & Releases)**:<br>  - Clone over **Smart HTTPS**, **SSH (`git@domain:owner/repo.git`)**, **IPFS (`ipfs://bafkrei...`)**, and **WebTorrent Magnet (`ws=` HTTP 206 WebSeed)**.<br>  - **Pull Requests with M-of-N Cooperative Quorum Merge Gates**: Require e.g. `2-of-3` co-steward `did:qi` approvals + passing CI before a PR can merge.<br>  - **Federated Issues (`ForgeFed` / ActivityPub)** & **Sandboxed CI Actions** running on delegated P2P compute permits. |
| **3. Developer** | • **Automated SHACL Non-Thing & Nomenclature CI Gate + `.q42j` Contributor Value-Flow Provenance**: Inspect live PR diff AST checks (blocking `rdfs:subClassOf owl:Thing` or forbidden nomenclature), trigger automatic `.q42` v4 ontology uplift on `git push`, and inspect the 48-byte `NQuin` contributor receipt emitted into the `.q42j` Permissive Commons Obligation Pool (`WP-07`) upon PR merge. |

