# WP-08 (P1/P2): Poet Host Admin Workbench & Turnkey Linux VPS Installer

**Work Package ID:** `WP-08`  
**Priority:** `P1/P2`  
**Depends On:** [`WP-04`](./WP-04-native-qapp-runtime-and-three-tier-sandbox.md), [`WP-07`](./WP-07-permissive-commons-micropayments-and-dlt.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/poet/`, `crates/qualia-cli/`, `crates/qualia-client-core/src/mail/`, `crates/qualia-core-db/src/crypto/`  
- `rust-app-framework`: Dioxus / Poet desktop, web (WASM), and native UI components  
- `webizen-host`: `crates/webizen-host-ui/`, `crates/webizen-host-installer/`  

---

## 1. Objective & Problem Statement

To replace legacy control panels (cPanel, WHM, Plesk) completely, `webizen-host` requires a human-centric administrative interface designed for human beings, families, and cooperative groups first—alongside a single-command turnkey installer that provisions a clean Linux VPS in under 5 minutes.

**WP-08** builds the **Poet Host Admin Workbench** organized around Webizen's Six Life Domains (**`Memory · Relations · Care · Practice · World · Instruments`**) inside Poet / Dioxus (compiling to desktop, mobile, and browser WASM), and packages the turnkey **`qualia-cli host init/install --profile=vps-human-centric`** provisioning tool.

---

## 2. cPanel-Parity Feature Matrix & Poet Workbench Implementation Map

| Legacy cPanel / WHM Feature | `webizen-host` Subsystem (Life Domain) | Underlying QualiaDB Modules & UX Deliverables |
|---|---|---|
| **Addon Domains, Subdomains & DNS Zone Editor** | **World & Realm Domain Manager** (`World`) | Visual wizard to attach ICANN domains/subdomains (`handle-plane`), auto-configure NS/glue/DNSSEC/DANE records in `net/dns/`, bind `did:qi` handles, and toggle 1-click `Q-CDN` seeding. |
| **AutoSSL / Let's Encrypt & TLS Manager** | **Dual-Authority Crypto Manager (`WebizenID-TLS` + ACME)** (`Instruments`) | Automates Let's Encrypt TLS certs for standard browsers while operating a **WebizenID-TLS CA** issuing Ed25519 + ML-KEM-768 client/device certs (SAN bound to Webizen RDF/DID endpoint) and `Groth16 over BLS12-381` (`crypto/` `deontic_access` circuit) ZKP standing proofs. |
| **Email Accounts, Forwarders, Webmail & Spam** | **Relations Domain Mail & Relationship-Scoped Aliases** (`Relations`) | Full custom-domain mail (`@yourdomain.tld`) backed by `qualia-client-core/src/mail` and `did:qi` mailbox binding. Implements **relationship-scoped email delegation** (unique address per contact/relationship, whitelisted via N3 ontology rules to eliminate spam and correlation). |
| **Softaculous / Node / PHP App Installer** | **Native QApp, Poet & VibeScript Registry** (`Practice`) | 1-click deployment and versioning (`q42/app_registry/`) of portable QApps (`qualia-app-contract`), Poet workspaces, `qualia-chat` DAG instances, 3D/10D `.hmc` portals, and W3C Solid Pods. |
| **MySQL / PostgreSQL / phpMyAdmin** | **QualiaDB Multi-Volume & SPARQL/N3 Studio** (`Memory`) | Manage `.q42` v4 volumes, `.q42j` journals, and 1-click Git ontology imports (`WebCivics/ns`), plus visual SPARQL-Star, N3 rule authoring (`=>`, `~>`, `^>`, `-o`), and SHACL validation panels. |
| **File Manager & FTP / SFTP** | **Hypermedia Bundle (`.hmc` / `.10d`) & Solid Explorer** (`Memory` / `World`) | Drag-and-drop management of `QBDL` `.hmc` bundles, `.10d` spatial assets, `.p64` weights, and Solid LDP folders with automatic EXIF/WAV provenance sidecars and `asset_envelope/` license checks. |
| **Cron Jobs & Background Workers** | **Bounded Tick, Agent & Swarm Scheduler** (`Instruments`) | Schedule deterministic 20 Hz world ticks (`simulation/fixed_tick.rs`), governed `agent_runtime/` workflows, periodic ontology syncs, and `services/swarm/` verify-before-pay compute jobs. |
| **Metrics, Bandwidth Logs, Billing & Backups** | **Hard Cost-Cap HUD, Commons Value-Flow & Shamir Backup Wizard** (`Care`) | Real-time telemetry of `MeterKind::{Bytes, EnergyJoules, Time, Compute}` per sandbox with a physical-style slider to lock in a **hard monthly dollar/egress ceiling**, live `Q-CDN` micropayment earnings, and M-of-N Shamir `.q42j` recovery wizard. |

---

## 3. Step-by-Step Implementation Tasks

### Task 8.0: Three-Persona Progressive-Disclosure UX (`Novice`, `TechGeek`, `Developer`)
1. Implement `AdaptiveHostWorkbench` and `UserPersonaTier` (`crates/webizen-host-workbench/src/persona_ui.rs` + `assets/index.html`) so that three distinct user groups share one unified state engine while seeing an interface tailored to their exact comfort level:
   - **Group 1 — `UserPersonaTier::Novice` ("Everyday Steward & Family View")**:
     - Zero technical jargon; plain-language cards and 1-click wizards.
     - **Monthly Bill Shield Slider**: Interactive `$5/mo–$40/mo` flat VPS ceiling with guaranteed `$0.00` overage (automatically shifts excess download traffic to peer-to-peer sharing at 80% utilization).
     - **Private Contact Email Aliases (`Relationship-Scoped Mail`)**: 1-click generator creating unique `rel-<contact>@yourdomain.tld` addresses with 1-click revoke.
     - **1-Click Knowledge & App Library**: Automatically adopts verified `.q42` v4 network copies ("Verify-Before-Rebuild") so novices never wait for heavy ontology compilation.
     - **Family Guardianship & Sanctuary Keep Badge**: Clear visual confirmation that personal/family private records stay strictly on the local device (`:8080`) and child/dependent spaces are protected by Guardianship & Capacity rules.
   - **Group 2 — `UserPersonaTier::TechGeek` ("Network, IPFS/CDN & Multi-Chain Operator View")**:
     - Protocol-level operational controls and telemetry.
     - **"Verify-Before-Rebuild" & Incremental Ontology Pipeline Monitor**: Inspect network peer `SHA-256` / `CRC-32C` / `Q42LEX v4` / SHACL Non-Thing verification status and step through resumable 42 MiB `SlgArena` background chunks.
     - **Multi-Protocol Seeding (`IPFS CIDv1`, `IPNS`, `WebTorrent`, `HTTP 206 Range`)**: Inspect live `ipfs://`, `ipns://`, `magnet:?xt=...&ws=...&xs=urn:cid:...`, and `HTTP 206` 40 KiB `QualiaSuperBlock` slice endpoints.
     - **Multi-Blockchain & Multi-Exchange Swap Hub**: Configure `eCash (XEC)`, `XRPL (XRP)`, `USDC (EVM L2)`, `Bitcoin Lightning`, `ILP-STREAM`, and `QualiaPQ-Ledger` alongside `MultiExchangeSwapHub` quotes with live `check_usury` (`<= 250 bps`) verification.
     - **QDNF Overlay, 48-Byte `NQuin` DNS Ring & M-of-N Cooperative Quorum**: Manage `fd00:42::/32` ULA IPv6, Split-Horizon `QPolicy` DNS rules, and 32-slot `SuspendedTransactionQueue` co-steward ratifications.
   - **Group 3 — `UserPersonaTier::Developer` ("Range-SPARQL, 48-B NQuin ABI & Sandbox Studio")**:
     - Deep engine diagnostics and authoring studio.
     - **Interactive Range-Backed SPARQL / SPARQL-Star Studio (`RangeSparqlEngine`)**: Execute `SPARQL 1.1` / `SPARQL-Star` queries over local or remote `.q42` v4 volumes with live `BIDX` `FieldRangeIndex` range-pruning telemetry (showing `1/240` 40 KiB `QualiaSuperBlock` slices fetched via `HTTP 206` / `IPFS` instead of downloading full multi-megabyte files).
     - **48-Byte `NQuin` Bit-Field & `Q42LEX v4` Inspector**: Inspect `subject`, `predicate` (opcode + property hash), `object` (60-bit `Q42LEX v4` token + inline type tag), `context` (Sensitivity class), `metadata` (`PermissiveRoutingLane` + Lamport clock), and live XOR `parity` (`S ^ P ^ O ^ C`).
     - **42 MiB `SlgArena` Sentinel, VibeScript (`VBC1`) `u64` Cycle Profiler & Post-Quantum `ML-DSA-65` Receipt Verifier**.

### Task 8.1: Poet Host Admin Workbench (Dioxus / Poet Native + WASM UI)
1. Implement the six life-domain workbench views in `crates/poet/` and `webizen-host-ui/` conforming to `crates/qualia-app-contract` (`SDK-01..10`):
   - **Stewardship & Quorum Bar**: Displays active stewardship mode (Single Natural Person, Family Guardianship, or M-of-N Cooperative Quorum) and pending transactions in the 32-slot `SuspendedTransactionQueue` (`WP-05`) awaiting co-steward ratification or paraconsistent conflict review.
   - **Ontology & Namespace Studio**: 1-click trigger and live progress monitor for `WP-01` cold-path compilation of `https://github.com/WebCivics/ns` (>100 MB) and virtual namespace status (`WP-02`).
   - **Relationship-Scoped Mail Manager**: Visual relationship graph binding custom-domain email aliases to specific `did:qi` contacts and N3 whitelist rules (`qualia-client-core/src/mail`).
   - **Hard Cost-Cap & Commons Value-Flow HUD**: Interactive slider configuring `meters.rs` monthly byte/dollar ceilings (`$0.00` permitted overage), Loop 1 `10x` Obligation Cost recovery progress bar, and Loop 2 `Q-CDN` seeder earnings ledger.

### Task 8.2: Turnkey 1-Command Linux VPS Installer (`qualia-cli host init / install`)
1. Implement `qualia-cli host init --profile=vps-human-centric` and `qualia-cli host install`:
   - Support modern Linux VPS targets (Debian, Ubuntu, Alpine, NixOS on `x86_64` and `aarch64`, 2 vCPU / 4 GB RAM baseline, with automatic detection of NVMe/ZNS storage and optional Vulkan/WebGPU compute adapters).
   - Provision unprivileged system user, `/var/lib/qualia/` content-addressed volume directories, systemd/OpenRC service units, eBPF socket filter attachments, `:53`/DoH/DoT/DoQ DNS listeners, `:443` HTTPS/QUIC + `WebizenID-TLS`/ACME authority, and `:4242` `PeerHost` / `Q-CDN` daemon.
   - Output a pairing QR code / `did:qi` invitation token so the operator can pair their local `webizen-desktop` (`:8080`) or open the Poet Host Admin Workbench in under 5 minutes.

---

## 4. Verification & Exit Evidence

- [ ] **Under-5-Minute Turnkey Provisioning Test**: Running `qualia-cli host install --profile=vps-human-centric` on a clean Linux VPS provisions the complete stack (daemon, `NQuin` DNS, `WebizenID-TLS`, Solid LDP bridge, and Poet Admin UI) in `< 5 minutes`.
- [ ] **End-to-End Operator Workflow Receipt**: Through the Poet Host Admin Workbench, a human steward (or M-of-N cooperative quorum) attaches a domain, provisions a relationship-scoped email alias, imports `WebCivics/ns` (>100 MB), locks in a hard monthly egress cost cap, and verifies a signed acceptance receipt on both the VPS and paired `webizen-desktop` client.
