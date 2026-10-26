# Webizen & QualiaDB Human-Centric VPS Hosting Platform (`webizen-host`)

Turnkey Linux VPS hosting platform, cPanel/WHM replacement, and online extension relay (`:8080` ↔ `:4242`) engineered on the **QualiaDB `0.0.40`** and **Webizen** stack.

## Architecture & Crate Layout (`WP-01` – `WP-08`)

- [`crates/webizen-host-core`](crates/webizen-host-core) — Universal 48-byte `NQuin` ABI, compile-time/runtime 64-bit FNV-1a `q_hash()`, 60-bit masked tokens, Human-Centric / International Human-Rights nomenclature guards, and SHACL-first non-`owl:Thing` class enforcement.
- [`crates/webizen-host-ingest`](crates/webizen-host-ingest) (**WP-01**) — Tier 2 `ColdBounded` (256 MiB budget) streaming compiler for `>100 MB` [`WebCivics/ns`](https://github.com/WebCivics/ns), `IngestMode::Complete` + `Q42LEX v4` paged lexicon, SHACL-first non-`owl:Thing` uplift, `FLAG_PAYLOAD_CATALOGUE` (`0x0080`), 40 KiB `QualiaSuperBlock`s, and 64-byte page-aligned `QBDL` `.hmc` hypermedia bundles.
- [`crates/webizen-host-namespace`](crates/webizen-host-namespace) (**WP-02**) — Zero-allocation (`HotZeroHeap`) Content-Negotiated Virtual Namespace Server (`ns.webcivics.net` v2) serving binary `.q42`, standard W3C RDF formats, and `webizen-lite-wasm` (640 KiB) with a Hard Origin Egress Byte & Dollar Circuit Breaker (`$0.00` overage).
- [`crates/webizen-host-dns`](crates/webizen-host-dns) (**WP-03**) — $O(1)$ `q_hash()` 48-byte `NQuin` DNS zone ring, `QPolicy` in-flight deontic split-horizon DNS firewall, Dual-Stack QDNF (`QRoute` Ed25519 → ULA IPv6 `fd00::/8`, `QResolve`), and two-host `CSCP-08` / `CSCP-09` Internet qualification.
- [`crates/webizen-host-sandbox`](crates/webizen-host-sandbox) (**WP-04**) — Three-Tier Multi-Tenant Sandbox (`HostSandboxManager`): Tier 1 VibeScript (`VBC1` `u64` cycle budgets + 42 MiB `SlgArena` cells + fail-closed capability leases), Tier 2 Portable QApps (`SDK-01..10`) & WASM isolates, and Tier 3 W3C Solid LDP Pod bridge (`web.civics.au`) + Linux/eBPF socket quotas.
- [`crates/webizen-host-stewardship`](crates/webizen-host-stewardship) (**WP-05**) — Who-Plane (`NaturalAgent` / `did:qi`) ≠ Handle-Plane (`DNI` / DNS / ABN) separation & `Collapse Detector`, Church (`Sanctuary Keep` local hardware) & State (`PermissiveCommonsTech` VPS) separation with client-encrypted `.q42j` Shamir backups, and Single Person, Family (`GuardianshipSemantics`), Multi-Person Cooperative (`M-of-N` `SuspendedTransactionQueue` + paraconsistent conflict retention), and Governed Service/AI Agent modes.
- [`crates/webizen-host-qcdn`](crates/webizen-host-qcdn) (**WP-06**) — Three-Layer User-Powered Decentralized CDN (`Q-CDN` Swarm: `<10 KiB` signed Root Index, Cooperative VPS Mirrors, `webizen-desktop` `:4242` WebTorrent seeders, Browser OPFS + WebRTC DataChannels) with CRC-32C / content-hash chunk verification.
- [`crates/webizen-host-economics`](crates/webizen-host-economics) (**WP-07**) — Two-Loop Permissive Commons (`value_flow.rs`) persisted in `.q42j` with automatic `10x` Commons Sunset (`EnforcePermissiveCommons`), 0% royalty for `NaturalAgent` & Humanitarian ICT, Multi-Blockchain Settlement Router (`XEC`, `XRP`, `USDC`, `BTC-LN`, `ILP-STREAM`), Multi-Exchange Coin Swap Hub (`ExchangeQuote` + `check_usury` fee guard), and Energy-Cheap (`<1 Joule` zero-PoW BFT), Post-Quantum-Secure (`ML-DSA-65` / `SLH-DSA`) Native Ledger (`QualiaPQ-Ledger`).
- [`crates/webizen-host-workbench`](crates/webizen-host-workbench) (**WP-08**) — Human-Centric Poet Host Admin Workbench organized around Webizen's Six Life Domains (`Memory · Relations · Care · Practice · World · Instruments`), Relationship-Scoped Mail, and Turnkey Linux VPS Installer.

## Documentation & Implementation Plan

- [Master Implementation Plan (`dev-docs/implementation-plan/00-MASTER-IMPLEMENTATION-PLAN.md`)](dev-docs/implementation-plan/00-MASTER-IMPLEMENTATION-PLAN.md)
- [Architecture Specification (`dev-docs/webizen_qualiadb_vps_hosting_specification.md`)](dev-docs/webizen_qualiadb_vps_hosting_specification.md)
- [Project Definitions (`dev-docs/project definitions.md`)](dev-docs/project%20definitions.md)
