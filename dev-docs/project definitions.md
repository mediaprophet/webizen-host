The webizen web-host server stack

The stack is designed for installation on VPS services and/or as an extension to a locally installed webizen-desktop / qualiadb install.

It needs to replace cpanel and similar, which means it needs to have all the functionality provided by those alternatives.  It should do this in a manner that both utilises qualiadb and then also acts to improve the stack, as a consequence of doing the work.

Qualiadb also has a range of ‘permissive commons’ and networking (qdnf stack) and an array of foundational ontological hosting and access needs that are currently unmet.

I’ve had problems with [ns.webcivics.net](http://ns.webcivics.net) where i’ve struggled to fund the hosting costs. This is in-turn intended to address that, and other issues.

It should produce a form of CDN that’s based on users, and then distribute micropayments if possible. We also need to look at how to support some sort of blockchain solution, whether it be by forking an existing solution or otherwise. 

# **Webizen and QualiaDB Human-Centric VPS Hosting Platform (webizen-host): Comprehensive Requirements, Architecture and Implementation Specification**

**Document ID:** SPEC-WEBIZEN-VPS-0.0.40  
**Date:** October 26, 2026  
**Baseline Stack:** [QualiaDB 0.0.40-dev](https://github.com/mediaprophet/qualiaDB/tree/0.0.40-dev) / [Webizen 0.0.39–0.0.40](https://webizen.au/) / [Poet](https://webizen.au/release-matrix.html) / [QDNF](https://webizen.au/qdnf.html)  
**Target Environments:** Commodity Linux VPS (Standalone Host and cPanel Replacement) and Online Extension Relay for Local webizen-desktop / qualiadb Installations (port 8080 to port 4242\)

# **1\. Executive Summary and Core Objectives**

Operating foundational ontological infrastructure and human-centric web services on conventional cloud platforms exposes independent stewards to unbounded financial liability and architectural lock-in. The operational history of [ns.webcivics.net](https://ns.webcivics.net/)—which serves machine-readable human rights instruments coupled with formal deontic and defeasible logic—demonstrated three acute failure modes of legacy infrastructure:

* **The Over-100 MB Ontology Import and Consumption Barrier**: Standard cloud repositories, triple stores, and browser environments fail when importing or parsing massive ontological source repositories exceeding 100 MB such as [WebCivics/ns](https://github.com/WebCivics/ns). Serving raw RDF/XML, Turtle, or OWL files forces clients to download monolithic dumps, preventing mobile and in-browser execution and inflating bandwidth consumption.  
* **Uncapped Cloud CDN Egress Liability**: Commercial content delivery networks (such as AWS CloudFront) provide no protocol-level cost circuit breaker when high-volume automated traffic spikes arrive from major US data hubs, turning public-good knowledge stewardship into an uncapped personal financial liability.  
* **Inadequacy of Legacy Control Panels (cPanel, WHM, Plesk)**: Legacy hosting stacks are built around monolithic LAMP/Docker architectures, treat ICANN DNS domains as the root of human identity, lack deterministic capability sandboxing, and cannot natively index, reason over, or stream 48-byte semantic graph records (NQuins).

The **Webizen Web-Host Server Stack (webizen-host)** is a turnkey Linux VPS hosting platform and full cPanel replacement engineered natively on the [QualiaDB and Webizen stack](https://webizen.au/), as audited against the [QualiaDB Capability Reference (0.0.40)](https://docs.google.com/document/d/1kKTwYKm9G333hKjclleAhwx2O-hVjv_v6htm_IL2kf8/edit). Building and operating the hosting platform directly utilizes qualia-core-db, qualia-client-core, vibe, qualia-peer, qualia-solid-bridge, and qualia-cooperative-core—and actively closes the remaining integration and network-qualification gaps in the core QualiaDB monorepo.

# **2\. Deployment Topologies and Stack-Improvement Symbiosis**

In alignment with the two-repo boundary defined in [WEBIZEN\_REORG\_NOTES.md](https://docs.google.com/file/d/1u9sxtc0QU6-1aeLiol2JqPsqF10lzwKN/view) and the [Qualia, Webizen, Poet Release Matrix](https://webizen.au/release-matrix.html), webizen-host consumes qualia-core-db and qualia-client-core directly without re-implementing engine logic in presentation layers.

## **2.1 Mode A: Standalone Human-Centric VPS Host**

Installed on any standard Linux VPS (Debian, Ubuntu, Alpine, or NixOS on x86\_64 or ARM64; 2 vCPU / 4 GB RAM baseline, scaling to dedicated NVMe/ZNS storage and optional Vulkan/WebGPU compute adapters per [Optimizing WGPU for AI and QualiaDB](https://docs.google.com/document/d/1MzQRXk2l0-Eji_h48uC08XYWMvyjfuzU-qoWmT-7bnU/edit)). A single CLI command (qualia-cli host init \--profile=vps-human-centric) provisions:

* **The Native Daemon (services/daemon.rs on port 4242 and HTTPS/QUIC port 443\)**: Manages .q42 v4 volumes, QBDL .hmc bundles, 42 MiB SlgArena Sentinel logic workers, and the qualia-solid-bridge W3C Solid/LDP pod server (as deployed on [web.civics.au](https://web.civics.au/)).  
* **The QDNF / QPR Edge Router**: Runs the native Qualia Peer Runtime (crates/qualia-peer PeerHost), CSCP control plane (Wave 0–1 fail-closed TLV codec, mailbox leases, receipts), and public transition bearers (WireGuard SocialWebNet, TLS WSS, HTTP/2 Extended CONNECT, and CSCP-08 public MASQUE bound-UDP relay endpoints).  
* **The Ontology Ingestion and Build Worker**: Executes bounded cold-path compilation of massive external git/HTTP ontology repositories (starting with [WebCivics/ns](https://github.com/WebCivics/ns)) into segmented .q42 and .hmc distributions.

## **2.2 Mode B: Online Extension Relay to Local webizen-desktop / qualiadb**

As outlined in the [Webizen 3.0 Host Service Requirements](https://devdocs.webizen.org/WebizenTechStack/Webizen3.0/HostServiceRequirements/), [Webizen Pro](https://devdocs.webizen.org/WebizenTechStack/Webizen3.5/WebizenProSeries/WebizenPro/), and [Webizen Desktop Application Requirements](https://docs.google.com/document/d/1B2Zz1MqZKJgqWtKPxPqDD4_LFIAJt1CXYHWb9utrj5E/edit), a VPS instance can pair cryptographically with a locally installed webizen-desktop / qualiadb environment (running on port 8080):

* **Cryptographic Pairing and Device Delegation**: Uses PeerHost::pair and did:qi mutual authentication (post-quantum ML-KEM-768 handshakes in net/qdnf/crypto/handshake/ plus Ed25519 signatures) to delegate a subdomain/hostname (mylaptop.mydomain.tld) and issue WebizenID-TLS client certificates.  
* **Strict "Church and State" Database Separation**: Enforces the foundational architecture described in [DRAFT: Guide For Developers](https://devdocs.webizen.org/GuideForDevelopers/):  
  * **The "Church" Database (TheWebizenAgent / Sanctuary Keep)**: Stores deeply private personal information—biographical history, health/pathology records (wellfare-core), and internal unshared thought/consciousness artifacts—strictly on the user's local device outside OS cloud-synced folders, protecting Freedom of Thought and Safety Protocols.  
  * **The "State" Database (PermissiveCommonsTech on the VPS)**: Stores records, websites, social interactions, and ontological resources that the user has explicitly chosen to share with at least one other agent under a signed ValuesCredentials / deontic contract (entity\_view/rights\_filter.rs and net/qdnf/policy\_labels/ Information Flow Control lattice).  
* **Encrypted Off-Site Recovery**: When the VPS acts as a backup target for the local Sanctuary Keep, it receives only client-side-encrypted .q42j append-only journal segments (q42/journal.rs) that cannot be inspected by the host and can be restored to a new machine via qualia-cli vault recover using M-of-N Shamir secret shares (qualia-client-core accountability fabric).

## **2.3 How Building webizen-host Directly Improves the QualiaDB Stack**

Implementing and operating webizen-host resolves six concrete engineering gaps identified in the [QualiaDB 0.0.40 Capability Reference](https://docs.google.com/document/d/1kKTwYKm9G333hKjclleAhwx2O-hVjv_v6htm_IL2kf8/edit):

* **Unblocking CSCP-08 and CSCP-09 Public Internet Qualification**: As recorded on [webizen.au/qdnf.html](https://webizen.au/qdnf.html), the CSCP-08 (public Internet WSS/MASQUE bound-UDP relay) and CSCP-09 live Internet two-host evidence flags remain false because static GitHub Pages cannot act as an active relay and the chores wait on an operator-supplied public hostname. Deploying webizen-host provides the live two-host path to qualify CSCP-08/09 and flip those honesty flags in-tree.  
* **Completing FLAG\_PAYLOAD\_CATALOGUE (0x0080, ADR 0014\) in .q42 Volumes**: Upgrades q42\_volume.rs from stub status to full read/write parity with bundle/cbor\_ld\_manifest.rs (PayloadCatalogueEntry).  
* **Wiring owl/materialize.rs and owl/shacl\_convert.rs into Production Ingest**: Connects the complete but currently Library-only OWL 2 RL forward-chaining materializer and OWL-to-SHACL uplift engine into the VPS ontology build pipeline.  
* **Replacing mock\_network\_fetch in net/fetch\_10d.rs**: Wires real content-addressed range transport over QPR and HTTP/2 while preserving the existing consent and CRC-32C verification gates.  
* **Hardening Multi-Tenant Key Derivation (identity/agency.rs)**: Upgrades derive\_lane\_key from single-pass SHA-256 to memory-hard Argon2id plus HKDF (specialized\_libs/cryptographic\_library) for multi-user VPS vault lane isolation.  
* **Binding Persistent Obligation Ledgers to Asset Manifests**: Connects the zero-heap arithmetic in modalities/value\_flow.rs (accumulate\_meter\_to\_pool, is\_commons\_discharged) to durable .q42j ledger checkpoints on the host.

# **3\. Large Ontology Ingestion, Processing and Segmented Hosting Pipeline (Over-100 MB WebCivics/ns)**

To host [https\://github.com/WebCivics/ns](https://github.com/WebCivics/ns) (over 100 MB) alongside the 102 UN/OHCHR/ICRC human-rights instruments in core-ontologies/, Australian Bureau of Statistics (ABS) datasets, medical/chemical ontologies (SNOMED, ChEBI, QUDT, DICOM/RadLex), and [Ecosphere Assets](https://docs.google.com/document/d/1WMoe6hn39ZnLFXl0T0KEWTW8zCBkdvduov2wctHZPsM/edit) species corpora, webizen-host replaces static file hosting with a streaming compilation and range-serving pipeline.

## **3.1 Bounded Cold-Path Streaming Ingestion Architecture**

Honoring QualiaDB's two-tier allocation contract (AGENTS.md Section 0-A: Tier 1 HotZeroHeap vs. Tier 2 ColdBounded), ontology ingestion runs as a supervised background service (q42/asset\_import/ plus qualia-cli/src/ingest/):

* **Step 1 — Repository Sync and Governed Envelope Check (q42/source\_catalogue/, q42/asset\_envelope/)**: Clones or pulls https\://github.com/WebCivics/ns (including large RDF/XML, Turtle, N3, and OWL trees) into /var/lib/qualia/staging/ns/, computing BLAKE3 and SHA-256 digests per source file and evaluating upstream licensing via q42/asset\_envelope/ (where unknown licenses fail closed and derived volumes inherit the union of upstream obligations).  
* **Step 2 — Streaming Chunk Parser and Q42LEX v4 Namespaced Lexicon (query/ingest\*.rs, q42\_lex\_ns.rs)**: Streams RDF/XML, Turtle, N-Triples, JSON-LD, YAML-LD (yaml\_ld\_q42.rs), and Notation3 (strict, defeasible, defeater, and linear rules) under an explicit caller byte budget (default 256 MiB cold arena, configurable per VPS profile, failing closed with quarantine counts on malformed triples). Enforces IngestMode::Complete paired with the v4 namespaced paged lexicon (Q42LEX v4), which deduplicates namespace prefixes and stores 60-bit masked tokens in range-addressable lexicon pages while computing 64-bit FNV-1a hashes (q\_hash()) for every IRI.  
* **Step 3 — SHACL-First Non-Thing Uplift and Bytecode Compilation (owl/shacl\_convert.rs, governance/webizen\_bytecode.rs)**: Enforces the normative rule in docs/manuals/standards/shacl-first-vs-owl-ok-class-list.md: natural persons, kinship, human relations, and living ecological entities are rdfs:Class plus SHACL/ShEx and are strictly forbidden from subclassing owl:Thing. Legacy OWL definitions are uplifted into W3C SHACL shape packs (shapes/\*.shacl.ttl) and compiled into WAM-style SlgOpcode bytecode (deontic 0x10–0x12, epistemic 0x20–0x22, paraconsistent 0x30–0x32, LTL 0x40–0x44).

## **3.2 Segmented Output Formats and Content-Negotiated Virtual Namespace Server**

* **.q42 v4 Semantic Volumes (q42\_volume.rs)**: 64-B header plus 40,960-B LZ4-compressed QualiaSuperBlocks (853 x 48-byte NQuins per block), BIDX block index, postings index, and Q42LEX v4 paged lexicon. Clients read the 64-B header and BIDX index via range\_volume.rs and fetch only the specific 40 KiB SuperBlocks matching their SPARQL/N3 query—turning a 150 MB file load into an under-100 KiB range fetch.  
* **QBDL .hmc Hypermedia Bundles (bundle/format.rs)**: Magic QBDL v1, 64-B header, 64-B page-aligned intact file entries, trailing CBOR index footer (key, kind, offset, length, sha256, meta), whole-file CRC-32C, and cbor\_ld\_manifest.rs. Any HTTP/2 server or QPR peer serves exact interior byte slices (HTTP 206 Partial Content) verified by per-entry SHA-256 digests.  
* **.vibe / VBC1 Vocabulary Chunks (vibe/src/vocab/)**: Tree-shaken .n3 vocabulary chunk tables and VBC1 bytecode chunks directly loaded by [VibeScript 0.1](https://webizen.au/progress-0.0.33.html) and the 640 KiB [webizen-lite-wasm](https://webizen.au/progress-0.0.37.html) Ontology MCP kernel.  
* **Content-Negotiated Virtual Namespace Server (Upgrading ns.webcivics.net)**: Resolves any ontology URI via HTTP content negotiation—returning binary NQuin slices (application/q42 or application/cbor-ld) to Webizen clients in under 1 ms, dynamically serializing Turtle, N-Triples (resolver.rs::format\_ntriples\_to), JSON-LD, or RDF/XML for legacy W3C tools, and serving an interactive HTML \+ WASM ontology inspector for human browser visitors.

# **4\. Human-Centric Ownership, Group Structures, and Agent Governance Models**

## **4.1 Decoupling the Who-Plane (NaturalAgent) from the Handle-Plane (DNI / DNS)**

In strict compliance with [QDNF Continuity Rules](https://webizen.au/qdnf.html):

* **Who-Plane (Identifier Fabric)**: Every human owner, family member, or community co-steward is represented as a NaturalAgent (never owl:Thing, never a corporate wallet) anchored by self-certifying did:qi (crates/qualia-core-db/src/did\_qi/ signed QCDE-1 lifecycle vectors) and WebizenID keys stored in their local key\_vault.rs.  
* **Handle-Plane (Locators and Domains)**: ICANN domain names (ns.webcivics.net, webizen.au, civics.au), IP addresses, business registry strings (ABNs), and expiring DNI topological locators sit strictly on the Handle-Plane.  
* **Continuity Invariant (Handle revoke does not equal who-erase)**: If a domain name expires or is seized by a registrar, the host's Collapse Detector marks the domain locator held/closed while keeping all NaturalAgent identities, cooperative memberships, and .q42 / Sanctuary Keep volumes intact and reachable over native QDNF (QResolve) or any newly attached domain handle.  
* **Instrument and Agent Honesty (core-ontologies/agent-accountability.n3)**: Software agents, AI models, and automated services operate under explicit capability credentials (capability-credentials.n3) and author-scoped ZCAP-LD delegation chains (modalities/delegation.rs). Per Webizen's foundational principle (*"Natural persons are not identity assets; instruments are not peers"*), every agent action carries cryptographic provenance tracing back to the authorizing NaturalAgent or Group/Cooperative quorum.

## **4.2 Four Human-Centric Ownership, Group and Agent Stewardship Modes**

* **Single Natural Person (Individual Human-Centric Host)**: Single root NaturalAgent (did:qi) holding 1-of-1 authority plus delegated device sub-keys (desktop, laptop, phone companion PWA qualia-mobile-harness) via ZCAP-LD (modalities/delegation.rs). Enforced by identity/webizen\_did.rs, did\_qi/, and governance/consent\_contract.rs.  
* **Family / Household Collective (Shared Domain \+ Guardianship)**: 1–2+ adult NaturalAgent co-stewards plus dependent profiles governed by GuardianshipRelations / GuardianshipSemantics and legal capacity rules (modalities/capacity.rs) under a shared top-level domain (per [GuideForDevelopers](https://devdocs.webizen.org/GuideForDevelopers/)). Enforced by wellfare-core/src/guardianship.rs and Argon2id derive\_lane\_key vault isolation.  
* **Multi-Person Group / Community / Cooperative (Many Natural Persons)**: M-of-N Steward Quorum of distinct NaturalAgents over the 32-slot SuspendedTransactionQueue (foundation/crdt.rs) plus BFT consensus (f \= floor((n \- 1\) / 3\) in modalities/consensus.rs) with explicit-denial guards (domains/geospatial/stewardship.rs). Powered by crates/qualia-cooperative-core (\~84 tests) and Sentinel VM multi-agent coordination opcodes (0x70–0x7F in governance/coordination.rs), with paraconsistent dissent retention (governance/illocution.rs).  
* **Governed Autonomous and Service Agents**: Delegated software and AI agents bound by ZCAP-LD attenuation (modalities/delegation.rs), Sentinel VM coordination opcodes (0x70–0x7F in governance/coordination.rs), and agent\_runtime/ phase leases—supporting automated ontology curation, research workflows, group service bots, and services/swarm/ verify-before-pay compute nodes under strict deontic guardrails.

# **5\. QualiaDB and Webizen Native Applications, cPanel-Replacement Stack and Multi-Tenant Sandboxing**

## **5.1 First-Class Support for QualiaDB and Webizen Native Applications**

* **Portable QApps and qualia-app-contract Applications (q42/app\_manifest/, q42/app\_registry/)**: Hosts versioned QApp packages conforming to crates/qualia-app-contract (the canonical command, context, session, and surface contract shared across Poet, Webizen OS, and Storytold applications) and the source-independent SDK boundary (GA-17 / SDK-01..10), with multi-user and multi-agent state sync over append-only .q42j session journals and CRDT merges (foundation/crdt.rs, sync.rs).  
* **VibeScript (VBC1) and Poet Manifold Applications (crates/vibe/, crates/poet/, webizen-studio)**: Executes [VibeScript 0.1](https://webizen.au/progress-0.0.33.html) reactive cell DAGs (reactive\_cell.rs), two-way data bindings (bind), presentation sheaves (present), and the \~1,158 host catalog operations (vibe/src/catalog/ids.rs) across \~90 families (GraphDatabase, DeonticLogic, N3Logic, ComputationalGeometry, Physics, Audio, Spectral, Cosmic, Inference, Orchestration, World) alongside poet/src/browser/\*\_chain\_actions.rs and vibe-play (port 7420\) / vibe-lsp.  
* **3D / 10D Spatial, Generative and Simulation Applications (webizen-render, webizen-runtime, .10d, .hmc)**: Serves multi-scale spatial applications built on the [Webizen 3D Engine](https://docs.google.com/file/d/1fugYZmVKAyEHwaTGV7ndznAObduUvEJn/view) (SemanticScene projecting SPARQL/N3 inference directly into 3D/WebGPU scenes with q42: provenance), the [Omniversal Coordinate System (OCS)](https://docs.google.com/document/d/1Auy3Y9gT-0yNPrlrdiTXfr5q5KBnPSAAXAL-mO4uyN0/edit), and Chora geospatial canvases (domains/geospatial/spatial\_sync.rs), progressively streaming .10d Living Containers (QuantizedMesh, Tensor10DNodes, SkeletalAnimation SKL1, EntityOntology EONT1, SurfaceReading SRD1, HyperspectralCube) and QBDL .hmc bundles with 20 Hz fixed-timestep world reducers (simulation/fixed\_tick.rs).  
* **Human-Centric Agentic and Neuro-Symbolic Applications (qualia-client-core, agent\_runtime/, wellfare-core)**: Hosts the Branching-Conversation Chat DAG (qualia-client-core/src/chat\_graph.rs), symbolic multi-agent blackboards (agent\_runtime/orchestration.rs), grammar-constrained VibeScript synthesis (domino\_gbnf.rs \+ neuro\_symbolic\_sieve.rs), .p64 model weight streaming (q42/p64\_weight.rs), and the 640 KiB [webizen-lite-wasm](https://webizen.au/progress-0.0.37.html) Ontology MCP endpoint.

## **5.2 Three-Tier Sandbox Architecture for Hosted Services and Websites**

## **5.3 cPanel-Parity Feature Set in the Human-Centric Poet Admin Workbench**

* **Sandbox Tier 1 — VibeScript (VBC1) and 42 MiB SlgArena Cellular Sandbox (Native Semantic Apps)**: Replaces unsafe server-side JavaScript (Node.js/V8) and PHP with [VibeScript 0.1](https://webizen.au/progress-0.0.33.html) (crates/vibe/) compiled to VBC1 bytecode. Every function carries a mandatory u64 instruction/cycle budget (vibe/src/budget.rs), executes under the strict effect lattice (Pure to Hot to Cold to Async to External in vibe/src/effects.rs), requires fail-closed using {Family}; capability leases (deontic\_interrupt.rs), and runs hot-path logic inside an isolated 42 MiB SlgArena Sentinel cell (governance/cell\_graph.rs).  
* **Sandbox Tier 2 — WebAssembly and QApp Isolate Sandbox (Portable Client/Server Apps)**: Executes compiled Rust/WASM application modules (conforming to the source-independent SDK-01..10 contract in qualia-app-contract), vibe-wasm packages, and the 640 KiB webizen-lite-wasm Ontology MCP endpoint, scoped to virtual volume prefixes (wasm\_storage.rs).  
* **Sandbox Tier 3 — W3C Solid LDP Pod Bridge and Linux/eBPF Container Sandbox (Web 2.0 and Interop Sites)**: Incorporates crates/qualia-solid-bridge (matching the MIT-licensed Solid/LDP baseline on [web.civics.au](https://web.civics.au/) with a strict Turtle-to-NQuin boundary) alongside unprivileged Linux user/mount/PID/network namespaces guarded by qualia-core-db's native eBPF packet/socket filter (net/) enforcing per-sandbox egress byte quotas.

Addressing the requirements in [UI / UX / Human Centric Systems Considerations](https://docs.google.com/document/d/11P5TziZqynsdiKeLslyj_QADst9FYZwF0RZKW4O-oQ0/edit), the server control panel is organized around Webizen's six life domains ([Memory, Relations, Care, Practice, World, Instruments](https://webizen.au/progress-0.0.26.html)) inside the Poet / Dioxus Workbench:

* **World and Realm Domain Manager**: Replaces cPanel Addon Domains/Subdomains; attaches ICANN domains, configures NS/glue records, binds did:qi handles, and toggles 1-click decentralized CDN seeding.  
* **Dual-Authority Crypto Manager (WebizenID-TLS \+ ACME)**: Replaces AutoSSL; automates Let's Encrypt TLS certs while acting as a dedicated WebizenID-TLS CA issuing Ed25519 \+ ML-KEM-768 device certificates and Groth16 over BLS12-381 (crypto/ deontic\_access circuit) zero-knowledge standing proofs.  
* **Relations Human-Centric Mail and Relationship-Scoped Aliases**: Replaces cPanel Email/SpamAssassin; provides full custom-domain email (@yourdomain.tld) backed by qualia-client-core/src/mail and did:qi mailbox binding, implementing **relationship-scoped email delegation** (delegating a unique email address to each relationship/contact, whitelisted against an N3 ontology document per [GuideForDevelopers](https://devdocs.webizen.org/GuideForDevelopers/)).  
* **QualiaDB Multi-Volume and SPARQL/N3 Studio**: Replaces MySQL/phpMyAdmin; manages .q42 v4 volumes, .q42j journals, 1-click Git ontology imports (WebCivics/ns), and visual SPARQL-Star/N3/SHACL authoring.  
* **Hypermedia Bundle (.hmc / .10d) and Solid Explorer**: Replaces cPanel File Manager/FTP; manages QBDL .hmc bundles, .10d spatial assets, and Solid Pod folders with automatic EXIF/WAV provenance extraction and asset\_envelope/ license verification.  
* **Bounded Tick Scheduler, .q42j Shamir Backup Wizard, and Hard Cost-Cap HUD**: Replaces Cron, Backup Wizard, and Bandwidth Meters; provides real-time telemetry of MeterKind::{Bytes, EnergyJoules, Time, Compute} with a hard monthly dollar/egress circuit-breaker slider.  
* **Native QApp, Poet and VibeScript Registry (q42/app\_registry/)**: Replaces Softaculous / Node / PHP installers with 1-click deployment and versioning of native Webizen QApps, Poet workspaces, qualia-chat DAG instances, and 3D/10D .hmc portals across desktop and mobile WASM.

# **6\. QualiaDB-Accelerated DNS, Naming and QDNF Routing**

 includes a dedicated net/dns/ subsystem (wire codec, resolver, cache ring, quin records, ontology, SDN, lossless archive) alongside net/qdnf/. Integrating these into webizen-host delivers an authoritative and recursive DNS \+ QDNF naming engine that outperforms conventional BIND/CoreDNS stacks in latency, security, and semantic control.

## **6.1 How QualiaDB Accelerates DNS Performance (net/dns/ \+ NQuin \+ q\_hash())**

* **Zero-Heap 48-Byte NQuin Zone and Cache Ring (HotZeroHeap)**:  
  * Traditional DNS servers parse variable-length wire strings and walk heap-allocated radix trees on every packet.  
  * In webizen-host, every DNS resource record (A, AAAA, CNAME, TXT, SRV, HTTPS, SVCB, DNSKEY, RRSIG, TLSA, plus custom DID/Q42 records) is compiled into a **48-byte NQuin** inside net/dns/:  
    * subject: 64-bit q\_hash() (FNV-1a) of the normalized domain name plus record type bits.  
    * predicate: Record class/type and QDNF routing lane flags.  
    * object: Inline packed IPv4/IPv6 address, DANE TLSA digest, TTL epoch, or did:q42 pointer to a Q42LEX v4 lexicon entry for long TXT/HTTPS payloads.  
    * context: Authoritative zone DID and DNSSEC/Ed25519 signature status.  
  * Because lookups execute as **O(1) 64-bit integer hash probes** inside a pre-allocated, cache-line-aligned HotZeroHeap ring buffer (with optional Linux **AF\_XDP / eBPF** kernel-bypass packet filtering), the server resolves millions of queries per second with zero heap allocations.  
* **In-Flight Deontic and SHACL Policy DNS Firewall (QPolicy \+ SlgArena)**:  
  * Because DNS records are native NQuins, the resolver evaluates **N3Logic and Deontic rules (0x10–0x12)** in-flight:  
  * **Jurisdiction-Aware and Deontic Routing (jurisdiction.n3)**: Automatically steers traffic away from hostile jurisdictions or non-compliant relays based on the steward's deontic protection profile (net/qdnf/profiles/ E16.1–E16.7).  
  * **Split-Horizon Privacy and Consent Gating**: Private service subdomains (such as family device endpoints or local webizen-desktop relays) resolve **only** when the DNS query carries a valid DNI cookie, TSIG, or DoH/DoQ WebizenID-TLS session proof—returning NXDOMAIN to public scanners.  
* **Bitemporal Lossless DNS Archive (net/dns/ lossless archive)**:  
  * Every zone mutation and DNSSEC/DANE key rollover is journaled in .q42j with bitemporal predicates (lifecycle:validFrom, lifecycle:transactionFrom per [Spatiotemporal Datetime Predicates in QualiaDB](https://docs.google.com/document/d/13ZijTk1Yx1hwjvwbkB7xCxaPaDZPmha4RVz9Zrb38sA/edit)), providing a tamper-evident evidentiary chain for legal continuity ("Continuity for a jury" per [QDNF](https://webizen.au/qdnf.html)).

## **6.2 Dual-Stack QDNF Naming and Cryptokey Routing**

Hosted domains on webizen-host operate simultaneously across the Legacy Internet Gateway and the six-layer [QDNF Protocol Honeycomb](https://webizen.au/qdnf.html):

* **Legacy Internet Gateway**: Serves UDP/TCP port 53 (with DNSSEC and DANE), DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ), automatically publishing \_didTXT records and .well-known/did.json / .well-known/qdnf descriptors.  
* **Native QDNF Honeycomb Stack (net/qdnf/)**:  
  * **QLink and DNI**: Proves neighbour adjacency cryptographically and assigns self-certifying, expiring topological locators (DNI) so network paths never expose permanent human identity.  
  * **QRoute and Cryptokey IPv6 (governance/web\_civics.rs)**: Uses constraint-first routing (validate to index to plan in net/qdnf/route/) and deterministic **Ed25519 to ULA IPv6 derivation** (fd00::/8 cryptokey routing where the mathematical DID key *is* the overlay IPv6 address over SocialWebNet WireGuard or raw Ethernet).  
  * **QResolve (net/qdnf/resolve/qsr)**: Resolves did:qi, did:q42, and content-addressed .q42/.hmc hashes directly across the peer fabric without depending on ICANN DNS.

# **7\. User-Powered Decentralized CDN and Egress Protection (Solving ns.webcivics.net)**

To ensure no Webizen operator ever faces the runaway CloudFront bandwidth bills experienced on [ns.webcivics.net](https://ns.webcivics.net/), every hosted domain and ontology volume on webizen-host is backed by a **User-Powered Decentralized CDN (Q-CDN)** with hard origin cost caps.

## **7.1 Three-Layer Architecture of the User-Powered Decentralized CDN (Q-CDN)**

Because QualiaDB compiles large ontologies and media into **content-addressed, chunk-verifiable containers**—40,960-byte LZ4 QualiaSuperBlocks in .q42 v4 and 64-byte page-aligned entries with SHA-256 footer digests in QBDL.hmc bundles—any peer can serve cached slices without the requester having to trust the peer:

* **1\. Origin Serves Lightweight Signed Root Index (Under 10 KiB)**:  
  * When a client requests a resource from ns.webcivics.net or any CDN-enabled hosted domain, the origin VPS serves the compact, Ed25519-signed **Master Index** (cbor\_ld\_manifest.rs / BIDX header), cataloging the SHA-256 / BLAKE3 digest, byte offset, and micropayment weight of every 40 KiB SuperBlock or .hmc segment.  
* **2\. Three-Tier Peer Swarm Distribution (QPR \+ WebTorrent port 4242 \+ Browser OPFS)**:  
  * **Tier A — Cooperative VPS Mirrors (net/peer/replication/)**: Other webizen-host VPS instances in the Webizen Alliance replicate hot .q42 and .hmc shards using Merkle custody proofs, tombstones, and resumable transfers, advertised via DNS HTTPS/SVCB and HTTP Alt-Svc headers.  
  * **Tier B — Desktop User Nodes (webizen-desktop via qualia-peer)**: Every user running webizen-desktop caches the .q42 ontology SuperBlocks and .hmc assets they use locally and seeds verified slices to peers over QSession/QSync and the built-in daemon seeder (services/webtorrent\_\*.rs on port 4242).  
  * **Tier C — Browser Visitors (OPFS Cache \+ WebRTC/WebTorrent)**: Browser visitors using the WASM portal cache fetched 40 KiB SuperBlocks in their Origin Private File System (OPFS, wasm\_storage.rs) and exchange verified chunks with fellow browser peers via WebRTC DataChannels.  
* **3\. Hard Origin Egress Circuit Breaker (net/qdnf/economics/meters.rs)**:  
  * The VPS operator sets a strict monthly or daily egress byte and dollar ceiling in meters.rs (for example, *"Max 1.5 TB/month direct origin egress; \$0.00 permitted overage"*) enforced by the Sentinel VM's anti-usury circuit breaker opcodes (governance/coordination.rs).  
  * When traffic from US data hubs or scrapers pushes origin egress toward the threshold, the circuit breaker trips automatically: the VPS continues serving the tiny signed Root Index and verified Humanitarian ICT sessions directly, while redirecting all bulk .q42/.hmc range fetches (via HTTP 307 Temporary Redirect, Link: rel="duplicate", and QResolve swarm pointers) to the user-powered Q-CDN swarm or commercial toll-gated mirrors.  
  * **Outcome**: Publisher hosting costs are mathematically capped at the flat monthly VPS fee (for example, \$5–\$20/month), completely eliminating CloudFront overage risk.

# **8\. Micropayments, Permissive Commons Economics and Blockchain / DLT Architecture**

To make [ns.webcivics.net](https://ns.webcivics.net/), [WebCivics/ns](https://github.com/WebCivics/ns), and [Ecosphere Assets](https://docs.google.com/document/d/1WMoe6hn39ZnLFXl0T0KEWTW8zCBkdvduov2wctHZPsM/edit) financially self-sustaining while keeping human-rights and humanitarian infrastructure free for natural persons, webizen-host wires the already-implemented **Permissive Commons Economic Engine (crates/qualia-core-db/src/modalities/value\_flow.rs)** and **QDNF Metering Substrate (net/qdnf/economics/meters.rs)** to protocol-level micropayments and a three-tier Blockchain/DLT architecture.

## **8.1 Two-Loop Permissive Commons Economic Model (modalities/value\_flow.rs)**

* **Loop 1 — Capital Creation Recovery (Obligation Cost and 10x Commons Sunset)**:  
  * Processing and curating large ontologies (WebCivics/ns, ABS data, medical/species corpora) and building the software stack incurs verifiable engineering and compute costs recorded in cbor\_ld\_manifest.rs as the baseline **Obligation Cost (**C\_obligation**)**, with a capped recovery ceiling of **up to** 10x C\_obligation computed via commons\_cost(production\_cost, roi\_cap\_percent, max\_roi\_percent) and guarded against extraction by usury\_ceiling() and check\_usury().  
  * **Natural Person and Humanitarian ICT Exemption (humanitarian-ict.n3)**: Requests carrying a verified NaturalAgent credential or Humanitarian ICT attestation receive a 0% royalty multiplier (royalty() \= 0), guaranteeing free access for citizens, researchers, and human-rights defenders.  
  * **Commercial Legal-Entity Toll Gate (HTTP 402 Payment Required / QPolicy)**: Incorporated legal entities, commercial AI training hubs, and corporate scrapers must attach an ILP-STREAM or eCash micropayment proof per range request. Payments accumulate via pool\_after(pool, payment) and accumulate\_meter\_to\_pool().  
  * **Automatic Commons Sunset (is\_commons\_discharged)**: The instant cumulative commercial contributions reach the capped obligation cost, is\_commons\_discharged(pool, cost) evaluates to true and invokes CommonsObligation::discharge\_to\_commons(), permanently transitioning the asset to PermissiveRoutingLane::EnforcePermissiveCommons (0b01) for all users worldwide—eradicating perpetual rent extraction ("Ending Digital Slavery" per [GuideForDevelopers](https://devdocs.webizen.org/GuideForDevelopers/)).  
* **Loop 2 — Ongoing Infrastructure Micropayments for Peer CDN Seeders and Hosts**:  
  * Independent of creation recovery, serving bandwidth and running remote SPARQL/inference jobs (services/swarm/ verify-before-pay) consumes live resources measured by net/qdnf/economics/meters.rs (MeterKind::{Bytes, EnergyJoules, Time, Compute}).  
  * value\_flow.rs::carriage\_fee\_from\_meters() calculates deterministic micro-tariffs per verified 40 KiB SuperBlock or .hmc range slice delivered, routing the payout directly to the **user nodes (webizen-desktop seeders)** and **independent VPS hosts** that served the bytes.

## **8.2 Blockchain and DLT Architecture: Three-Tier Human-Centric DLT Strategy (Forking vs. Native Hybrid)**

Auditing qualia-core-db and qualia-client-core shows four ledger and payment primitives **already implemented in-tree**: services/ilp\_dispatcher.rs (**ILP-STREAM-over-SPSP** writing every payment as a signed N-Quad receipt into .q42), qualia-client-core's **BIP32 / secp256k1 HD wallet** with **eCash (XEC) integration via** chronik.rs, did\_qi/**UTXO anchoring**, and modalities/consensus.rs (**BFT consensus** f \= floor((n \- 1\) / 3\)). To leverage these existing capabilities without reinventing wallet or indexer primitives, webizen-host adopts a **Three-Tier Human-Centric DLT Architecture**:

* **Tier 1 (Immediate Launch — No-Fork Production Rail): eCash (XEC / chronik.rs) UTXO Base \+ ILP-STREAM Off-Chain Micropayments**:  
  * Uses the in-tree chronik.rs indexer and BIP32 wallet for sub-cent (\~\$0.0001), under-2-second Avalanche-finalized UTXO settlements and did:qi anchoring, while services/ilp\_dispatcher.rs streams high-frequency per-chunk CDN micropayments and logs signed N-Quad receipts into .q42j. Turns on commercial toll collection for ns.webcivics.net and peer CDN payouts on Day 1 with zero consensus maintenance.  
* **Tier 2 (Phase 1.5 — Blockless Local/Realm Clearinghouse): Native QDNF DAG-CRDT \+ BFT Committee Ledger**:  
  * Uses append-only .q42j hash-chained N-Quad journals, modalities/reconciliation.rs (compare\_views), and realm **BFT committees (**modalities/consensus.rs, f \= floor((n \- 1\) / 3\)) across cooperative VPS hosts to clear bilateral CDN bandwidth credits and track commons\_cost pools with zero gas fees, periodically checkpointing net balances onto Tier 1 or Tier 3\.  
* **Tier 3 (Phase 2 — Dedicated Chain Fork Option): Forked eCash/Avalanche-UTXO or Rust BFT Dedicated Chain ("QualiaChain")**:  
  * Forks the open-source **eCash (ABC/Avalanche-UTXO \+ Chronik Rust indexer)** or a lightweight **Rust BFT engine** and embeds **qualia-core-db's 42 MiB SlgArena VM (governance/webizen.rs)** directly into block and transaction validation—so L1 consensus natively enforces value\_flow.rs (check\_usury, 10x commons sunset, and NaturalAgent fee exemptions) while preserving 100% of existing chronik.rs and did:qi UTXO code.

# **9\. Phased Implementation Plan and Work Packages (WP-01 to WP-08)**

In accordance with AGENTS.md Section 0-A/B and the source-independent SDK release gate (GA-17 / SDK-01..10 in the [QualiaDB Capability Reference](https://docs.google.com/document/d/1kKTwYKm9G333hKjclleAhwx2O-hVjv_v6htm_IL2kf8/edit)), execution is structured into eight sequential Work Packages:

* **WP-01 (P0) — Streaming Large Ontology Compiler (Over-100 MB WebCivics/ns)**: Configure q42/asset\_import/ streaming worker in qualia-core-db/src/q42/ and qualia-cli/src/ingest/ to pull and chunk [https\://github.com/WebCivics/ns](https://github.com/WebCivics/ns); enforce IngestMode::Complete \+ Q42LEX v4 (q42\_lex\_ns.rs) \+ owl/shacl\_convert.rs (SHACL-first non-Thing uplift); complete FLAG\_PAYLOAD\_CATALOGUE (0x0080) writer in q42\_volume.rs and emit segmented QBDL.hmc bundles. *Exit Evidence*: Full WebCivics/ns repo compiles within a 256 MiB cold memory budget with zero OOMs; verify-graph \--encoder=import passes 100%.  
* **WP-02 (P0) — Range-Served Virtual Namespace and Cost Cap (ns.webcivics.net v2)**: Replace static file serving on [ns.webcivics.net](https://ns.webcivics.net/) (services/daemon.rs, q42/volume/range\_volume.rs) with a zero-alloc HTTP/2 and HTTP/3 content-negotiated handler (.q42 slice, Turtle, JSON-LD, N-Triples, HTML+WASM) and wire net/qdnf/economics/meters.rs hard monthly/daily egress byte and dollar circuit breakers. *Exit Evidence*: ns.webcivics.net serves 40 KiB QualiaSuperBlock range queries in under 2 ms; simulated US-hub traffic surge trips the hard cap cleanly with \$0 overage.  
* **WP-03 (P0/P1) — QualiaDB NQuin DNS Server and Live QDNF Relay**: Expose net/dns/ 48-byte NQuin zone ring on UDP/TCP port 53, DoH, DoT, and DoQ with automatic DNSSEC/DANE and \_did records, and use the live VPS hostname to execute two-host Internet trials for **CSCP-08** (MASQUE bound-UDP) and **CSCP-09**. *Exit Evidence*: O(1) q\_hash() DNS benchmark verified; CSCP-08 and CSCP-09 public Internet evidence flags on [webizen.au/qdnf.html](https://webizen.au/qdnf.html) flip to verified.  
* **WP-04 (P1) — Three-Tier Multi-Tenant Sandbox Engine and QApp Runtime Hosting**: Build HostSandboxManager (crates/vibe/, governance/cell\_graph.rs, qualia-solid-bridge) isolating tenants into 42 MiB SlgArena cells \+ VibeScript VBC1u64 cycle budgets, WASM QApp isolates, native QApp runtime hosting (qualia-app-contract, .10d/.hmc spatial streaming, chat\_graph.rs, agent\_runtime/), qualia-solid-bridge ([web.civics.au](https://web.civics.au/) pods), and Linux cgroup/namespace \+ eBPF socket quotas. *Exit Evidence*: Budget-exhausting VBC1 script halts deterministically without impacting sibling sandboxes; Solid LDP pods pass W3C read/write conformance.  
* **WP-05 (P1) — Ownership, Group Structures and Agent Governance**: Upgrade derive\_lane\_key (identity/agency.rs) to Argon2id \+ HKDF; wire 1-click PeerHost::pair between local webizen-desktop (port 8080\) and VPS (port 4242\) with encrypted .q42j backup and Shamir CLI recovery; enable M-of-N Steward Quorum (qualia-cooperative-core, stewardship.rs, SuspendedTransactionQueue) and ZCAP-LD agent delegation (modalities/delegation.rs, core-ontologies/agent-accountability.n3). *Exit Evidence*: Individual, Family (GuardianshipSemantics), Cooperative, and Governed Agent server ownership modes pass audit; domain handle revoke passes Collapse Detector.  
* **WP-06 (P1) — User-Powered Decentralized CDN (Q-CDN Swarm)**: Replace mock\_network\_fetch in net/fetch\_10d.rs with live QPR/HTTP range transport; connect port 4242 WebTorrent seeder (services/webtorrent\_\*.rs) and Merkle replication (net/peer/replication/) to webizen-desktop and browser OPFS caches; automate HTTP 307 / Alt-Svc swarm redirect on origin quota threshold. *Exit Evidence*: Peers serve verified 40 KiB .q42 SuperBlocks and .hmc slices; tampered peer chunks are rejected by SHA-256/CRC-32C before arena admission.  
* **WP-07 (P1/P2) — Permissive Commons Toll Gate, Micropayments and DLT**: Persist modalities/value\_flow.rs obligation pools in .q42j; enforce HTTP 402 / QPolicy commercial toll gate (exempting Natural Persons and Humanitarian ICT) with automatic 10x sunset; stream services/ilp\_dispatcher.rs \+ chronik.rs eCash payouts to CDN seeders and prepare the Tier 3 UTXO-BFT fork. *Exit Evidence*: Commercial scraper requests settle ILP/eCash micropayments into .q42 N-Quad receipts; reaching 10x C\_obligation permanently flips asset to EnforcePermissiveCommons.  
* **WP-08 (P1/P2) — Poet Host Admin UI and Turnkey VPS Installer**: Build the human-centric **Poet Host Admin Workbench** (crates/poet/, webizen-studio) covering Domains, Human-Centric Relationship Mail, QApp Registry, Ontology Compiler, Sandboxes, Hard Cost-Cap Slider, and CDN Earnings HUD, paired with a 1-command Linux VPS installer (qualia-cli host install). *Exit Evidence*: Clean Linux VPS provisions the full stack in under 5 minutes; human operator configures domain, relationship mail, ontology seed, and hard cost cap via UI.

# **10\. References and Authoritative Source Index**

* **WebCivics Ontology Repository (Over-100 MB Seed Target)**: [https\://github.com/WebCivics/ns](https://github.com/WebCivics/ns) and live human-rights instrument service [https\://ns.webcivics.net/](https://ns.webcivics.net/)  
* **QualiaDB and Webizen Core Documentation**: [Webizen / QualiaDB Portal (0.0.39)](https://webizen.au/), [QDNF — Qualia Decentralized Network Fabric](https://webizen.au/qdnf.html), [Qualia · Webizen · Poet Release Matrix](https://webizen.au/release-matrix.html), [Honest Progress 0.0.37](https://webizen.au/progress-0.0.37.html), [Honest Progress 0.0.33 (VibeScript 0.1)](https://webizen.au/progress-0.0.33.html), [Honest Progress 0.0.26 (Life Domains)](https://webizen.au/progress-0.0.26.html), and [QualiaDB 0.0.40-dev Source Repository](https://github.com/mediaprophet/qualiaDB/tree/0.0.40-dev)  
* **Webizen Historical and Architectural Specifications**: [DRAFT: Guide For Developers (Church and State Vaults, WebizenID-TLS, Relationship Mail, Permissive Commons)](https://devdocs.webizen.org/GuideForDevelopers/), [Host Software Requirements (VPS)](https://devdocs.webizen.org/WebizenTechStack/Webizen3.0/HostServiceRequirements/), [Webizen Pro VPS and Confidential Computing](https://devdocs.webizen.org/WebizenTechStack/Webizen3.5/WebizenProSeries/WebizenPro/), and [W3C Solid MIT Baseline (web.civics.au)](https://web.civics.au/)  
* **Workspace Architecture and Audit Documents**: [Project Definitions (The Webizen Web-Host Server Stack)](https://docs.google.com/document/d/13skx0615mKULbJRP7YI1Dr8MreLq9mPntFKyQvXlMSI/edit), [QualiaDB Capability Reference for Ecosphere Assets (0.0.40 Audit)](https://docs.google.com/document/d/1kKTwYKm9G333hKjclleAhwx2O-hVjv_v6htm_IL2kf8/edit), [Ecosphere Assets Specification (Obligation Cost and 10x Commons Sunset)](https://docs.google.com/document/d/1WMoe6hn39ZnLFXl0T0KEWTW8zCBkdvduov2wctHZPsM/edit), [WEBIZEN\_REORG\_NOTES.md](https://docs.google.com/file/d/1u9sxtc0QU6-1aeLiol2JqPsqF10lzwKN/view), [UI / UX / Human Centric Systems Considerations](https://docs.google.com/document/d/11P5TziZqynsdiKeLslyj_QADst9FYZwF0RZKW4O-oQ0/edit), [Webizen Desktop Application Requirements](https://docs.google.com/document/d/1B2Zz1MqZKJgqWtKPxPqDD4_LFIAJt1CXYHWb9utrj5E/edit), and [Optimizing WGPU for AI and QualiaDB](https://docs.google.com/document/d/1MzQRXk2l0-Eji_h48uC08XYWMvyjfuzU-qoWmT-7bnU/edit)