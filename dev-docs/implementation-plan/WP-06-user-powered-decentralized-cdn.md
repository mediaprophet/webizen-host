# WP-06 (P1): User-Powered Decentralized CDN (`Q-CDN` Swarm)

**Work Package ID:** `WP-06`  
**Priority:** `P1`  
**Depends On:** [`WP-02`](./WP-02-virtual-namespace-and-cost-cap.md), [`WP-03`](./WP-03-nquin-dns-and-qdnf-relay.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/net/fetch_10d.rs`, `crates/qualia-core-db/src/net/peer/replication/`, `crates/qualia-core-db/src/services/webtorrent_*.rs`, `crates/qualia-core-db/src/wasm_storage.rs`, `crates/qualia-peer/`  
- `webizen-host`: `crates/webizen-host-qcdn/` (Root Index signer, swarm tracker/coordinator, & HTTP 307 offload router)  

---

## 1. Objective & Problem Statement

Centralized CDNs (such as AWS CloudFront) charge uncapped per-GB egress fees and turn high-demand public ontologies (`ns.webcivics.net`) into financial liabilities for their stewards. Because QualiaDB compiles large ontologies, QApps, and spatial media into **content-addressed, chunk-verifiable containers**—40,960-byte LZ4 `QualiaSuperBlock`s in `.q42` v4 and 64-byte page-aligned entries with SHA-256 footer digests in `QBDL` `.hmc` bundles—any peer can serve cached slices without the requester having to trust the peer.

**WP-06** implements the **Three-Layer User-Powered Decentralized CDN (`Q-CDN`)** with **Multi-Protocol Content-Addressed Sharing (`IPFS`, `IPNS`, `Partial-CAR`, `WebTorrent`, `QPR`, and `HTTP 206 Range`)**:
- Integrates `qualia-core-db/src/q42/volume/magnet.rs` (`Q42Magnet`, `compose_magnet` with BitTorrent `urn:btih:` + WebTorrent `ws=` HTTP web-seed + `xs=urn:cid:` IPFS CID), `car.rs` / `cid.rs` (`CidSha256`, `VerifiedCarRangeSource`), and `range.rs` (`HttpRangeSource`, `ipfs_gateway_range_source`, `ipns_gateway_range_source`).
- Enables clients and SPARQL query planners (`Q42RangeVolume`) to fetch **only the exact 40 KiB `QualiaSuperBlock`s or 64-byte aligned `.hmc` ranges** required for their query across HTTP Range, IPFS gateways, WebTorrent peers, or QPR nodes, without downloading the entire ontology file.
- Enforces the network-wide **"Verify-Before-Rebuild"** deduplication rule: peers and VPS hosts discover, verify, and reuse existing valid `.q42` / `.hmc` builds across the network, and only re-compile an ontology when no build exists or when a peer's version fails cryptographic/CRC-32C/SHACL verification.
- Closes QualiaDB Repo Gap #4 by replacing `mock_network_fetch` in `net/fetch_10d.rs` with live content-addressed range transport over QPR and HTTP/2.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **Live Content-Addressed Range Transport** | `crates/qualia-core-db/src/net/fetch_10d.rs`, `q42/volume/range_volume.rs` | Replace `mock_network_fetch` in `net/fetch_10d.rs` with real QPR and HTTP/2 `206 Partial Content` range fetching while preserving consent and CRC-32C / SHA-256 verification gates. |
| **Signed Root Index (`< 10 KiB`)** | `crates/qualia-core-db/src/bundle/cbor_ld_manifest.rs`, `q42/q42_volume.rs` (`BIDX`) | Serve compact Ed25519-signed Master Indexes listing the SHA-256 / BLAKE3 digest, byte offset, and micropayment weight of every 40 KiB SuperBlock or `.hmc` / `.10d` segment. |
| **Tier A: Cooperative VPS Mirrors** | `crates/qualia-core-db/src/net/peer/replication/` | Replicate hot `.q42`, `.10d`, and `.hmc` shards across participating `webizen-host` VPS nodes with Merkle custody proofs, tombstones, and resumable transfers. |
| **Tier B: `webizen-desktop` User Seeders** | `crates/qualia-core-db/src/services/webtorrent_*.rs` (`:4242`), `crates/qualia-peer/` (`QSession`/`QSync`) | Enable local `webizen-desktop` nodes to cache `.q42` SuperBlocks and `.hmc` slices they use and seed verified chunks to peers on `:4242` and over QPR. |
| **Tier C: Browser OPFS + WebRTC Swarm** | `crates/qualia-core-db/src/wasm_storage.rs`, `services/webtorrent_*.rs` | Cache fetched 40 KiB SuperBlocks in browser Origin Private File System (OPFS) and exchange chunk-verified slices via WebRTC DataChannels. |

---

## 3. Step-by-Step Implementation Tasks

### Task 6.1: Replacing `mock_network_fetch` in `net/fetch_10d.rs`
1. Replace the mock transport stub in `crates/qualia-core-db/src/net/fetch_10d.rs` with live range transport over:
   - **QPR (`crates/qualia-peer`)** content-addressed slice requests.
   - **HTTP/2 & HTTP/3 `206 Partial Content`** byte-range fetches (`Range: bytes=offset-end`).
2. Enforce strict pre-admission verification:
   - Check the user/steward consent gate before initiating network I/O.
   - Verify the CRC-32C and SHA-256 / BLAKE3 digest of every incoming 40 KiB `QualiaSuperBlock`, `.10d` section, or `.hmc` slice against the Ed25519-signed Root Index **before** admitting bytes into the arena or OPFS cache. Reject and ban peers serving corrupted chunks.

### Task 6.2: Three-Tier Peer Swarm Distribution (`Q-CDN`)
1. **Origin Signed Root Index (`< 10 KiB`)**:
   - On every ontology or bundle publish, generate and sign the compact Root Index (`cbor_ld_manifest.rs` + `BIDX` block map) containing per-chunk digests, byte offsets, and `value_flow.rs` micropayment weights.
2. **Tier A — Cooperative & Group VPS Mirrors (`net/peer/replication/`)**:
   - Wire Merkle custody proof replication across participating `webizen-host` VPS nodes, advertising mirror endpoints via DNS `HTTPS`/`SVCB` records (`WP-03`) and HTTP `Alt-Svc` headers.
3. **Tier B — Desktop User & Agent Seeders (`webizen-desktop` on `:4242`)**:
   - Connect `services/webtorrent_*.rs` (port `:4242`) and `QSession`/`QSync` so `webizen-desktop` automatically seeds verified `.q42` SuperBlocks and `.hmc` segments from its local cache while recording metered delivery receipts for Loop 2 micropayments (`WP-07`).
4. **Tier C — Browser OPFS Cache & WebRTC DataChannels (`wasm_storage.rs`)**:
   - Store fetched 40 KiB SuperBlocks in browser OPFS (`wasm_storage.rs`) and enable WebRTC DataChannel peer exchange for concurrent visitors on `ns.webcivics.net`.

### Task 6.3: Automated Origin Egress Offload (`meters.rs` → `Q-CDN`)
1. Connect the `meters.rs` egress circuit breaker (`WP-02`) directly to the `Q-CDN` swarm table:
   - When origin egress approaches the steward's configured byte/dollar ceiling, automatically respond to bulk `.q42`/`.hmc`/`.10d` range requests with `HTTP 307 Temporary Redirect`, `Link: rel="duplicate"`, and `QResolve` active peer swarm descriptors pointing to healthy Tier A/B/C seeders.

---

## 4. Verification & Exit Evidence

- [ ] **Live `net/fetch_10d.rs` Transport Test**: `net/fetch_10d.rs` fetches real `.10d`, `.hmc`, and `.q42` range slices over live HTTP/2 and QPR sockets with zero mock fallbacks.
- [ ] **Tampered Chunk Rejection Audit**: Injecting a single-bit flip into a peer-served 40 KiB `QualiaSuperBlock` or `.hmc` slice triggers immediate SHA-256 / CRC-32C rejection prior to arena admission.
- [ ] **End-to-End Three-Tier Swarm Trial**: Origin VPS serves only the `< 10 KiB` signed Root Index while `webizen-desktop` (`:4242`) and browser OPFS peers serve 100% of bulk `.q42` SuperBlocks for a `WebCivics/ns` query.
