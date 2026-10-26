# WP-02 (P0): Content-Negotiated Virtual Namespace & Hard Cost Cap (`ns.webcivics.net` v2)

**Work Package ID:** `WP-02`  
**Priority:** `P0` (Critical Path — Immediate Solution for `ns.webcivics.net`)  
**Depends On:** [`WP-01`](./WP-01-large-ontology-streaming-compiler.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/services/daemon.rs`, `crates/qualia-core-db/src/q42/volume/range_volume.rs`, `crates/qualia-core-db/src/query/resolver.rs`, `crates/qualia-core-db/src/net/qdnf/economics/meters.rs`, `crates/qualia-core-db/src/governance/coordination.rs`  
- `webizen-host`: `crates/webizen-host-namespace/` (HTTP/2 & HTTP/3 content-negotiated namespace handler)  

---

## 1. Objective & Problem Statement

Hosting `ns.webcivics.net` on legacy static web servers and commercial CDNs (such as AWS CloudFront) created two severe operational problems:
1. Clients requesting a single ontology term had to download multi-megabyte static RDF/XML or Turtle files.
2. High-volume automated traffic from major US data hubs caused uncapped per-GB egress charges with no protocol-level cost circuit breaker.

**WP-02** replaces static file serving on `ns.webcivics.net` (and any custom ontology domain hosted on `webizen-host`) with:
1. A **zero-allocation (`HotZeroHeap`) Virtual Namespace Server** backed by memory-mapped `.q42` v4 volumes and `QBDL` `.hmc` bundles supporting **`HTTP Range` (`206 Partial Content`)** (`q42/volume/range.rs` & `range_volume.rs`) so clients only fetch the specific 40 KiB `QualiaSuperBlock`s they need rather than downloading the entire >100 MB ontology.
2. **Range-Backed SPARQL / SPARQL-Star Query Execution** (`sparql_library/` + `Q42RangeVolume`): Allows local and remote callers to run `SELECT`, `ASK`, `CONSTRUCT`, and `DESCRIBE` SPARQL queries where the planner (`Q42RangeQueryPlan`) uses the `.q42` `BIDX` object index, `FIDX` field ranges, and `PIDX` postings to read only matching 40 KiB SuperBlocks over HTTP Range, IPFS, or WebTorrent.
3. A **Hard Origin Egress Circuit Breaker** (`net/qdnf/economics/meters.rs`) that mathematically caps publisher hosting costs at the flat monthly VPS rate.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **Range-Served `.q42` & `.hmc` Slices** | `crates/qualia-core-db/src/q42/volume/range_volume.rs`, `bundle/format.rs` | Expose HTTP `206 Partial Content` and QPR slice handlers for 64-B headers, `BIDX` index pages, 40,960-B `QualiaSuperBlock`s, and 64-B aligned `.hmc` segments. |
| **Content-Negotiated Namespace Router** | `crates/qualia-core-db/src/services/daemon.rs`, `query/resolver.rs` | Route `https://<domain>/<namespace>/<term>` via `q_hash()` lookup into the mounted `.q42` volume and project into binary `.q42`/CBOR-LD, standard W3C RDF formats, or HTML+WASM. |
| **Hard Egress & Dollar Circuit Breaker** | `crates/qualia-core-db/src/net/qdnf/economics/meters.rs`, `governance/coordination.rs` | Wire per-domain and host-wide `MeterKind::{Bytes, EnergyJoules, Time, Compute}` counters with hard daily/monthly egress byte and dollar ceilings. |
| **Browser Ontology Explorer** | `webizen-lite-wasm` (640 KiB Ontology MCP WASM kernel) | Serve interactive HTML shell + 640 KiB `webizen-lite-wasm` inspector that fetches only the required 40 KiB SuperBlock into browser OPFS. |

---

## 3. Step-by-Step Implementation Tasks

### Task 2.1: Zero-Allocation Virtual Namespace Handler (`HotZeroHeap`)
1. Implement `VirtualNamespaceHandler` integrated with `services/daemon.rs` (HTTP/2 and HTTP/3 QUIC on `:443` / `:4242`):
   - Hash incoming request URI (`https://ns.webcivics.net/*`) at ingress via 64-bit FNV-1a `q_hash()`.
   - Probe the memory-mapped `.q42` v4 `BIDX` index in $O(1)$ / $O(\log B)$ time to locate the exact 40,960-byte `QualiaSuperBlock` and `Q42LEX v4` lexicon page containing the term's `NQuin` neighborhood.
2. Implement full **HTTP Content Negotiation (`Accept` header dispatch)** without storing duplicate text files on disk (with **W3C CBOR-LD `application/cbor-ld` (`0xD90501`)** as the native structured linked-data format, never JSON):
   - **`Accept: application/q42` or `application/cbor-ld` (Default Native Format for Qualia / Webizen Clients & APIs)**:
     - Stream the exact 48-byte `NQuin` slice or zero-heap 74-byte W3C CBOR-LD (`0xD9 0x05 0x01`) record, `Q42LEX v4` token page, and Ed25519-signed provenance receipt directly from the memory-mapped `QualiaSuperBlock` in `< 1 ms`.
   - **`Accept: text/turtle`, `application/n-triples` (W3C RDF Text Clients)**:
     - Reconstruct standard W3C RDF serializations on the fly into a caller-supplied fixed stack/response buffer using `query/resolver.rs::format_ntriples_to` and `Q42LEX v4` prefix tables.
   - **`Accept: text/html` (Human Browser Visitors)**:
     - Serve the lightweight HTML shell embedding `webizen-lite-wasm` (640 KiB), rendering the term's multi-language definition (`PayloadCatalogueEntry`), SHACL shape constraints (`shapes/*.shacl.ttl`), deontic modality rules (`0x10–0x12`), and interactive neighborhood graph in the visitor's browser.
3. Implement **HTTP `206 Partial Content` Range Serving**:
   - Support standard `Range: bytes=start-end` requests against `.q42` v4 volumes (`range_volume.rs`) and `QBDL` `.hmc` bundles (`entry.offset + seg.offset`), returning `ETag` / `Digest` headers with per-SuperBlock CRC-32C / SHA-256 verification.

### Task 2.2: Hard Origin Egress Circuit Breaker (`net/qdnf/economics/meters.rs`)
1. Configure `EgressQuotaPolicy` in `net/qdnf/economics/meters.rs`:
   - Allow the VPS steward or cooperative quorum to configure hard daily and monthly ceilings (e.g., `max_monthly_origin_egress_bytes = 1.5 TB`, `max_permitted_overage_usd = $0.00`).
   - Account every outbound response byte at the socket/handler perimeter in $O(1)$ atomic counters (`HotZeroHeap`).
2. Wire the **Circuit Breaker Trip Transition** enforced by Sentinel VM anti-usury opcodes (`governance/coordination.rs`):
   - **Normal State (Below Threshold)**: Origin VPS serves both signed Root Indexes (`< 10 KiB`), term lookups, and range slices directly while advertising peer swarm mirrors via `Alt-Svc` and `Link: rel="duplicate"`.
   - **Tripped State (At or Near Egress Threshold, e.g., US Data-Hub Scraper Surge)**:
     - **Protected Traffic Always Allowed**: The origin continues serving the compact (`< 10 KiB`) Ed25519-signed Root Index (`cbor_ld_manifest.rs` / `BIDX` header) and requests carrying a verified `NaturalAgent` (`did:qi`) or `humanitarian-ict.n3` session credential.
     - **Bulk Range Offload**: All unauthenticated or bulk `.q42` / `.hmc` range requests receive an immediate zero-alloc `HTTP 307 Temporary Redirect` (with `Link: <qpr://...>; rel="duplicate"` and `QResolve` swarm pointers) to the User-Powered Decentralized CDN (`Q-CDN`, `WP-06`) or `HTTP 402 Payment Required` commercial toll gate (`WP-07`).

---

## 4. Verification & Exit Evidence

- [ ] **Sub-2ms Range & Content-Negotiation Latency**: Benchmark confirms `ns.webcivics.net` resolves URI lookups in `< 2 ms` across `application/q42`, `application/cbor-ld` (native default), `application/n-triples`, `text/turtle`, and `text/html` with zero heap allocation (`assert_zero_alloc`) in the `application/q42`, `application/cbor-ld`, and `application/n-triples` hot paths.
- [ ] **US-Hub Traffic Surge Simulation**: Automated load test simulating a 10 Gbps / multi-terabyte scraper surge verifies that `meters.rs` trips the circuit breaker at the exact byte ceiling with **$0.00 overage**, keeping Root Index and verified `NaturalAgent` / Humanitarian ICT queries 100% available.
