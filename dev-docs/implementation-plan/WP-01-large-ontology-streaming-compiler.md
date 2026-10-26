# WP-01 (P0): Streaming Large Ontology Compiler (`>100 MB` `WebCivics/ns`)

**Work Package ID:** `WP-01`  
**Priority:** `P0` (Critical Path Foundation)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/q42/`, `crates/qualia-core-db/src/modalities/logic/owl/`, `crates/qualia-core-db/src/bundle/`, `crates/vibe/src/vocab/`, `crates/qualia-cli/src/ingest/`  
- `webizen-host`: `crates/webizen-host-ingest/` (host daemon ingestion supervisor & staging manager)  

---

## 1. Objective & Problem Statement

Standard semantic web tools, cloud repositories, and browser/mobile runtimes fail when importing or parsing massive ontological source repositories exceeding 100 MB—most notably [`https://github.com/WebCivics/ns`](https://github.com/WebCivics/ns) alongside the 102 UN/OHCHR/ICRC human-rights instruments in `core-ontologies/`, Australian Bureau of Statistics (ABS) datasets, medical/chemical ontologies (SNOMED, ChEBI, QUDT, DICOM/RadLex), and Ecosphere Assets species corpora.

**WP-01** implements a supervised, **Tier 2 `ColdBounded`** streaming and **incremental over-time** ontology ingestion and compilation pipeline that:
1. **Checks the Network First ("Verify-Before-Rebuild" Deduplication)**: Queries QDNF (`QResolve`), IPFS/IPNS, and WebTorrent peer manifests to check if a compiled `.q42` v4 / `QBDL` `.hmc` artifact for the target `(repo_url, commit_hash, schema_version)` already exists on the network. If an existing network build passes full cryptographic, CRC-32C/SHA-256, `Q42LEX v4`, and SHACL-first non-`owl:Thing` verification, the VPS adopts and seeds it immediately without redundant re-processing. It only re-compiles if no build exists or if existing network versions fail verification (quarantining the faulty build).
2. **Processes Large Ontologies Incrementally Over Time**: Executes resumable, checkpointed background compilation jobs across multi-hundred-megabyte corpora (`WebCivics/ns` >100 MB, SNOMED, ChEBI, QUDT, ABS, GBIF) in bounded time/memory slices without starving live VPS services.
3. **Emits Range-Addressable Multi-Protocol Containers**: Enforces SHACL-first non-`owl:Thing` uplift for human-centric classes, interns all strings into the v4 namespaced paged lexicon (`Q42LEX v4`), completes `FLAG_PAYLOAD_CATALOGUE` (`0x0080`), and emits HTTP-Range, IPFS/CAR, and WebTorrent-ready **`.q42` v4 semantic volumes**, **`QBDL` `.hmc` hypermedia bundles**, and **`.vibe` / `VBC1` vocabulary chunks** within a strict **256 MiB** memory ceiling.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **Source Sync & Provenance** | `crates/qualia-core-db/src/q42/source_catalogue/`, `q42/asset_import/`, `q42/asset_envelope/` | Add git/archive chunked staging puller with per-file BLAKE3 + SHA-256 digests, git commit tree recording, and fail-closed upstream license unioning in `asset_envelope/`. |
| **Streaming Chunk Parser** | `crates/qualia-core-db/src/query/ingest*.rs`, `n3_parser.rs`, `yaml_ld_q42.rs` | Wire chunked streaming readers for RDF/XML, Turtle, N-Triples, JSON-LD, YAML-LD, and Notation3 (`=>`, `~>`, `^>`, `-o`) bounded by a 256 MiB `ColdBounded` arena budget. |
| **Namespaced Paged Lexicon** | `crates/qualia-core-db/src/q42/q42_lex_ns.rs`, `lexicon.rs` | Enforce `IngestMode::Complete` (never `StripLiterals`) paired with `Q42LEX v4` prefix deduplication, 60-bit masked tokens (`0x0FFF_FFFF_FFFF_FFFF`), and 64-bit FNV-1a `q_hash()`. |
| **OWL 2 RL & SHACL Uplift** | `crates/qualia-core-db/src/modalities/logic/owl/materialize.rs`, `owl/shacl_convert.rs`, `shacl_compiler.rs` | Connect `Library-only` `owl/materialize.rs` and `owl/shacl_convert.rs` into the production ingest pipeline; enforce non-`owl:Thing` uplift into `shapes/*.shacl.ttl` and `SlgOpcode` bytecode (`0x10–0x44`). |
| **`.q42` v4 Volume & Payload Catalogue** | `crates/qualia-core-db/src/q42/q42_volume.rs`, `bundle/cbor_ld_manifest.rs` | Complete `FLAG_PAYLOAD_CATALOGUE` (`0x0080`, ADR 0014) read/write implementation in `q42_volume.rs` with full parity to `PayloadCatalogueEntry`. |
| **`QBDL` `.hmc` & `.vibe` Packaging** | `crates/qualia-core-db/src/bundle/format.rs`, `crates/vibe/src/vocab/` | Emit domain-sharded `QBDL` `.hmc` bundles (64-B aligned entries + CBOR footer + CRC-32C) and tree-shaken `.vibe` / `VBC1` vocabulary chunks. |

---

## 3. Step-by-Step Implementation Tasks

### Task 1.1: Network-Wide "Verify-Before-Rebuild" Deduplication & Resumable Over-Time Job Queue
1. Implement `VerifyBeforeRebuildGate` in `webizen-host-ingest`:
   - Before compiling an ontology repository (`(repo_url, commit_hash, compiler_version)`), query the network (`QResolve`, IPFS CIDs, WebTorrent info-hashes) for existing compiled `.q42` v4 volumes.
   - Verify any discovered candidate volume: check source commit/SHA-256 match, SuperBlock CRC-32C digests, `IngestMode::Complete` lexicon integrity, and zero `owl:Thing` human/living subclasses.
   - **Adopt if Valid**: If a network candidate passes 100% of checks, adopt and pin/seed it directly without re-processing.
   - **Rebuild on Fault**: If no candidate exists—or if the network candidate fails integrity or SHACL-first checks—mark the faulty network candidate quarantined and schedule a local compilation job.
2. Implement `IncrementalCompilationJob` for **Over-Time Background Processing**:
   - Partition massive ontology repositories (`>100 MB` `WebCivics/ns`, medical/scientific corpora) into checkpointed work slices that run incrementally over time under idle CPU/IO budgets and persist progress between ticks or daemon restarts.
3. Implement `StagingRepoSync` in `q42/asset_import/`:
   - Clone or incremental-fetch `https://github.com/WebCivics/ns` (and configured mirrors) into a marker-verified staging directory (`/var/lib/qualia/staging/ns/` on Linux VPS or caller-configured scratch `TempDir`).
   - Walk the file tree deterministically (lexicographical path order) and compute `BLAKE3` and `SHA-256` digests for every `.rdf`, `.ttl`, `.n3`, `.owl`, `.jsonld`, and `.yaml` source file.
4. Validate license metadata through `q42/asset_envelope/`:
   - Any unrecognized or missing upstream license fails closed before compilation.
   - Derived `.q42` volumes and `.hmc` bundles automatically inherit the union of upstream obligations (including `PermissiveCommons` and attribution terms).

### Task 1.2: Bounded Streaming Multi-Format Parser & `Q42LEX v4` Interning
1. Configure the streaming parser pipeline (`query/ingest*.rs`, `n3_parser.rs`) to read large RDF/XML and Turtle files in fixed 64 KiB stream buffers rather than building a full in-memory DOM.
2. Enforce `IngestMode::Complete` across all ontology builds:
   - Intern every IRI prefix and local name into `Q42LEX v4` (`q42_lex_ns.rs`), storing 60-bit masked tokens (`generate_60bit_token`) in range-addressable lexicon pages.
   - Pack inline `xsd:integer` (`0b001 << 60`), `xsd:decimal` (`0b010 << 60`), and `xsd:boolean` (`0b011 << 60`) per `resolver.rs` rules, and `did:q42` topological pointers (`MSB = 1`) per `identifier.rs`.
   - Record malformed triples in a quarantine counter receipt without panicking or leaking memory.
3. Enforce the **256 MiB `ColdBounded` Arena Budget**:
   - Check allocation sizes prior to growing any cold construction buffer; fail closed with `IngestError::BudgetExhausted` if the caller's byte budget is exceeded.

### Task 1.3: Wiring `owl/materialize.rs` & `owl/shacl_convert.rs` (SHACL-First Non-Thing Uplift)
1. Wire `modalities/logic/owl/shacl_convert.rs` and `owl/materialize.rs` directly into `qualia-cli/src/ingest/` and `q42/asset_import/`:
   - **Normative Non-Thing Gate**: Inspect all imported class hierarchies against `docs/manuals/standards/shacl-first-vs-owl-ok-class-list.md`.
   - Any class representing natural persons (`NaturalAgent`), children/dependents, kinship, human relations, or living ecological entities that subclasses `owl:Thing` in legacy source files is automatically rewritten to `rdfs:Class` + W3C SHACL shape constraints (`shapes/*.shacl.ttl`).
2. Compile uplifted SHACL shapes and N3 rules (`=>` strict, `~>` defeasible, `^>` defeater, `-o` linear) via `shacl_compiler.rs` and `governance/webizen_bytecode.rs` into deterministic `SlgOpcode` bytecode:
   - Deontic (`0x10–0x12`, with `^>` defeaters setting `DEFEATER_BIT` in `predicate[63]`), Epistemic (`0x20–0x22`), Paraconsistent (`0x30–0x32`), and LTL (`0x40–0x44`).

### Task 1.4: Completing `FLAG_PAYLOAD_CATALOGUE` (`0x0080`, ADR 0014) in `q42_volume.rs`
1. Upgrade `q42_volume.rs` to serialize and deserialize the `FLAG_PAYLOAD_CATALOGUE` (`0x0080`) section with byte-exact parity against `bundle/cbor_ld_manifest.rs` (`PayloadCatalogueEntry`):
   - Support multi-language prose definitions, SHACL shape pack descriptors, and provenance sidecars indexed alongside the 40,960-byte LZ4 `QualiaSuperBlock`s (853 × 48-byte `NQuin`s per SuperBlock) and `BIDX` block index.
2. Emit domain-sharded **`QBDL` `.hmc` Hypermedia Bundles** (`bundle/format.rs`):
   - 64-byte header (`QBDL` v1 magic), 64-byte page-aligned intact entries (`.q42` sub-volumes, `law_packages.rs`, `.10d` manifolds, and `PayloadCatalogueEntry` attachments), trailing CBOR index footer (`offset`, `length`, `sha256`), and whole-file CRC-32C.
3. Emit tree-shaken **`.vibe` / `VBC1` Vocabulary Chunks** (`crates/vibe/src/vocab/`) for high-frequency WebCivics and human-rights predicates so `VibeScript 0.1` and the 640 KiB `webizen-lite-wasm` kernel can load them with zero string-table bloat.

---

## 4. Verification & Exit Evidence

- [ ] **Memory Ceiling Verification**: Compiling the entire `https://github.com/WebCivics/ns` repository (>100 MB) + `core-ontologies/` (102 human-rights instruments) completes within the **256 MiB** `ColdBounded` budget with zero OOMs.
- [ ] **Round-Trip Graph Integrity**: `qualia-cli verify-graph --encoder=import` passes 100% on the generated `.q42` v4 volumes and `QBDL` `.hmc` bundles.
- [ ] **SHACL-First Non-Thing Audit**: Automated test asserts zero `NaturalAgent`, kinship, or ecological species classes remain subclassed under `owl:Thing` in compiled volumes.
- [ ] **`FLAG_PAYLOAD_CATALOGUE` (`0x0080`) Parity Test**: Round-trip test in `q42_volume.rs` verifies `PayloadCatalogueEntry` read/write parity with `cbor_ld_manifest.rs`.
- [ ] **Range-Slice Benchmark**: `range_volume.rs` extracts a single 40 KiB `QualiaSuperBlock` and resolves terms via `Q42LEX v4` without reading the full volume.
