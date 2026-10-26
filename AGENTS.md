# Webizen-Host — Agent Coordination, Human-Centric Nomenclature & Architectural Rules

## Intellectual Property & Licensing Notice

QualiaDB, the Qualia App Framework, Webizen-Host, and all Qualia/Webizen-specific architectures, integrations, modifications, and extensions are governed by:

**Copyright (c) 2026 Timothy Charles Holborn**  
**https://www.linkedin.com/in/ubiquitous/ | timothy.holborn@gmail.com**  
**License:** Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)  

---

## 0. Mandatory Human-Centric & Human-Rights Terminology Rule

All documentation, code identifiers, CLI flags, ontology predicates, and UI copy across `webizen-host` **must strictly avoid** the terms `sovereign`, `sovereignty`, or `self-sovereign`:
- **Rationale**: The purpose of this platform is **Human-Centric** systems grounded in international human-rights instruments ([OHCHR Core International Human Rights Instruments](https://www.ohchr.org/en/instruments-listings)), which never describe natural persons or their dependents (such as infants, children, or persons supported under guardianship and legal capacity frameworks) as "sovereign" or "self-sovereign".
- **Required Nomenclature**:
  - Use **Human-Centric**, **Personal & Family Stewardship**, **Human Agency**, **Guardianship & Capacity Semantics** (`GuardianshipRelations`, `modalities/capacity.rs`), **Cooperative Quorum Stewardship**, **Sanctuary Keep** (*Freedom of Thought*), and **Relationship-Scoped Mail**.
  - Honour the foundational invariant: *"Natural persons are not identity assets; instruments are not peers"* (`core-ontologies/agent-accountability.n3`).
  - Enforce the **SHACL-First Non-Thing Rule**: Natural persons (`NaturalAgent`), kinship, human relations, and living ecological entities are `rdfs:Class` + SHACL/ShEx and **must never subclass `owl:Thing`**.

---

## 1. QualiaDB Engine Immovable Rules (Inherited from `c:\github\qualiaDB\AGENTS.md`)

1. **Two-Tier Zero-Heap Model (`AGENTS.md` §0-A)**:
   - **Tier 1 (`HotZeroHeap`)**: Hot-path DNS resolution, virtual namespace range-slice lookups, deontic/SHACL policy checks, and byte/dollar metering gates must allocate **zero heap memory** (`no Vec/String/Box`), operating over caller-supplied `&mut [T]` slices and 48-byte `NQuin` buffers.
   - **Tier 2 (`ColdBounded`)**: Cold-path ontology ingestion (`>100 MB` `WebCivics/ns`), SHACL uplift, and `.q42` v4 / `QBDL` `.hmc` packaging run under an explicit caller-owned byte budget (default **256 MiB**) and **fail closed** on budget exhaustion.
2. **48-Byte `NQuin` ABI & `q_hash()`**: All semantic quads, DNS records, and ledger receipts fit the 48-byte `NQuin` structure; all IRIs use 64-bit FNV-1a `q_hash()` with 60-bit masked `Q42LEX v4` tokens.
3. **42 MiB `SlgArena` Sentinel**: Per-tenant reasoning cells are isolated within 42 MiB `SlgArena` bounds with non-recursive evaluators.
4. **Library Structure & Temporary-Artifact Hygiene (`AGENTS.md` §0-B)**:
   - New capabilities are directory-backed libraries (`mod.rs` routing + focused single-purpose files `< 500` lines).
   - Temporary files use bounded `tempfile::TempDir` with RAII cleanup.
5. **Multi-Chain, Multi-Exchange & Future-Proof Post-Quantum DLT (`WP-07`)**:
   - Support multiple blockchains (`XEC`, `XRPL`, `USDC`, `BTC/Lightning`, `ILP-STREAM`) and multiple coin exchange sites (`ExchangeSiteConnector`) for immediate payment and conversion functionality, while anchoring canonical truth in `.q42j` journals backed by an **energy-cheap (zero-PoW BFT/DAG-CRDT), post-quantum-secure (`ML-DSA-65` / `SLH-DSA` / `ML-KEM-768`)** native ledger.

---

## 2. Implementation Plan Reference

See [`dev-docs/implementation-plan/00-MASTER-IMPLEMENTATION-PLAN.md`](dev-docs/implementation-plan/00-MASTER-IMPLEMENTATION-PLAN.md) for the complete Work Package breakdown (`WP-01` through `WP-08`).
