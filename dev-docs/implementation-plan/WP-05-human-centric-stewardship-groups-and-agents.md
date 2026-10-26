# WP-05 (P1): Human-Centric Person, Family, Group & Agent Stewardship

**Work Package ID:** `WP-05`  
**Priority:** `P1`  
**Depends On:** [`WP-03`](./WP-03-nquin-dns-and-qdnf-relay.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/identity/agency.rs`, `crates/qualia-core-db/src/did_qi/`, `crates/qualia-core-db/src/specialized_libs/cryptographic_library/`, `crates/qualia-core-db/src/foundation/crdt.rs`, `crates/qualia-core-db/src/modalities/capacity.rs`, `crates/qualia-core-db/src/modalities/delegation.rs`, `crates/qualia-core-db/src/modalities/jural.rs`, `crates/qualia-core-db/src/governance/illocution.rs`, `crates/qualia-core-db/src/governance/coordination.rs`, `crates/qualia-core-db/src/domains/geospatial/stewardship.rs`, `crates/qualia-cooperative-core/`, `crates/qualia-peer/`, `crates/wellfare-core/src/guardianship.rs`  
- `webizen-host`: `crates/webizen-host-stewardship/` (stewardship quorum gate, pairing relay, & encrypted `.q42j` backup service)  

---

## 1. Objective & Problem Statement

A core requirement of the specification is that a server *"should either be owned by a group (many natural persons) or a natural person, it may act to extend local services to an online location to support personal info, or be used to support community / group resources, etc."* using **Human-Centric** and international **human-rights** concepts (human dignity, legal capacity, guardianship for dependents/infants, freedom of thought, and cooperative stewardship—never "sovereign" or "self-sovereign").

**WP-05** implements the cryptographic and jural root of `webizen-host`:
1. Strict separation of the **Who-Plane (`NaturalAgent` / `did:qi`)** from the **Handle-Plane (`DNI` / ICANN DNS / ABN)** with `Collapse Detector` continuity (`Handle revoke ≠ who-erase`).
2. Strict **"Church & State" Vault Separation** (`TheWebizenAgent` / Sanctuary Keep strictly on local hardware; `PermissiveCommonsTech` shared state and client-encrypted `.q42j` Shamir backups on the VPS).
3. Upgrading `derive_lane_key` in `identity/agency.rs` to memory-hard **Argon2id + HKDF**.
4. Supporting all **Four Human-Centric Stewardship & Agency Modes**: Single Natural Person, Family/Household (`GuardianshipSemantics`), Multi-Person Group/Community/Cooperative (`M-of-N` Steward Quorum), and Governed Autonomous/Service Agents (`core-ontologies/agent-accountability.n3`).

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **Memory-Hard Multi-Tenant Lane Keys** | `crates/qualia-core-db/src/identity/agency.rs`, `specialized_libs/cryptographic_library/` | Upgrade `derive_lane_key(pin, salt)` from single-pass SHA-256 to Argon2id + HKDF for per-member Sanctuary Keep lane isolation. |
| **Local ↔ VPS Pairing & Sanctuary Keep Backup** | `crates/qualia-peer/` (`PeerHost::pair`, `exchange_protected`), `q42/journal.rs`, `qualia-client-core` | Wire 1-click pairing between local `webizen-desktop` (`:8080`) and VPS (`:4242`) using ML-KEM-768 + Ed25519; store only client-encrypted `.q42j` backup segments recoverable via M-of-N Shamir secret shares (`qualia-cli vault recover`). |
| **Family Guardianship & Legal Capacity** | `crates/wellfare-core/src/guardianship.rs`, `modalities/capacity.rs` | Enforce `GuardianshipRelations` / `GuardianshipSemantics` and age/capacity-gated sandboxes for infants, children, and supported dependents under a shared family domain. |
| **M-of-N Cooperative Quorum & Dissent Retention** | `crates/qualia-cooperative-core/`, `foundation/crdt.rs` (`SuspendedTransactionQueue`), `domains/geospatial/stewardship.rs`, `governance/illocution.rs` | Gate privileged host mutations behind M-of-N steward signatures in the 32-slot `SuspendedTransactionQueue` with explicit-denial guards and paraconsistent (`0x30–0x32`) dissent retention. |
| **Governed Service & AI Agents** | `crates/qualia-core-db/src/modalities/delegation.rs` (ZCAP-LD), `governance/coordination.rs` (`0x70–0x7F`), `core-ontologies/agent-accountability.n3` | Enforce capability-bounded ZCAP-LD delegation chains tracing every software/AI agent action back to the authorizing `NaturalAgent` or cooperative quorum. |

---

## 3. Step-by-Step Implementation Tasks

### Task 5.1: Hardening `derive_lane_key` (`identity/agency.rs`) with Argon2id + HKDF
1. Replace the single-pass SHA-256 implementation of `derive_lane_key(pin, salt)` in `crates/qualia-core-db/src/identity/agency.rs` with memory-hard **Argon2id** (backed by `specialized_libs/cryptographic_library`) followed by **HKDF-SHA256** domain separation (`"qualia.sanctuary.lane.v1"`).
2. Preserve `compute_scoped_merkle_root(frame, author_did_hash)` zero-allocation iteration over `&[NQuin]` via `bytemuck::cast_ref`.

### Task 5.2: Who-Plane (`NaturalAgent`) ≠ Handle-Plane (`DNI`/DNS) & `Collapse Detector`
1. Anchor all human stewards and members on the **Who-Plane** via `NaturalAgent` + self-certifying `did:qi` (`did_qi/` signed `QCDE-1` lifecycle vectors) and hardware/local `key_vault.rs`.
2. Bind ICANN domain names (`ns.webcivics.net`, `civics.au`), IPv4/IPv6 addresses, ABNs, and expiring `DNI` locators strictly on the **Handle-Plane**.
3. Wire the **`Collapse Detector`**:
   - If an ICANN domain expires, fails renewal, or is seized by a registrar, transition the domain handle to `held/closed` on the locator plane while keeping 100% of `NaturalAgent` identities, family/cooperative memberships, and `.q42` / Sanctuary Keep volumes intact and reachable over native QDNF (`QResolve`) or any newly attached domain handle.

### Task 5.3: Local `webizen-desktop` (`:8080`) ↔ VPS (`:4242`) Pairing & "Church & State" Separation
1. Implement the 1-click pairing workflow (`qualia-cli host pair` / Poet UI) using `PeerHost::pair` and `exchange_protected` (post-quantum ML-KEM-768 handshakes in `net/qdnf/crypto/handshake/` + Ed25519 signatures over `SocialWebNet` WireGuard or CSCP WSS/HTTP2 capsules).
2. Enforce the cryptographic **Church & State Vault Boundary**:
   - **Church Vault (`TheWebizenAgent` / Sanctuary Keep)**: Deeply personal biographical, health (`wellfare-core`), and unshared consciousness/thought records remain strictly on local hardware (`:8080`), never mounted unencrypted on the VPS.
   - **State Vault (`PermissiveCommonsTech` on the VPS)**: Shared social records, public websites, and `ValuesCredentials`-governed ontologies (`entity_view/rights_filter.rs` + `net/qdnf/policy_labels/`).
   - **Client-Encrypted `.q42j` Off-Site Backup**: Local Sanctuary Keep backups sent to the VPS are encrypted client-side before transmission as append-only `.q42j` segments and can only be decrypted locally via `qualia-cli vault recover` using M-of-N Shamir secret shares.

### Task 5.4: Four Human-Centric Stewardship & Agency Archetypes
1. **Archetype 1 — Single Natural Person (`NaturalAgent`)**:
   - 1-of-1 root `did:qi` authority + ZCAP-LD (`modalities/delegation.rs`) sub-key delegation to personal devices (desktop, laptop, `qualia-mobile-harness` PWA).
2. **Archetype 2 — Family / Household Collective (`GuardianshipSemantics`)**:
   - 1–2+ adult `NaturalAgent` co-stewards + dependent profiles (infants, children, elders/dependents) governed by `wellfare-core/src/guardianship.rs` (`GuardianshipRelations`) and legal capacity rules (`modalities/capacity.rs`), with per-member Argon2id Sanctuary Keep lanes.
3. **Archetype 3 — Multi-Person Group / Community / Cooperative (`M-of-N` Steward Quorum)**:
   - Wire privileged server mutations (DNS zone updates, canonical ontology admissions, egress cost-cap changes, micropayment pool disbursements) into the 32-slot **`SuspendedTransactionQueue`** (`foundation/crdt.rs`).
   - Require `M-of-N` designated steward signatures (`domains/geospatial/stewardship.rs` with explicit-denial guard and BFT `f = ⌊(n-1)/3⌋` in `modalities/consensus.rs`) before atomic execution.
   - Retain conflicting steward policy proposals via **Paraconsistent Logic (`0x30–0x32`)** and Hohfeldian correlative-gap detection (`modalities/jural.rs`, `governance/illocution.rs`), flagging `RequiresHumanReview` rather than overwriting dissent.
   - Support Indigenous Traditional Knowledge / Biocultural labels via `governance/tk_bc_labels.rs`.
4. **Archetype 4 — Governed Autonomous & Service Agents**:
   - Enforce `core-ontologies/agent-accountability.n3` (*"Natural persons are not identity assets; instruments are not peers"*).
   - Require every automated curator, bot, or `services/swarm/` worker to present an attenuated ZCAP-LD delegation chain (`modalities/delegation.rs`) and execute under Sentinel coordination opcodes (`0x70 OP_AUTHORIZATION_GRANT`, `0x71 OP_RESOURCE_DECLARATION`, `0x72 OP_PERFORMANCE_RATING` in `governance/coordination.rs`).

---

## 4. Verification & Exit Evidence

- [ ] **Argon2id + HKDF Lane Key Test**: Unit and integration tests in `identity/agency.rs` verify deterministic Argon2id + HKDF key derivation and per-member vault isolation.
- [ ] **Handle Revoke ≠ Who-Erase (`Collapse Detector`) Audit**: Simulating ICANN domain seizure transitions the domain handle to `held/closed` while `QResolve` continues resolving all `NaturalAgent`, family, and cooperative volumes 100%.
- [ ] **Church & State Sanctuary Keep Audit**: Inspecting VPS storage during `:8080` ↔ `:4242` pairing confirms zero plaintext Sanctuary Keep triples exist on the VPS; `qualia-cli vault recover` restores encrypted `.q42j` segments using M-of-N Shamir shares.
- [ ] **All Four Stewardship Modes Pass Conformance**: Automated tests verify Single Person, Family (`GuardianshipSemantics` + `capacity.rs`), Cooperative (`M-of-N` `SuspendedTransactionQueue` + paraconsistent dissent retention), and Governed Agent (`ZCAP-LD` + `0x70–0x72`) execution gates.
