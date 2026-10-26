# WP-07 (P1/P2): Permissive Commons Toll Gate, Multi-Chain Micropayments, Coin Exchange Connectors & Post-Quantum DLT Path

**Work Package ID:** `WP-07`  
**Priority:** `P1/P2`  
**Depends On:** [`WP-05`](./WP-05-human-centric-stewardship-groups-and-agents.md), [`WP-06`](./WP-06-user-powered-decentralized-cdn.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/modalities/value_flow.rs`, `crates/qualia-core-db/src/net/qdnf/economics/meters.rs`, `crates/qualia-core-db/src/services/ilp_dispatcher.rs`, `crates/qualia-core-db/src/modalities/consensus.rs`, `crates/qualia-core-db/src/modalities/reconciliation.rs`, `crates/qualia-core-db/src/q42/journal.rs`, `crates/qualia-core-db/src/net/qdnf/crypto/`, `crates/qualia-client-core/` (`chronik.rs`, multi-chain HD wallet)  
- `webizen-host`: `crates/webizen-host-economics/` (HTTP `402` toll gate, `.q42j` obligation pool persistence, multi-chain settlement router, multi-exchange swap connectors, & post-quantum native ledger engine)  

---

## 1. Objective & Design Philosophy

Public-good ontological infrastructure (`ns.webcivics.net`, `WebCivics/ns`, and Ecosphere Assets) must be financially self-sustaining without charging natural persons or humanitarian defenders, and without permitting perpetual SaaS rent extraction ("Ending Digital Slavery"). Users and independent VPS hosts who contribute bandwidth and compute to the `Q-CDN` swarm (`WP-06`) must receive automated micropayments.

### Architectural Principle: Immediate Multi-Chain & Multi-Exchange Functionality + Future-Proof Energy-Cheap Post-Quantum Ledger
No single existing blockchain is 100% trusted for the long term—existing chains carry trade-offs in governance, fee volatility, energy consumption, or classical elliptic-curve (`secp256k1` / `Ed25519`) vulnerability to quantum adversaries. Therefore, **WP-07** enforces a strict architectural separation:
1. **Canonical Accounting in Post-Quantum-Ready `.q42j` Journals**: All `CommonsObligation` pools, `meters.rs` resource accounting, and micropayment receipts are recorded first as canonical 48-byte `NQuin` records inside hash-chained `.q42j` journals.
2. **Pluggable Multi-Blockchain Settlement Rails (Immediate Functionality Today)**: Rather than locking into a single chain, `webizen-host` supports **multiple blockchains and payment rails simultaneously** (eCash/XEC via `chronik.rs`, XRPL, USDC/EVM L2 rails, Bitcoin/Lightning, Solana/low-fee rails, and ILP-STREAM-over-SPSP via `services/ilp_dispatcher.rs`) behind a unified `ChainSettlementAdapter` trait.
3. **Multi-Exchange Connectors & Cross-Coin Swap Routing (`ExchangeConnector`)**: Integrates connectors to **multiple cryptocurrency exchange sites and swap aggregators** so commercial payers can pay in one coin/token while host stewards and `Q-CDN` peer seeders automatically exchange or settle into their preferred coin/currency with best-rate comparison, fee ceilings, and fail-closed slippage guards.
4. **Future-Proof Energy-Cheap & Quantum-Secure Native Ledger**: Defines and progressively activates a native, zero-mining (energy-cheap) **Post-Quantum DAG-CRDT + BFT Ledger** using NIST post-quantum signatures (`ML-DSA-65` / Dilithium, `SLH-DSA` / SPHINCS+, and `ML-KEM-768` in `net/qdnf/crypto/` and `specialized_libs/cryptographic_library/`) + `modalities/consensus.rs` ($f = \lfloor(n-1)/3\rfloor$) and embedded 42 MiB `SlgArena` transaction validation.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` & `webizen-host` | Engineering Action Required |
|---|---|---|
| **Loop 1: Capital Creation Recovery & `10x` Sunset** | `crates/qualia-core-db/src/modalities/value_flow.rs`, `bundle/cbor_ld_manifest.rs`, `q42/journal.rs` | Persist `CommonsObligation` pools (`commons_cost`, `pool_after`, `accumulate_meter_to_pool`, `is_commons_discharged`) into `.q42j` journals so reaching `10x C_obligation` permanently flips the volume to `EnforcePermissiveCommons` (`0b01`). |
| **HTTP `402` Commercial Toll Gate & Natural Person Exemption** | `crates/qualia-core-db/src/net/qdnf/policy_labels/`, `core-ontologies/humanitarian-ict.n3`, `did_qi/` | Grant 0% royalty (`royalty() = 0`) to verified `NaturalAgent` and Humanitarian ICT credentials; require multi-chain / ILP-STREAM micropayment proofs from commercial legal entities and corporate scrapers. |
| **Loop 2: Peer CDN & Swarm Micropayments** | `crates/qualia-core-db/src/net/qdnf/economics/meters.rs`, `value_flow.rs::carriage_fee_from_meters()`, `services/ilp_dispatcher.rs` | Calculate deterministic micro-tariffs from `MeterKind::{Bytes, EnergyJoules, Time, Compute}` and stream payouts to `webizen-desktop` seeders and VPS mirrors. |
| **Multi-Blockchain Settlement Router** | `services/ilp_dispatcher.rs`, `qualia-client-core` (`chronik.rs`, BIP32/BIP44 wallet), `webizen-host-economics/src/chains.rs` | Implement `ChainSettlementAdapter` supporting multiple blockchains concurrently: eCash (`XEC`), XRPL (`XRP`), EVM/L2 Stablecoins (`USDC`/`USDT`), Bitcoin/Lightning (`BTC`), and ILP-STREAM channels. |
| **Multi-Exchange & Cross-Coin Swap Hub** | `webizen-host-economics/src/exchanges.rs`, `modalities/value_flow.rs` | Implement `ExchangeSiteConnector` & `MultiExchangeAggregator` supporting multiple coin exchange sites/APIs for rate quotes, order execution, cross-chain swaps, and anti-usury slippage checks (`check_usury`). |
| **Energy-Cheap Post-Quantum Native Ledger** | `net/qdnf/crypto/`, `specialized_libs/cryptographic_library/`, `modalities/consensus.rs`, `governance/webizen.rs` | Build the quantum-secure (`ML-DSA-65` + `BLAKE3`/`SHA-256` hash-chain) and energy-cheap (zero-PoW BFT + DAG-CRDT) native ledger with embedded 42 MiB `SlgArena` rule enforcement. |

---

## 3. Step-by-Step Implementation Tasks

### Task 7.1: Binding Persistent Obligation Pools to `.q42j` & Asset Manifests (Loop 1)
1. Persist `CommonsObligation` state in `cbor_ld_manifest.rs` and append-only `.q42j` transaction journals (`q42/journal.rs`):
   - Record baseline engineering/curation **Obligation Cost (`C_obligation`)** and capped recovery ceiling ($\le 10 \times C_{\text{obligation}}$ via `commons_cost(production_cost, roi_cap_percent, max_roi_percent)` guarded by `usury_ceiling()` and `check_usury()`).
2. Wire the **HTTP `402 Payment Required` / `QPolicy` Toll Gate**:
   - **Natural Persons & Humanitarian ICT Exemption (`humanitarian-ict.n3`)**: Requests presenting a verified `NaturalAgent` (`did:qi` / `WebizenID-TLS` / ZKP standing proof) or Humanitarian ICT credential evaluate `royalty() = 0` and bypass the toll gate with $0 fee.
   - **Commercial Legal-Entity Toll Collection**: Requests from corporate scrapers, commercial AI training hubs, or incorporated legal entities without a payment proof receive `HTTP 402 Payment Required` advertising all enabled multi-chain payment endpoints and ILP-STREAM SPSP pointers.
   - **Automatic Commons Sunset (`is_commons_discharged`)**: Each verified commercial payment appends a signed N-Quad receipt to `.q42j` and updates the pool via `accumulate_meter_to_pool()`. The instant `is_commons_discharged(pool, cost)` returns `true`, invoke `CommonsObligation::discharge_to_commons()`, permanently setting the volume's routing lane to `PermissiveRoutingLane::EnforcePermissiveCommons` (`0b01`) for all users worldwide.

### Task 7.2: Multi-Blockchain Settlement Router (`ChainSettlementAdapter`)
1. Define a unified, zero-lock-in `ChainSettlementAdapter` trait in `webizen-host-economics`:
   - **Rail 1 — ILP-STREAM Off-Chain Micropayment Packets (`services/ilp_dispatcher.rs`)**: High-frequency per-40 KiB-SuperBlock streaming micropayments logged as signed N-Quad receipts in `.q42j`.
   - **Rail 2 — eCash (`XEC` via `chronik.rs`)**: Sub-cent fees (`~$0.0001`), `< 2s` finality, and `did:qi` UTXO anchoring using the existing in-tree `chronik.rs` indexer and BIP32 wallet.
   - **Rail 3 — XRPL & EVM L2 Stablecoins (`USDC` / `XRP`)**: Extends the existing `ilp_dispatcher.rs` XRPL/USDC settlement hooks for commercial entities paying in fiat-pegged stablecoins or XRP.
   - **Rail 4 — Bitcoin / Lightning (`BOLT11` / `L402`) & Low-Fee L1/L2 Rails**: Pluggable invoice generation and settlement verification for BTC/Lightning and additional configured UTXO/account chains.
2. Allow the host steward (or M-of-N cooperative quorum) to enable, disable, or re-weight supported blockchains dynamically via policy NQuins without restarting the daemon.

### Task 7.3: Multi-Exchange Connectors & Cross-Coin Swap Hub (`ExchangeSiteConnector`)
1. Implement `ExchangeSiteConnector` and `MultiExchangeRouter`:
   - Support multiple coin exchange sites and swap providers simultaneously (e.g., CEX spot/convert REST/WebSocket APIs such as Kraken, Coinbase, Binance, Bitstamp, plus non-custodial cross-chain swap aggregators and DEX routers).
   - **Multi-Source Price & Liquidity Oracle**: Query multiple exchange sites in parallel to compute a median reference exchange rate (rejecting outlier feeds) when converting commercial tolls or CDN seeder payouts between coins (e.g., `XEC` ↔ `USDC` ↔ `BTC` ↔ `XRP` ↔ local currency).
   - **Fail-Closed Slippage & Anti-Usury Guard**: Before executing any coin exchange or cross-chain swap, verify the total exchange fee + spread against `value_flow.rs::check_usury()`. If an exchange site's spread or withdrawal fee exceeds the steward's configured basis-point ceiling, automatically route the swap to the next healthy exchange site or hold in the `.q42j` clearing pool.
   - **Automated Seeder & Steward Payout Conversion**: Allow each `Q-CDN` peer seeder and VPS steward to declare their preferred payout coin in their `did:qi` profile while callers pay in any supported asset.

### Task 7.4: Energy-Cheap & Post-Quantum-Secure Native Ledger Architecture
1. Build the **Post-Quantum Native Ledger (`QualiaPQ-Ledger`)** so the ecosystem is never dependent on vulnerable or energy-wasteful external blockchains:
   - **Zero Proof-of-Work (Energy-Cheap by Design)**: Uses deterministic DAG-CRDT causal ordering (`.q42j` hash-chained journals + `modalities/reconciliation.rs`) combined with lightweight BFT quorum finality (`modalities/consensus.rs`, $f = \lfloor(n-1)/3\rfloor$) and energy metering (`MeterKind::EnergyJoules` in `meters.rs`). Zero mining, zero wasted electricity.
   - **Post-Quantum Cryptographic Primitives**:
     - Hybrid classical + NIST post-quantum transaction and block signatures: `Ed25519` + **`ML-DSA-65` (FIPS 204 Dilithium)** and **`SLH-DSA` (FIPS 205 Stateless Hash-Based Signatures)** for long-term archival anchors, paired with **`ML-KEM-768` (FIPS 203 Kyber)** transport encryption and `BLAKE3` / `SHA-256` Merkle commitments.
   - **Embedded 42 MiB `SlgArena` Consensus Validation**: Every validator node runs `governance/webizen.rs` over candidate transactions so `check_usury()`, `10x` `CommonsObligation` sunset, and `NaturalAgent` / Humanitarian ICT fee exemptions are enforced directly at consensus.

---

## 4. Verification & Exit Evidence

- [ ] **Natural Person & Humanitarian ICT $0 Exemption Test**: Requests with a valid `NaturalAgent` or `humanitarian-ict.n3` proof always receive `200 OK` / `206 Partial Content` with `royalty() == 0`.
- [ ] **Multi-Chain Commercial Toll & Durable `10x` Sunset Test**: Commercial requests settle payments across at least two distinct blockchain adapters (e.g., `chronik.rs` XEC and `ilp_dispatcher.rs` USDC/XRPL) into `.q42j` N-Quad receipts; reaching $10 \times C_{\text{obligation}}$ permanently flips the volume to `EnforcePermissiveCommons` (`0b01`).
- [ ] **Multi-Exchange Coin Conversion & Failover Test**: `MultiExchangeRouter` fetches quotes from multiple exchange connectors, rejects an artificially inflated-fee quote via `check_usury()`, and routes the coin exchange through the lowest-cost healthy exchange connector to pay a `Q-CDN` seeder.
- [ ] **Post-Quantum & Energy-Cheap Ledger Receipt**: Native `.q42j` BFT committee finalizes a batch of CDN bandwidth credits signed with hybrid `Ed25519 + ML-DSA-65` post-quantum signatures at `< 1 Joule` compute energy cost.
