# WP-04 (P1): Native QApp Runtime & Three-Tier Multi-Tenant Sandbox

**Work Package ID:** `WP-04`  
**Priority:** `P1`  
**Depends On:** [`WP-01`](./WP-01-large-ontology-streaming-compiler.md)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-app-contract/`, `crates/vibe/`, `crates/poet/`, `crates/qualia-solid-bridge/`, `crates/qualia-core-db/src/governance/cell_graph.rs`, `crates/qualia-core-db/src/q42/app_manifest/`, `crates/qualia-core-db/src/q42/app_registry/`, `crates/qualia-core-db/src/simulation/fixed_tick.rs`, `crates/qualia-core-db/src/agent_runtime/`, `crates/qualia-client-core/src/chat_graph.rs`  
- `webizen-host`: `crates/webizen-host-sandbox/` (`HostSandboxManager` & multi-tenant cell orchestrator)  

---

## 1. Objective & Problem Statement

Legacy hosting control panels (cPanel/WHM, Plesk) rely on heavyweight OS virtual machines, Docker containers, or insecure shared scripting runtimes (PHP, Node.js/V8) that are vulnerable to cross-tenant memory/CPU starvation and cannot natively execute QualiaDB/Webizen applications (`.q42` volumes, `VibeScript` `VBC1` reactive cells, `.10d` / `.hmc` 3D/10D spatial worlds, or branching-conversation `chat_graph.rs` DAGs).

**WP-04** builds the **`HostSandboxManager`** and **Native QualiaDB / Webizen Application Server**, isolating every tenant, domain, and application inside a deterministic **Three-Tier Sandbox Architecture** while providing first-class hosting for all four native QualiaDB/Webizen application families.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **Tier 1: VibeScript (`VBC1`) & 42 MiB `SlgArena` Cells** | `crates/vibe/` (`budget.rs`, `effects.rs`, `deontic_interrupt.rs`, `catalog/ids.rs`, `reactive_cell.rs`), `governance/cell_graph.rs` | Build `HostSandboxManager` to run per-tenant `VBC1` chunks with mandatory `u64` instruction budgets, fail-closed `using {Family};` capability leases, and isolated 42 MiB `SlgArena` cells. |
| **Tier 2: Portable QApps & WASM Isolates** | `crates/qualia-app-contract/` (`SDK-01..10`), `q42/app_manifest/`, `q42/app_registry/`, `wasm_storage.rs` | Host versioned QApps, `vibe-wasm` modules, and the 640 KiB `webizen-lite-wasm` Ontology MCP endpoint mounted on scoped virtual volume prefixes with `.q42j` CRDT session sync. |
| **Tier 3: W3C Solid LDP Pods & Linux/eBPF Sandbox** | `crates/qualia-solid-bridge/`, `crates/qualia-core-db/src/net/` (eBPF filter) | Mount per-user and per-group W3C Solid Pods (matching `web.civics.au` Turtle↔`NQuin` boundary) and unprivileged Linux namespaces (user/mount/PID/net) guarded by cgroups + eBPF socket bandwidth quotas. |
| **3D/10D Spatial & Agentic App Services** | `webizen-render`, `simulation/fixed_tick.rs`, `qualia-client-core/src/chat_graph.rs`, `agent_runtime/orchestration.rs` | Serve progressive `.10d` Living Containers and `.hmc` bundles with authoritative 20 Hz `fixed_tick.rs` world reducers, plus branching `chat_graph.rs` DAGs and neuro-symbolic blackboards. |

---

## 3. Step-by-Step Implementation Tasks

### Task 4.1: Sandbox Tier 1 — VibeScript (`VBC1`) & 42 MiB `SlgArena` Cellular Isolation
1. Implement `Tier1VibeCell` in `HostSandboxManager`:
   - Allocate an isolated **42 MiB `SlgArena` Sentinel Cell** (`governance/cell_graph.rs`) per active tenant/app cell, connected solely via `PermissiveRoutingLane` (`00=Passthrough`, `01=Commons`, `10=Bilateral`, `11=Spatial`) channels.
   - Enforce mandatory `u64` execution cycle budgets (`vibe/src/budget.rs`) on every `VBC1` function call so runaway loops terminate deterministically at the exact cycle limit without impacting sibling tenants.
   - Enforce the effect lattice (`Pure < Hot < Cold < Async < External` in `vibe/src/effects.rs`) and fail-closed `using {Family};` capability leases (`deontic_interrupt.rs`) across the ~1,158 host catalog operations (`vibe/src/catalog/ids.rs`).
2. Expose `vibe-play` (`:7420`) and `vibe-lsp` developer endpoints for authorized sandbox stewards.

### Task 4.2: Sandbox Tier 2 — Portable QApps (`qualia-app-contract`) & WASM Isolates
1. Wire `QAppHostRegistry` (`q42/app_manifest/`, `q42/app_registry/`):
   - Validate and mount compiled QApp bundles conforming to `crates/qualia-app-contract` (`GA-17` / `SDK-01..10` command, context, session, and surface contracts).
   - Restrict each QApp isolate to its own scoped virtual volume prefix (`wasm_storage.rs`) and typed command/event ring buffers.
   - Synchronize multi-user and multi-agent application state over append-only `.q42j` session journals (`GameSessionJournal`) and Lamport/LWW CRDT merges (`foundation/crdt.rs`, `sync.rs`).

### Task 4.3: Sandbox Tier 3 — W3C Solid LDP Pod Bridge & Linux/eBPF Container Perimeter
1. Integrate `crates/qualia-solid-bridge` into `webizen-host`:
   - Provision per-person, per-family, and per-group W3C Solid LDP Pods (compatible with the MIT baseline deployed on [`web.civics.au`](https://web.civics.au/)).
   - Enforce the strict Turtle/JSON-LD ↔ 48-byte `NQuin` translation boundary so users can run standard W3C Solid applications or export/migrate their data at any time.
2. Implement the Linux Namespace + eBPF Perimeter for static HTML5/CSS sites and legacy Web 2.0 workloads:
   - Spawn unprivileged Linux `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET` containers with read-only root mounts and cgroup v2 CPU/RAM ceilings.
   - Attach `qualia-core-db`'s native eBPF socket filter (`net/`) to enforce per-sandbox ingress/egress bandwidth ceilings and block unauthorized outbound connections.

### Task 4.4: First-Class 3D/10D Spatial (`.10d` / `.hmc`) & Agentic DAG Hosting
1. Wire progressive streaming and authoritative simulation for `.10d` Living Containers (`QuantizedMesh`, `Tensor10DNodes`, `SkeletalAnimation` `SKL1`, `EntityOntology` `EONT1`, `SurfaceReading` `SRD1`, `HyperspectralCube`) and `QBDL` `.hmc` bundles paired with 20 Hz fixed-timestep world reducers (`simulation/fixed_tick.rs`).
2. Host the Branching-Conversation Chat DAG (`qualia-client-core/src/chat_graph.rs`), symbolic multi-agent blackboards (`agent_runtime/orchestration.rs`), grammar-constrained VibeScript synthesis (`domino_gbnf.rs` + `neuro_symbolic_sieve.rs`), and `.p64` model weight streaming (`q42/p64_weight.rs`).

---

## 4. Verification & Exit Evidence

- [ ] **Deterministic Cycle-Budget Halt Test**: A malicious/infinite-loop `VBC1` script halts at its exact `u64` cycle budget with zero heap allocation (`HotZeroHeap`) and zero latency impact on sibling 42 MiB `SlgArena` cells.
- [ ] **Fail-Closed Capability Lease Test**: A `VBC1` chunk or QApp attempting to invoke any of the ~1,158 host catalog operations without a matching `using {Family};` manifest lease is rejected by `deontic_interrupt.rs`.
- [ ] **W3C Solid LDP Conformance**: Hosted `qualia-solid-bridge` pods pass W3C Solid LDP read/write/ACL round-trip conformance tests.
- [ ] **Portable QApp & `.10d` Execution Receipt**: A `qualia-app-contract` QApp and a `.10d`/`.hmc` spatial scene synchronize state across `webizen-desktop` and browser WASM via `.q42j` journals.
