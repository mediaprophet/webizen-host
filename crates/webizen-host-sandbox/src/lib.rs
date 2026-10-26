//! WP-04 (P1): Native QApp Runtime & Three-Tier Multi-Tenant Sandbox (`HostSandboxManager`).
//!
//! Isolates hosted tenants, domains, and native Webizen/QualiaDB applications across three tiers:
//! 1. **Tier 1 — VibeScript (`VBC1`) & 42 MiB `SlgArena` Cellular Sandbox**: Mandatory `u64`
//!    cycle budgets (`vibe/src/budget.rs`), strict effect lattice (`Pure < Hot < Cold < Async < External`),
//!    and fail-closed `using {Family};` capability leases (`deontic_interrupt.rs`).
//! 2. **Tier 2 — Portable QApps (`qualia-app-contract` `SDK-01..10`) & WASM Isolates**: Scoped
//!    virtual volume prefixes (`wasm_storage.rs`) and `.q42j` session CRDT synchronization.
//! 3. **Tier 3 — W3C Solid LDP Pod Bridge (`qualia-solid-bridge`) & Linux/eBPF Container Sandbox**:
//!    Strict Turtle ↔ 48-byte `NQuin` translation boundary (`web.civics.au` baseline) + per-sandbox
//!    eBPF socket bandwidth ceilings.

use webizen_host_core::{
    pack_context, pack_metadata, pack_predicate, q_hash, NQuin, PermissiveRoutingLane,
    SensitivityClass, SLG_ARENA_CELL_BYTES,
};

/// VibeScript effect lattice (`Pure < Hot < Cold < Async < External`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VibeEffectLevel {
    Pure = 0,
    Hot = 1,
    Cold = 2,
    Async = 3,
    External = 4,
}

/// Host catalog capability families (`vibe/src/catalog/ids.rs`, ~90 families / ~1,158 operations).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityFamily {
    GraphDatabase = 1,
    DeonticLogic = 2,
    N3Logic = 3,
    ComputationalGeometry = 4,
    Physics = 5,
    Audio = 6,
    Spectral = 7,
    Inference = 8,
    Orchestration = 9,
    WorldSimulation = 10,
    ExternalNetwork = 11,
    FilesystemMount = 12,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxError {
    CycleBudgetExhausted { used: u64, limit: u64 },
    ArenaCellExhausted { requested: usize, limit: usize },
    EffectLatticeViolation {
        required: VibeEffectLevel,
        permitted: VibeEffectLevel,
    },
    CapabilityLeaseDenied(CapabilityFamily),
    EbpfBandwidthQuotaExceeded { used_bytes: u64, ceiling_bytes: u64 },
}

/// Tier 1: VibeScript (`VBC1`) & 42 MiB `SlgArena` Sentinel Cell.
#[derive(Clone, Debug)]
pub struct Tier1VibeCell {
    pub cell_id_hash: u64,
    pub max_cycle_budget: u64,
    pub cycles_used: u64,
    pub max_effect_level: VibeEffectLevel,
    pub arena_bytes_used: usize,
    pub granted_leases_mask: u64,
}

impl Tier1VibeCell {
    pub fn new(
        cell_name: &str,
        max_cycle_budget: u64,
        max_effect_level: VibeEffectLevel,
        granted_families: &[CapabilityFamily],
    ) -> Self {
        let mut mask = 0u64;
        for &fam in granted_families {
            mask |= 1u64 << (fam as u16);
        }
        Self {
            cell_id_hash: q_hash(cell_name),
            max_cycle_budget,
            cycles_used: 0,
            max_effect_level,
            arena_bytes_used: 0,
            granted_leases_mask: mask,
        }
    }

    /// Execute a `VBC1` instruction step, enforcing `u64` cycle bounds, 42 MiB `SlgArena` ceiling,
    /// the effect lattice, and fail-closed `using {Family};` capability leases (`deontic_interrupt.rs`).
    #[inline]
    pub fn execute_vbc1_step(
        &mut self,
        step_cycles: u64,
        required_effect: VibeEffectLevel,
        required_family: Option<CapabilityFamily>,
        arena_bytes_delta: usize,
    ) -> Result<(), SandboxError> {
        if required_effect > self.max_effect_level {
            return Err(SandboxError::EffectLatticeViolation {
                required: required_effect,
                permitted: self.max_effect_level,
            });
        }
        if let Some(fam) = required_family {
            if (self.granted_leases_mask & (1u64 << (fam as u16))) == 0 {
                return Err(SandboxError::CapabilityLeaseDenied(fam));
            }
        }
        let next_cycles = self.cycles_used.saturating_add(step_cycles);
        if next_cycles > self.max_cycle_budget {
            self.cycles_used = self.max_cycle_budget;
            return Err(SandboxError::CycleBudgetExhausted {
                used: next_cycles,
                limit: self.max_cycle_budget,
            });
        }
        let next_arena = self.arena_bytes_used.saturating_add(arena_bytes_delta);
        if next_arena > SLG_ARENA_CELL_BYTES {
            return Err(SandboxError::ArenaCellExhausted {
                requested: next_arena,
                limit: SLG_ARENA_CELL_BYTES,
            });
        }
        self.cycles_used = next_cycles;
        self.arena_bytes_used = next_arena;
        Ok(())
    }
}

/// Tier 2: Portable QApp (`qualia-app-contract` `SDK-01..10`) & WASM Isolate descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier2QAppIsolate {
    pub app_id: String,
    pub sdk_contract_version: String, // e.g., "SDK-01..10"
    pub scoped_volume_prefix: String,
    pub supports_10d_streaming: bool,
    pub supports_chat_dag: bool,
    pub fixed_tick_hz: u32,
}

impl Tier2QAppIsolate {
    pub fn verify_scoped_path(&self, requested_path: &str) -> bool {
        requested_path.starts_with(&self.scoped_volume_prefix) && !requested_path.contains("..")
    }
}

/// Tier 3: W3C Solid LDP Pod Bridge (`qualia-solid-bridge`) & Linux/eBPF Container Perimeter.
#[derive(Clone, Debug)]
pub struct Tier3SolidAndEbpfSandbox {
    pub pod_root_uri: String,
    pub owner_did_hash: u64,
    pub ebpf_egress_ceiling_bytes: u64,
    pub ebpf_egress_used_bytes: u64,
}

impl Tier3SolidAndEbpfSandbox {
    /// Strict Turtle ↔ 48-byte `NQuin` translation boundary (`web.civics.au` W3C Solid LDP baseline).
    pub fn translate_turtle_triple_to_nquin(
        &mut self,
        subject_uri: &str,
        predicate_uri: &str,
        object_uri: &str,
        wire_bytes: u64,
    ) -> Result<NQuin, SandboxError> {
        let next_bytes = self.ebpf_egress_used_bytes.saturating_add(wire_bytes);
        if next_bytes > self.ebpf_egress_ceiling_bytes {
            return Err(SandboxError::EbpfBandwidthQuotaExceeded {
                used_bytes: next_bytes,
                ceiling_bytes: self.ebpf_egress_ceiling_bytes,
            });
        }
        self.ebpf_egress_used_bytes = next_bytes;
        Ok(NQuin::new(
            q_hash(subject_uri),
            pack_predicate(predicate_uri, 0x01, false),
            q_hash(object_uri) & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(self.owner_did_hash, SensitivityClass::Restricted),
            pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 0),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp04_tier1_vibescript_budget_and_capability_leases_fail_closed() {
        let mut cell_a = Tier1VibeCell::new(
            "tenant_a_vibe_app",
            1_000,
            VibeEffectLevel::Hot,
            &[CapabilityFamily::GraphDatabase, CapabilityFamily::DeonticLogic],
        );
        let mut cell_b = Tier1VibeCell::new(
            "tenant_b_sibling",
            5_000,
            VibeEffectLevel::Hot,
            &[CapabilityFamily::GraphDatabase],
        );

        // Authorized GraphDatabase step succeeds
        assert!(cell_a
            .execute_vbc1_step(
                400,
                VibeEffectLevel::Hot,
                Some(CapabilityFamily::GraphDatabase),
                4096
            )
            .is_ok());

        // Unauthorized ExternalNetwork lease fails closed via deontic_interrupt
        assert_eq!(
            cell_a.execute_vbc1_step(
                10,
                VibeEffectLevel::Hot,
                Some(CapabilityFamily::ExternalNetwork),
                0
            ),
            Err(SandboxError::CapabilityLeaseDenied(
                CapabilityFamily::ExternalNetwork
            ))
        );

        // Runaway script in cell_a halts deterministically at 1,000 cycles without affecting sibling cell_b
        assert_eq!(
            cell_a.execute_vbc1_step(
                700,
                VibeEffectLevel::Pure,
                Some(CapabilityFamily::DeonticLogic),
                0
            ),
            Err(SandboxError::CycleBudgetExhausted {
                used: 1100,
                limit: 1000
            })
        );
        assert!(cell_b
            .execute_vbc1_step(
                500,
                VibeEffectLevel::Hot,
                Some(CapabilityFamily::GraphDatabase),
                1024
            )
            .is_ok());
    }

    #[test]
    fn wp04_tier2_qapp_and_tier3_solid_ldp_bridge_conformance() {
        let qapp = Tier2QAppIsolate {
            app_id: "org.webizen.storytold.world".to_string(),
            sdk_contract_version: "SDK-01..10".to_string(),
            scoped_volume_prefix: "/volumes/tenant_a/qapp_storytold/".to_string(),
            supports_10d_streaming: true,
            supports_chat_dag: true,
            fixed_tick_hz: 20,
        };
        assert!(qapp.verify_scoped_path("/volumes/tenant_a/qapp_storytold/scene.10d"));
        assert!(!qapp.verify_scoped_path("/volumes/tenant_b/secret.q42"));

        let mut solid = Tier3SolidAndEbpfSandbox {
            pod_root_uri: "https://web.civics.au/alice/profile/card#me".to_string(),
            owner_did_hash: q_hash("did:qi:alice"),
            ebpf_egress_ceiling_bytes: 1024,
            ebpf_egress_used_bytes: 0,
        };
        let q = solid
            .translate_turtle_triple_to_nquin(
                "https://web.civics.au/alice/profile/card#me",
                "http://xmlns.com/foaf/0.1/name",
                "Alice",
                256,
            )
            .unwrap();
        assert!(q.verify_parity());
    }
}
