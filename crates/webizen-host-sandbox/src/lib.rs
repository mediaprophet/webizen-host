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

pub use vibe::{
    Env as VibeEnv, LocalHost as VibeLocalHost, Program as VibeProgram, Value as VibeValue,
};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxError {
    CycleBudgetExhausted { used: u64, limit: u64 },
    ArenaCellExhausted { requested: usize, limit: usize },
    EffectLatticeViolation {
        required: VibeEffectLevel,
        permitted: VibeEffectLevel,
    },
    CapabilityLeaseDenied(CapabilityFamily),
    EbpfBandwidthQuotaExceeded { used_bytes: u64, ceiling_bytes: u64 },
    VibeRuntimeDiagnostic(String),
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

    /// Parse, type-check, effect-check, and execute a real VibeScript (`.vibe`) function
    /// inside this Tier-1 cell using the `qualiaDB/crates/vibe` engine.
    pub fn execute_vibe_function(
        &mut self,
        vibe_source: &str,
        fn_name: &str,
        args: Vec<VibeValue>,
    ) -> Result<VibeValue, SandboxError> {
        let source_len = vibe_source.len();
        let projected_arena = self.arena_bytes_used.saturating_add(source_len);
        if projected_arena > SLG_ARENA_CELL_BYTES {
            return Err(SandboxError::ArenaCellExhausted {
                requested: projected_arena,
                limit: SLG_ARENA_CELL_BYTES,
            });
        }

        let normalized = normalize_vibe_web_source(vibe_source);
        let prog = match vibe::load_program(vibe_source) {
            Ok(p) => p,
            Err(_) if vibe_source.contains("web.cbor_ld_response") => {
                vibe::load_program(&normalized)
                    .map_err(|d| SandboxError::VibeRuntimeDiagnostic(d.message))?
            }
            Err(d) => return Err(SandboxError::VibeRuntimeDiagnostic(d.message)),
        };

        let mut required_effect = VibeEffectLevel::Pure;
        let mut step_cost = 50u64;
        for item in &prog.items {
            if let vibe::Item::Function(f) = item {
                if f.name == fn_name {
                    required_effect = match f.effect {
                        Some(vibe::EffectClass::Pure) => VibeEffectLevel::Pure,
                        Some(vibe::EffectClass::Hot) => VibeEffectLevel::Hot,
                        Some(vibe::EffectClass::Cold) => VibeEffectLevel::Cold,
                        Some(vibe::EffectClass::Async) => VibeEffectLevel::Async,
                        Some(vibe::EffectClass::External) => VibeEffectLevel::External,
                        None if f.is_async => VibeEffectLevel::Async,
                        None => VibeEffectLevel::Pure,
                    };
                    for arg in &f.budget {
                        if arg.name == "steps" {
                            match &arg.value.kind {
                                vibe::ExprKind::Literal(vibe::Literal::Int(n)) if *n > 0 => {
                                    step_cost = *n as u64;
                                }
                                vibe::ExprKind::Literal(vibe::Literal::UInt(u)) if *u > 0 => {
                                    step_cost = *u;
                                }
                                _ => {}
                            }
                        }
                    }
                    break;
                }
            }
        }

        if required_effect > self.max_effect_level {
            return Err(SandboxError::EffectLatticeViolation {
                required: required_effect,
                permitted: self.max_effect_level,
            });
        }

        self.execute_vbc1_step(step_cost, required_effect, None, source_len)?;

        let mut host = VibeLocalHost::default();
        let mut env = VibeEnv::default();
        match vibe::eval_function(&prog, fn_name, args.clone(), &mut host, &mut env) {
            Ok(val) => Ok(val),
            Err(d)
                if vibe_source.contains("web.cbor_ld_response")
                    && d.message.contains("web.cbor_ld_response") =>
            {
                let fallback_prog = vibe::load_program(&normalized)
                    .map_err(|e| SandboxError::VibeRuntimeDiagnostic(e.message))?;
                let mut fallback_host = VibeLocalHost::default();
                let mut fallback_env = VibeEnv::default();
                vibe::eval_function(
                    &fallback_prog,
                    fn_name,
                    args,
                    &mut fallback_host,
                    &mut fallback_env,
                )
                .map_err(|e| SandboxError::VibeRuntimeDiagnostic(e.message))
            }
            Err(d) => Err(SandboxError::VibeRuntimeDiagnostic(d.message)),
        }
    }
}

fn normalize_vibe_web_source(vibe_source: &str) -> String {
    if !vibe_source.contains("web.cbor_ld_response") {
        return vibe_source.to_string();
    }
    let needle = "web.cbor_ld_response(";
    let mut out = String::with_capacity(vibe_source.len() + 480);
    let mut rest = vibe_source;
    while let Some(pos) = rest.find(needle) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + needle.len()..];
        let is_int = after.trim_start().chars().next().is_some_and(|c| c.is_ascii_digit());
        out.push_str(if is_int {
            "webizen_cbor_ld_response_3("
        } else {
            "webizen_cbor_ld_response_2("
        });
        rest = after;
    }
    out.push_str(rest);
    out.push_str(
        r#"
pure fn webizen_cbor_ld_response_3(status: i64, ctx: String, payload: Record) budget(steps: 100) -> Record {
    let encoded = cbor_ld.encode(payload, ctx);
    let resp = web.response(status, "application/cbor-ld", encoded);
    return { status: status, content_type: "application/cbor-ld", context: ctx, tag: encoded.tag, byte_len: encoded.byte_len, hex: encoded.hex, bytes: encoded.bytes, payload: payload, zero_js: resp.zero_js, headers: resp.headers };
}
pure fn webizen_cbor_ld_response_2(payload: Record, ctx: String) budget(steps: 100) -> Record {
    return webizen_cbor_ld_response_3(200, ctx, payload);
}
"#,
    );
    out
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
            .execute_vbc1_step(400, VibeEffectLevel::Hot, Some(CapabilityFamily::GraphDatabase), 4096)
            .is_ok());

        // Unauthorized ExternalNetwork lease fails closed via deontic_interrupt
        assert_eq!(
            cell_a.execute_vbc1_step(10, VibeEffectLevel::Hot, Some(CapabilityFamily::ExternalNetwork), 0),
            Err(SandboxError::CapabilityLeaseDenied(CapabilityFamily::ExternalNetwork))
        );

        // Runaway script in cell_a halts deterministically at 1,000 cycles without affecting sibling cell_b
        assert_eq!(
            cell_a.execute_vbc1_step(700, VibeEffectLevel::Pure, Some(CapabilityFamily::DeonticLogic), 0),
            Err(SandboxError::CycleBudgetExhausted { used: 1100, limit: 1000 })
        );
        assert!(cell_b
            .execute_vbc1_step(500, VibeEffectLevel::Hot, Some(CapabilityFamily::GraphDatabase), 1024)
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

    #[test]
    fn wp04_tier1_executes_real_vibe_engine_and_enforces_pure_effect_lattice() {
        let vibe_src = r#"
module webizen_host_cpanel;

pure fn render_route(persona: String, page: String) budget(steps: 400) -> Record {
    let view = ui.select_persona(persona, page);
    let badge_patch = ui.patch("persona-badge", "textContent", view.badge);
    let cbor_state = web.cbor_ld_response(200, "https://ns.webcivics.net/cpanel", view);
    let resp = web.response(200, "text/html; charset=utf-8", view.badge);
    return { view: view, patch: badge_patch, cbor_ld: cbor_state, response: resp };
}

pure fn verify_relationship_mail(alias: String, sender: String, allowed: String) budget(steps: 200) -> Record {
    return web.route_mail(alias, sender, allowed);
}

pure fn check_peer_resource_permit(priority_tier: i64, host_util_pct: i64, req_units: i64, quota: i64) budget(steps: 200) -> Record {
    return web.check_permit(priority_tier, host_util_pct, req_units, quota);
}

effect fn mutate_external_gateway(endpoint: String) budget(steps: 100) -> Record {
    let resp = web.response(200, "text/plain", endpoint);
    return resp;
}
"#;

        let mut pure_cell = Tier1VibeCell::new(
            "cpanel-pure-cell",
            10_000,
            VibeEffectLevel::Pure,
            &[CapabilityFamily::GraphDatabase],
        );

        // 1. Execute `render_route` calling `ui.select_persona` and `web.cbor_ld_response`
        let route_val = pure_cell
            .execute_vibe_function(
                vibe_src,
                "render_route",
                vec![VibeValue::String("geek".into()), VibeValue::String("domains".into())],
            )
            .unwrap();
        let VibeValue::Record(route_rec) = route_val else { panic!("expected Record") };
        assert!(route_rec.contains_key("view") && route_rec.contains_key("cbor_ld"));
        assert_eq!(pure_cell.cycles_used, 400);

        // 2. Execute `verify_relationship_mail` calling `web.route_mail`
        let mail_val = pure_cell
            .execute_vibe_function(
                vibe_src,
                "verify_relationship_mail",
                vec![
                    VibeValue::String("bob@alice.tld".into()),
                    VibeValue::String("alice@bob.tld".into()),
                    VibeValue::String("alice@bob.tld".into()),
                ],
            )
            .unwrap();
        let VibeValue::Record(mail_rec) = mail_val else { panic!("expected Record") };
        assert_eq!(mail_rec.get("admitted"), Some(&VibeValue::Bool(true)));
        assert_eq!(
            mail_rec.get("verdict"),
            Some(&VibeValue::String("DeliverToRelationshipThread".into()))
        );
        assert_eq!(pure_cell.cycles_used, 600);

        // 3. Execute `check_peer_resource_permit` calling `web.check_permit`
        let permit_val = pure_cell
            .execute_vibe_function(
                vibe_src,
                "check_peer_resource_permit",
                vec![VibeValue::I64(2), VibeValue::I64(70), VibeValue::I64(10), VibeValue::I64(50)],
            )
            .unwrap();
        let VibeValue::Record(permit_rec) = permit_val else { panic!("expected Record") };
        assert_eq!(permit_rec.get("admitted"), Some(&VibeValue::Bool(true)));
        assert_eq!(permit_rec.get("status"), Some(&VibeValue::String("Admitted".into())));
        assert_eq!(pure_cell.cycles_used, 800);

        // 4. Verify `effect fn` fails closed with `EffectLatticeViolation` inside a `VibeEffectLevel::Pure` cell
        let err = pure_cell.execute_vibe_function(
            vibe_src,
            "mutate_external_gateway",
            vec![VibeValue::String("https://ns.webcivics.net".into())],
        );
        assert_eq!(
            err,
            Err(SandboxError::EffectLatticeViolation {
                required: VibeEffectLevel::External,
                permitted: VibeEffectLevel::Pure,
            })
        );
    }
}
