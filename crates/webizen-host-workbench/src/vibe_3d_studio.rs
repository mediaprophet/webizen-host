//! WP-11 (D11.1 & D11.2): VibeScript 3D Creative Studio & AAA Volumetric Viewport Forge
//! (`Vibe3dAssetForge`, `Vibe3dMeshPreset`, `Vibe3dPbrShader`, `Vibe3dForgeReceipt`).

use std::f64::consts::PI;
use std::fs;
use std::path::{Path, PathBuf};
use vibe::animation::{
    evaluate_preset, list_all_presets, AnimationFamily, Motor, PresetInfo, SpringConfig,
    SpringState3D,
};
use vibe::physics::{
    evaluate_field_interactions, AcousticFacet, ChemicalFacet, ContinuantState, FieldDeclaration,
    MaterialSignature, MechanicalFacet, OpticalFacet, ThermalFacet,
};
use vibe::Pose;
use webizen_host_core::{
    encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash,
    validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass,
    CBOR_LD_QUIN_WIRE_SIZE, INLINE_TAG_INTEGER, OP_RESOURCE_DECLARATION,
};
use webizen_host_ingest::QbdlHmcBundle;

/// Canonical 3D procedural mesh presets for the VibeScript 3D Creative Studio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vibe3dMeshPreset {
    GeodesicManifoldDome,
    TorusKnotQuantumCore,
    CrystalLatticeSpire,
    OrbitalStewardshipRing,
}

impl Vibe3dMeshPreset {
    pub fn from_name(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase().replace('-', "_");
        if lower.contains("torus") || lower.contains("knot") || lower.contains("quantum") {
            Self::TorusKnotQuantumCore
        } else if lower.contains("crystal") || lower.contains("lattice") || lower.contains("spire") {
            Self::CrystalLatticeSpire
        } else if lower.contains("orbital") || lower.contains("ring") || lower.contains("steward") {
            Self::OrbitalStewardshipRing
        } else {
            Self::GeodesicManifoldDome
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GeodesicManifoldDome => "geodesic_manifold_dome",
            Self::TorusKnotQuantumCore => "torus_knot_quantum_core",
            Self::CrystalLatticeSpire => "crystal_lattice_spire",
            Self::OrbitalStewardshipRing => "orbital_stewardship_ring",
        }
    }
}

/// Canonical PBR / 5-Facet `MaterialSignature` shader presets for the 3D Creative Studio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vibe3dPbrShader {
    ObsidianGlass,
    BioluminescentPlasma,
    BrushedTitanium,
    CrystallineQuartz,
}

impl Vibe3dPbrShader {
    pub fn from_name(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase().replace('-', "_");
        if lower.contains("obsidian") || lower.contains("glass") {
            Self::ObsidianGlass
        } else if lower.contains("titanium") || lower.contains("brushed") || lower.contains("metal") {
            Self::BrushedTitanium
        } else if lower.contains("quartz") || lower.contains("crystal") {
            Self::CrystallineQuartz
        } else {
            Self::BioluminescentPlasma
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ObsidianGlass => "obsidian_glass",
            Self::BioluminescentPlasma => "bioluminescent_plasma",
            Self::BrushedTitanium => "brushed_titanium",
            Self::CrystallineQuartz => "crystalline_quartz",
        }
    }

    pub fn primary_hex(&self) -> &'static str {
        match self {
            Self::ObsidianGlass => "#1e293b",
            Self::BioluminescentPlasma => "#06b6d4",
            Self::BrushedTitanium => "#94a3b8",
            Self::CrystallineQuartz => "#a855f7",
        }
    }

    pub fn accent_hex(&self) -> &'static str {
        match self {
            Self::ObsidianGlass => "#38bdf8",
            Self::BioluminescentPlasma => "#34d399",
            Self::BrushedTitanium => "#f8fafc",
            Self::CrystallineQuartz => "#f472b6",
        }
    }

    pub fn to_vibe_material_signature(&self) -> MaterialSignature {
        let (id, name, yield_kpa, ym_gpa, density, albedo, ior, abs, imp, cond) = match self {
            Self::ObsidianGlass => ("did:q42:material:obsidian-glass-v1", "Volcanic Obsidian Glass", 65_000.0, 72.0, 2550.0, 0.14, 1.51, 0.28, 1.35e7, 1.35),
            Self::BioluminescentPlasma => ("did:q42:material:bioluminescent-plasma-v1", "Bioluminescent Photonic Plasma Shell", 45.0, 3.6, 420.0, 0.92, 1.38, 0.04, 0.95e6, 4.80),
            Self::BrushedTitanium => ("did:q42:material:brushed-titanium-v1", "Aerospace Brushed Titanium Grade-5", 880_000.0, 114.0, 4430.0, 0.68, 2.16, 0.12, 2.73e7, 6.70),
            Self::CrystallineQuartz => ("did:q42:material:crystalline-quartz-v1", "Piezoelectric Crystalline Quartz", 110_000.0, 97.0, 2650.0, 0.84, 1.544, 0.02, 1.52e7, 3.20),
        };
        MaterialSignature {
            id: id.to_string(),
            name: name.to_string(),
            mechanical: Some(MechanicalFacet { yield_kpa, youngs_modulus_gpa: ym_gpa, density_kg_m3: density, poisson_ratio: 0.26 }),
            optical: Some(OpticalFacet { albedo, ior, absorption: abs }),
            acoustic: Some(AcousticFacet { impedance_rayls: imp, absorption_coeff: 0.06 }),
            chemical: Some(ChemicalFacet {
                soluble_in: None,
                dissolve_rate_per_s: 0.0,
                dissolve_products: None,
                immiscible_with: vec!["did:q42:species:H2O".to_string()],
            }),
            thermal: Some(ThermalFacet { conductivity_w_mk: cond, specific_heat_j_kgk: 780.0, melt_point_k: Some(1883.0), boil_point_k: Some(3100.0) }),
        }
    }
}

/// Receipt emitted after forging a 3D scene, `.hmc` bundle, CBOR-LD receipt, and IPFS/WebSeed share.
#[derive(Clone, Debug, PartialEq)]
pub struct Vibe3dForgeReceipt {
    pub scene_id: String,
    pub mesh_preset: Vibe3dMeshPreset,
    pub shader: Vibe3dPbrShader,
    pub animation_family: String,
    pub animation_preset: String,
    pub vertex_count: usize,
    pub face_count: usize,
    pub motor_scalar: f64,
    pub spring_position: [f64; 3],
    pub field_events_count: usize,
    pub hmc_path: PathBuf,
    pub svg_path: PathBuf,
    pub cbor_ld_path: PathBuf,
    pub ipfs_cid: String,
    pub magnet_uri: String,
}

/// VibeScript 3D Creative Studio & AAA Volumetric Asset Forge.
pub struct Vibe3dAssetForge;

impl Vibe3dAssetForge {
    pub fn available_animation_presets() -> &'static [PresetInfo] {
        list_all_presets()
    }

    pub fn render_aaa_3d_viewport_svg(
        scene_id: &str,
        mesh_preset: Vibe3dMeshPreset,
        shader: Vibe3dPbrShader,
        anim_family: AnimationFamily,
        anim_preset: &str,
        time_sec: f64,
    ) -> (String, usize, usize, f64, [f64; 3], usize) {
        let sample = evaluate_preset(anim_family, anim_preset, time_sec);
        let (s, c) = ((time_sec * 0.65 + 0.35) * 0.5).sin_cos();
        let inv = (1.0f64 / 3.0).sqrt();
        let target_motor = Motor::from_rotation_translation(
            [c, s * inv, s * inv, s * inv],
            [sample.vector[0] * 0.15, sample.vector[1] * 0.15, sample.vector[2] * 0.15],
        );
        let active_motor = Motor::sclerp(&sample.motor, &target_motor, 0.55);

        let spring_cfg = SpringConfig { mass: 1.0, stiffness: 240.0, damping: 22.0, ..SpringConfig::wobbly() };
        let spring_state = SpringState3D::new([0.0, -1.2, 0.5], [1.5, 2.0, -0.8], sample.vector);
        let (spring_pos, _, _) = spring_state.evaluate_at(&spring_cfg, time_sec.max(0.12));

        let mat_sig = shader.to_vibe_material_signature();
        let (albedo, ior) = mat_sig.optical.as_ref().map(|o| (o.albedo, o.ior)).unwrap_or((0.8, 1.45));
        let mut continuant = ContinuantState {
            id: format!("did:q42:continuant:{scene_id}"),
            pose: Pose {
                position: vec![spring_pos[0], spring_pos[1], spring_pos[2]],
                orientation: vec![active_motor.r_w, active_motor.r_x, active_motor.r_y, active_motor.r_z],
                frame: Some("manifold:10d:xyzd_t".to_string()),
            },
            material: mat_sig,
            mass_kg: 1.25,
            is_solid: true,
            is_crushed: false,
            current_temperature_k: 293.15,
        };
        let mut field_events = Vec::new();
        evaluate_field_interactions(&mut continuant, &[FieldDeclaration::standard_atmosphere()], &mut field_events);

        let (verts, faces) = Self::build_mesh_geometry(mesh_preset);
        let transformed: Vec<[f64; 3]> = verts.iter().map(|&v| active_motor.transform_point(v)).collect();
        let mut sorted_faces: Vec<(f64, [usize; 3])> = faces
            .iter()
            .map(|&f| ((transformed[f[0]][2] + transformed[f[1]][2] + transformed[f[2]][2]) / 3.0, f))
            .collect();
        sorted_faces.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let (primary, accent) = (shader.primary_hex(), shader.accent_hex());
        let mut poly_svg = String::with_capacity(sorted_faces.len() * 140);
        for (z_avg, f) in &sorted_faces {
            let (p0, p1, p2) = (Self::project_point(transformed[f[0]]), Self::project_point(transformed[f[1]]), Self::project_point(transformed[f[2]]));
            let shade = ((z_avg + 2.2) / 4.4).clamp(0.22, 0.96);
            poly_svg.push_str(&format!(
                r#"<polygon points="{:.1},{:.1} {:.1},{:.1} {:.1},{:.1}" fill="url(#pbr-grad)" fill-opacity="{:.2}" stroke="{}" stroke-opacity="0.72" stroke-width="1.15"/>"#,
                p0[0], p0[1], p1[0], p1[1], p2[0], p2[1], shade, accent
            ));
        }

        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 540" width="100%" height="100%">
  <defs>
    <filter id="aaa-bloom" x="-25%" y="-25%" width="150%" height="150%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur"/>
      <feSpecularLighting in="blur" surfaceScale="4" specularConstant="0.9" specularExponent="24" lighting-color="{accent}" result="spec"><fePointLight x="480" y="140" z="260"/></feSpecularLighting>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="spec"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <radialGradient id="nebula-bg" cx="50%" cy="48%" r="65%"><stop offset="0%" stop-color="#0f172a"/><stop offset="60%" stop-color="#090d16"/><stop offset="100%" stop-color="#020617"/></radialGradient>
    <linearGradient id="pbr-grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="{accent}"/><stop offset="55%" stop-color="{primary}"/><stop offset="100%" stop-color="#020617"/></linearGradient>
    <style>
      @keyframes pulseHalo {{ 0%, 100% {{ opacity: 0.45; }} 50% {{ opacity: 0.88; }} }}
      .hud-text {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; fill: #e2e8f0; }}
      .hud-accent {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; fill: {accent}; font-weight: bold; }}
    </style>
  </defs>
  <rect width="960" height="540" fill="url(#nebula-bg)"/>
  <g stroke="#1e293b" stroke-width="1" opacity="0.65">
    <line x1="0" y1="390" x2="960" y2="390"/><line x1="0" y1="435" x2="960" y2="435"/><line x1="0" y1="485" x2="960" y2="485"/>
    <line x1="480" y1="350" x2="120" y2="540"/><line x1="480" y1="350" x2="320" y2="540"/><line x1="480" y1="350" x2="480" y2="540"/><line x1="480" y1="350" x2="640" y2="540"/><line x1="480" y1="350" x2="840" y2="540"/>
  </g>
  <ellipse cx="480" cy="275" rx="260" ry="92" fill="none" stroke="{accent}" stroke-width="1.2" stroke-dasharray="6 4" style="animation: pulseHalo 4s infinite;"/>
  <g filter="url(#aaa-bloom)">{poly_svg}</g>
  <rect x="18" y="16" width="430" height="96" rx="8" fill="#0f172acc" stroke="{accent}" stroke-width="1"/>
  <text x="32" y="38" class="hud-accent">VIBE 3D STUDIO // AAA 10D MANIFOLD VIEWPORT</text>
  <text x="32" y="56" class="hud-text">SCENE: {scene_id} | MESH: {mesh}</text>
  <text x="32" y="74" class="hud-text">SHADER: {shader_str} (Albedo {albedo:.2}, IOR {ior:.3})</text>
  <text x="32" y="92" class="hud-text">ANIM: {fam}::{anim_preset} | PGA S={scalar:.3} | V={v_cnt} F={f_cnt}</text>
</svg>"##,
            accent = accent, primary = primary, poly_svg = poly_svg, scene_id = scene_id,
            mesh = mesh_preset.as_str(), shader_str = shader.as_str(), albedo = albedo, ior = ior,
            fam = anim_family.name(), anim_preset = anim_preset, scalar = sample.scalar,
            v_cnt = verts.len(), f_cnt = faces.len(),
        );

        (svg, verts.len(), faces.len(), sample.scalar, spring_pos, field_events.len())
    }

    pub fn forge_3d_scene_and_hmc(
        data_dir: &Path,
        scene_id: &str,
        mesh_preset: Vibe3dMeshPreset,
        shader: Vibe3dPbrShader,
        anim_family: AnimationFamily,
        anim_preset: &str,
        time_sec: f64,
        origin_base_url: &str,
    ) -> Result<Vibe3dForgeReceipt, &'static str> {
        validate_human_centric_nomenclature(scene_id)?;
        validate_human_centric_nomenclature(anim_preset)?;
        let clean_id = scene_id.trim().trim_matches(['/', '\\', '.']);
        if clean_id.is_empty() || clean_id.contains("..") {
            return Err("Invalid 3D Studio scene_id");
        }

        let (svg, vertex_count, face_count, motor_scalar, spring_position, field_events_count) =
            Self::render_aaa_3d_viewport_svg(clean_id, mesh_preset, shader, anim_family, anim_preset, time_sec);

        let vibe_script = format!(
            "module studio_{clean_id};\npure fn scene_pose(t: Float) budget(steps: 200) -> Record {{\n  {{ scene: \"{clean_id}\", mesh: \"{}\", shader: \"{}\", family: \"{}\", preset: \"{anim_preset}\", scalar: {motor_scalar:.4} }}\n}}\n",
            mesh_preset.as_str(), shader.as_str(), anim_family.name()
        );
        let sig = shader.to_vibe_material_signature();
        let mat_summary = format!("id={}\nname={}\nshader={}\n", sig.id, sig.name, shader.as_str());

        let hmc = QbdlHmcBundle::build(&[
            ("viewport/scene.svg", "aaa_volumetric_svg", svg.as_bytes()),
            ("scripts/scene.vibe", "vibescript_3d", vibe_script.as_bytes()),
            ("materials/pbr.txt", "vibe_material_signature", mat_summary.as_bytes()),
        ]);

        let studio_dir = data_dir.join("studio");
        fs::create_dir_all(&studio_dir).map_err(|_| "Failed to create studio directory")?;

        let hmc_path = studio_dir.join(format!("{clean_id}.hmc"));
        let svg_path = studio_dir.join(format!("{clean_id}.svg"));
        let cbor_ld_path = studio_dir.join(format!("{clean_id}.cbor-ld"));

        fs::write(&hmc_path, &hmc.bytes).map_err(|_| "Failed to write .hmc bundle")?;
        fs::write(&svg_path, svg.as_bytes()).map_err(|_| "Failed to write .svg viewport")?;

        let quin = NQuin::new(
            q_hash(&format!("https://ns.webcivics.net/studio/{clean_id}")),
            pack_predicate("https://ns.webcivics.net/studio#hasHmcAsset", OP_RESOURCE_DECLARATION, false),
            INLINE_TAG_INTEGER | (face_count as u64),
            pack_context(q_hash("https://ns.webcivics.net/graph/studio"), SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::Spatial, 1, hmc.whole_file_crc32c),
        );
        let mut cbor_buf = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        encode_quin_cbor_ld_zero_heap(&quin, &mut cbor_buf)?;
        fs::write(&cbor_ld_path, &cbor_buf).map_err(|_| "Failed to write .cbor-ld receipt")?;

        let share = crate::solid_ipfs_webseed::publish_file_to_ipfs_and_webseed(
            data_dir, &format!("{clean_id}.hmc"), &hmc.bytes, origin_base_url,
        )?;

        Ok(Vibe3dForgeReceipt {
            scene_id: clean_id.to_string(),
            mesh_preset,
            shader,
            animation_family: anim_family.name().to_string(),
            animation_preset: anim_preset.to_string(),
            vertex_count,
            face_count,
            motor_scalar,
            spring_position,
            field_events_count,
            hmc_path,
            svg_path,
            cbor_ld_path,
            ipfs_cid: share.ipfs_cid,
            magnet_uri: share.magnet_uri,
        })
    }

    fn project_point(p: [f64; 3]) -> [f64; 2] {
        let depth = (3.8 - p[2] * 0.45).max(1.1);
        let scale = 340.0 / depth;
        [480.0 + p[0] * scale, 255.0 - p[1] * scale]
    }

    fn build_mesh_geometry(preset: Vibe3dMeshPreset) -> (Vec<[f64; 3]>, Vec<[usize; 3]>) {
        let (rings, segs) = (6usize, 12usize);
        let mut verts = Vec::with_capacity((rings + 1) * segs);
        let mut faces = Vec::with_capacity(rings * segs * 2);
        for r in 0..=rings {
            let u = r as f64 / rings as f64;
            let phi = u * PI;
            for s in 0..segs {
                let theta = (s as f64 / segs as f64) * 2.0 * PI;
                let pt = match preset {
                    Vibe3dMeshPreset::GeodesicManifoldDome => [phi.sin() * theta.cos() * 1.35, phi.cos() * 1.35, phi.sin() * theta.sin() * 1.35],
                    Vibe3dMeshPreset::TorusKnotQuantumCore => {
                        let rad = 1.05 + 0.38 * (3.0 * theta).cos();
                        [rad * (2.0 * theta).cos(), 0.42 * (3.0 * theta).sin() + (u - 0.5) * 0.6, rad * (2.0 * theta).sin()]
                    }
                    Vibe3dMeshPreset::CrystalLatticeSpire => {
                        let rad = (1.0 - (u - 0.5).abs() * 1.65).max(0.18) * 1.25;
                        [rad * theta.cos(), (u - 0.5) * 2.4, rad * theta.sin()]
                    }
                    Vibe3dMeshPreset::OrbitalStewardshipRing => {
                        let major = 1.35 + 0.28 * phi.cos();
                        [major * theta.cos(), 0.28 * phi.sin(), major * theta.sin()]
                    }
                };
                verts.push(pt);
            }
        }
        for r in 0..rings {
            for s in 0..segs {
                let next_s = (s + 1) % segs;
                let (a, b, c, d) = (r * segs + s, r * segs + next_s, (r + 1) * segs + next_s, (r + 1) * segs + s);
                faces.push([a, b, c]);
                faces.push([a, c, d]);
            }
        }
        (verts, faces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct ScopedTempDir(PathBuf);
    impl ScopedTempDir {
        fn new() -> Self {
            static CNT: AtomicU64 = AtomicU64::new(1);
            let p = std::env::temp_dir().join(format!(
                "qualia_vibe_3d_studio_{}_{}",
                std::process::id(),
                CNT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn d11_1_and_d11_2_vibe_3d_asset_forge_evaluates_pga_motors_physics_svg_and_hmc_bundle() {
        let presets = Vibe3dAssetForge::available_animation_presets();
        assert!(presets.len() >= 30);
        for fam in [
            "spatial_kinematics", "physical_dynamics", "mesh_topology", "thermodynamic_phase",
            "optics_waves", "acoustic_spectral", "multitrack_timelines", "hud_glass_ui",
            "outbound_haptics", "generative_fields",
        ] {
            assert!(presets.iter().any(|p| p.family == fam));
        }

        let tmp = ScopedTempDir::new();
        for (id, mesh, shd, fam, preset) in [
            ("sanctuary_dome", Vibe3dMeshPreset::GeodesicManifoldDome, Vibe3dPbrShader::BioluminescentPlasma, AnimationFamily::SpatialKinematics, "orbit_spin"),
            ("quantum_core", Vibe3dMeshPreset::TorusKnotQuantumCore, Vibe3dPbrShader::ObsidianGlass, AnimationFamily::OpticsWaves, "fresnel_glow"),
        ] {
            let receipt = Vibe3dAssetForge::forge_3d_scene_and_hmc(
                &tmp.0, id, mesh, shd, fam, preset, 0.75, "https://ns.webcivics.net",
            ).expect("forge 3D scene succeeds");
            assert!(receipt.vertex_count > 20 && receipt.face_count > 40);
            let svg_disk = fs::read_to_string(&receipt.svg_path).unwrap();
            assert!(svg_disk.contains("<svg") && svg_disk.contains("<feGaussianBlur"));
            let cbor_bytes = fs::read(&receipt.cbor_ld_path).unwrap();
            assert_eq!(&cbor_bytes[0..3], &[0xD9, 0x05, 0x01]);
            let ipfs_bytes = crate::solid_ipfs_webseed::serve_ipfs_block(&tmp.0, &receipt.ipfs_cid).unwrap();
            assert_eq!(&ipfs_bytes[0..4], b"QBDL");
            let rebuilt = QbdlHmcBundle::build(&[("viewport/scene.svg", "aaa_volumetric_svg", svg_disk.as_bytes())]);
            assert_eq!(rebuilt.extract_verified_slice("viewport/scene.svg").unwrap(), svg_disk.as_bytes());
        }
    }
}
