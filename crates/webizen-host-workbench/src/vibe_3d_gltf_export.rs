//! Khronos glTF 2.0 Binary (`.glb`) & Wavefront `.obj` 3D Asset Exporters (`WP-19` Swarm 6B / D19.2).
//!
//! Provides deterministic, zero-external-dependency Khronos glTF 2.0 Binary (`.glb`) and
//! Wavefront `.obj` exporters for `Vibe3dMeshPreset` and `Vibe3dPbrShader`.

use std::f32::consts::PI;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use webizen_host_core::validate_human_centric_nomenclature;

use crate::vibe_3d_studio::{Vibe3dMeshPreset, Vibe3dPbrShader};

/// Khronos glTF 2.0 magic header bytes (`b"glTF"` = `0x46546C67` in little-endian).
pub const GLTF_MAGIC: u32 = 0x4654_6C67;
/// Khronos glTF 2.0 specification version (`2`).
pub const GLTF_VERSION: u32 = 2;
/// Khronos glTF 2.0 JSON chunk type (`b"JSON"` = `0x4E4F534A` in little-endian).
pub const GLTF_CHUNK_JSON: u32 = 0x4E4F_534A;
/// Khronos glTF 2.0 Binary buffer chunk type (`b"BIN\0"` = `0x004E4942` in little-endian).
pub const GLTF_CHUNK_BIN: u32 = 0x004E_4942;

/// Generate deterministic 3D vertex positions (`POSITION`), unit vertex normals (`NORMAL`),
/// and 16-bit triangle indices (`[u16; 3]`) for any `Vibe3dMeshPreset`.
pub fn build_indexed_mesh_f32(
    preset: Vibe3dMeshPreset,
) -> (Vec<[f32; 3]>, Vec<[f32; 3]>, Vec<[u16; 3]>) {
    let (rings, segs) = (8usize, 16usize);
    let vert_count = (rings + 1) * segs;
    let mut positions = Vec::with_capacity(vert_count);
    let mut normals = vec![[0.0f32; 3]; vert_count];
    let mut faces = Vec::with_capacity(rings * segs * 2);

    for r in 0..=rings {
        let u = r as f32 / rings as f32;
        let phi = u * PI;
        for s in 0..segs {
            let theta = (s as f32 / segs as f32) * 2.0 * PI;
            let pt = match preset {
                Vibe3dMeshPreset::GeodesicManifoldDome => [
                    phi.sin() * theta.cos() * 1.35,
                    phi.cos() * 1.35,
                    phi.sin() * theta.sin() * 1.35,
                ],
                Vibe3dMeshPreset::TorusKnotQuantumCore => {
                    let rad = 1.05 + 0.38 * (3.0 * theta).cos();
                    [
                        rad * (2.0 * theta).cos(),
                        0.42 * (3.0 * theta).sin() + (u - 0.5) * 0.6,
                        rad * (2.0 * theta).sin(),
                    ]
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
            positions.push(pt);
        }
    }

    for r in 0..rings {
        for s in 0..segs {
            let next_s = (s + 1) % segs;
            let a = (r * segs + s) as u16;
            let b = (r * segs + next_s) as u16;
            let c = ((r + 1) * segs + next_s) as u16;
            let d = ((r + 1) * segs + s) as u16;
            faces.push([a, b, c]);
            faces.push([a, c, d]);
        }
    }

    for &[i0, i1, i2] in &faces {
        let p0 = positions[i0 as usize];
        let p1 = positions[i1 as usize];
        let p2 = positions[i2 as usize];
        let e1 = [p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]];
        let e2 = [p2[0] - p0[0], p2[1] - p0[1], p2[2] - p0[2]];
        let fn_vec = [
            e1[1] * e2[2] - e1[2] * e2[1],
            e1[2] * e2[0] - e1[0] * e2[2],
            e1[0] * e2[1] - e1[1] * e2[0],
        ];
        for &idx in &[i0 as usize, i1 as usize, i2 as usize] {
            normals[idx][0] += fn_vec[0];
            normals[idx][1] += fn_vec[1];
            normals[idx][2] += fn_vec[2];
        }
    }

    for (idx, n) in normals.iter_mut().enumerate() {
        let len = (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt();
        if len > 1e-6 {
            n[0] /= len;
            n[1] /= len;
            n[2] /= len;
        } else {
            let p = positions[idx];
            let plen = (p[0] * p[0] + p[1] * p[1] + p[2] * p[2]).sqrt();
            if plen > 1e-6 {
                *n = [p[0] / plen, p[1] / plen, p[2] / plen];
            } else {
                *n = [0.0, 1.0, 0.0];
            }
        }
    }

    (positions, normals, faces)
}

fn shader_pbr_factors(shader: Vibe3dPbrShader) -> ([f32; 4], f32, f32) {
    match shader {
        Vibe3dPbrShader::ObsidianGlass => ([0.118, 0.161, 0.231, 0.92], 0.15, 0.08),
        Vibe3dPbrShader::BioluminescentPlasma => ([0.024, 0.714, 0.831, 1.00], 0.10, 0.22),
        Vibe3dPbrShader::BrushedTitanium => ([0.580, 0.639, 0.722, 1.00], 0.92, 0.28),
        Vibe3dPbrShader::CrystallineQuartz => ([0.659, 0.333, 0.969, 0.95], 0.05, 0.12),
    }
}

fn sanitize_json_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean.is_empty() {
        "vibe_3d_scene".to_string()
    } else {
        clean
    }
}

fn vec3_bounds(items: &[[f32; 3]]) -> ([f32; 3], [f32; 3]) {
    let mut min_v = [f32::MAX; 3];
    let mut max_v = [f32::MIN; 3];
    for v in items {
        for axis in 0..3 {
            if v[axis] < min_v[axis] {
                min_v[axis] = v[axis];
            }
            if v[axis] > max_v[axis] {
                max_v[axis] = v[axis];
            }
        }
    }
    (min_v, max_v)
}

/// Export a 3D procedural mesh and PBR material into a standards-compliant Khronos glTF 2.0 Binary (`.glb`).
pub fn export_mesh_to_glb(
    scene_id: &str,
    preset: Vibe3dMeshPreset,
    shader: Vibe3dPbrShader,
) -> Vec<u8> {
    let clean_id = sanitize_json_id(scene_id);
    let (positions, normals, faces) = build_indexed_mesh_f32(preset);
    let (pos_min, pos_max) = vec3_bounds(&positions);
    let (norm_min, norm_max) = vec3_bounds(&normals);
    let (base_color, metallic, roughness) = shader_pbr_factors(shader);

    let pos_byte_len = positions.len() * 12;
    let norm_byte_len = normals.len() * 12;
    let idx_count = faces.len() * 3;
    let idx_byte_len = idx_count * 2;
    let max_index = (positions.len().saturating_sub(1)) as u16;

    let raw_bin_len = pos_byte_len + norm_byte_len + idx_byte_len;
    let padded_bin_len = (raw_bin_len + 3) & !3;
    let mut bin_chunk = Vec::with_capacity(padded_bin_len);
    for p in &positions {
        for &coord in p {
            bin_chunk.extend_from_slice(&coord.to_le_bytes());
        }
    }
    for n in &normals {
        for &coord in n {
            bin_chunk.extend_from_slice(&coord.to_le_bytes());
        }
    }
    for f in &faces {
        for &idx in f {
            bin_chunk.extend_from_slice(&idx.to_le_bytes());
        }
    }
    while bin_chunk.len() % 4 != 0 {
        bin_chunk.push(0x00);
    }

    let norm_offset = pos_byte_len;
    let idx_offset = pos_byte_len + norm_byte_len;
    let json_str = format!(
        concat!(
            r#"{{"asset":{{"version":"2.0","generator":"Webizen Vibe 3D Studio"}},"#,
            r#""scene":0,"scenes":[{{"name":"{id}","nodes":[0]}}],"#,
            r#""nodes":[{{"name":"{id}_node","mesh":0}}],"#,
            r#""meshes":[{{"name":"{mesh_name}","primitives":[{{"attributes":{{"POSITION":0,"NORMAL":1}},"indices":2,"material":0,"mode":4}}]}}],"#,
            r#""materials":[{{"name":"{mat_name}","pbrMetallicRoughness":{{"baseColorFactor":[{bc0:.4},{bc1:.4},{bc2:.4},{bc3:.4}],"metallicFactor":{met:.4},"roughnessFactor":{rough:.4}}}}}],"#,
            r#""accessors":["#,
            r#"{{"bufferView":0,"byteOffset":0,"componentType":5126,"count":{v_cnt},"type":"VEC3","min":[{pmin0:.6},{pmin1:.6},{pmin2:.6}],"max":[{pmax0:.6},{pmax1:.6},{pmax2:.6}]}},"#,
            r#"{{"bufferView":1,"byteOffset":0,"componentType":5126,"count":{v_cnt},"type":"VEC3","min":[{nmin0:.6},{nmin1:.6},{nmin2:.6}],"max":[{nmax0:.6},{nmax1:.6},{nmax2:.6}]}},"#,
            r#"{{"bufferView":2,"byteOffset":0,"componentType":5123,"count":{i_cnt},"type":"SCALAR","min":[0],"max":[{max_idx}]}}"#,
            r#"],"#,
            r#""bufferViews":["#,
            r#"{{"buffer":0,"byteOffset":0,"byteLength":{pos_len},"target":34962}},"#,
            r#"{{"buffer":0,"byteOffset":{norm_off},"byteLength":{norm_len},"target":34962}},"#,
            r#"{{"buffer":0,"byteOffset":{idx_off},"byteLength":{idx_len},"target":34963}}"#,
            r#"],"#,
            r#""buffers":[{{"byteLength":{bin_len}}}]}}"#
        ),
        id = clean_id,
        mesh_name = preset.as_str(),
        mat_name = shader.as_str(),
        bc0 = base_color[0], bc1 = base_color[1], bc2 = base_color[2], bc3 = base_color[3],
        met = metallic, rough = roughness, v_cnt = positions.len(),
        pmin0 = pos_min[0], pmin1 = pos_min[1], pmin2 = pos_min[2],
        pmax0 = pos_max[0], pmax1 = pos_max[1], pmax2 = pos_max[2],
        nmin0 = norm_min[0], nmin1 = norm_min[1], nmin2 = norm_min[2],
        nmax0 = norm_max[0], nmax1 = norm_max[1], nmax2 = norm_max[2],
        i_cnt = idx_count, max_idx = max_index,
        pos_len = pos_byte_len, norm_off = norm_offset, norm_len = norm_byte_len,
        idx_off = idx_offset, idx_len = idx_byte_len, bin_len = bin_chunk.len(),
    );

    let mut json_chunk = json_str.into_bytes();
    while json_chunk.len() % 4 != 0 {
        json_chunk.push(0x20);
    }

    let total_len = 12 + 8 + json_chunk.len() + 8 + bin_chunk.len();
    let mut glb = Vec::with_capacity(total_len);
    glb.extend_from_slice(&GLTF_MAGIC.to_le_bytes());
    glb.extend_from_slice(&GLTF_VERSION.to_le_bytes());
    glb.extend_from_slice(&(total_len as u32).to_le_bytes());

    glb.extend_from_slice(&(json_chunk.len() as u32).to_le_bytes());
    glb.extend_from_slice(&GLTF_CHUNK_JSON.to_le_bytes());
    glb.extend_from_slice(&json_chunk);

    glb.extend_from_slice(&(bin_chunk.len() as u32).to_le_bytes());
    glb.extend_from_slice(&GLTF_CHUNK_BIN.to_le_bytes());
    glb.extend_from_slice(&bin_chunk);
    glb
}

/// Export a 3D procedural mesh and PBR material metadata into a standard Wavefront `.obj` ASCII string.
pub fn export_mesh_to_wavefront_obj(
    scene_id: &str,
    preset: Vibe3dMeshPreset,
    shader: Vibe3dPbrShader,
) -> String {
    let clean_id = sanitize_json_id(scene_id);
    let (positions, normals, faces) = build_indexed_mesh_f32(preset);
    let mut out = String::with_capacity(positions.len() * 64 + faces.len() * 32 + 256);
    out.push_str("# Webizen Vibe 3D Studio Wavefront OBJ Export\n");
    out.push_str(&format!(
        "# preset={} shader={}\n",
        preset.as_str(),
        shader.as_str()
    ));
    out.push_str(&format!("o {clean_id}\n"));
    out.push_str(&format!("usemtl {}\n", shader.as_str()));

    for p in &positions {
        out.push_str(&format!("v {:.6} {:.6} {:.6}\n", p[0], p[1], p[2]));
    }
    for n in &normals {
        out.push_str(&format!("vn {:.6} {:.6} {:.6}\n", n[0], n[1], n[2]));
    }
    for &[i0, i1, i2] in &faces {
        let (a, b, c) = (i0 as usize + 1, i1 as usize + 1, i2 as usize + 1);
        out.push_str(&format!("f {a}//{a} {b}//{b} {c}//{c}\n"));
    }
    out
}

/// Write both `<data_dir>/studio/<scene_id>.glb` and `<data_dir>/studio/<scene_id>.obj` to disk.
pub fn write_scene_glb_and_obj(
    data_dir: &Path,
    scene_id: &str,
    preset: Vibe3dMeshPreset,
    shader: Vibe3dPbrShader,
) -> io::Result<(PathBuf, PathBuf)> {
    validate_human_centric_nomenclature(scene_id)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let clean_id = sanitize_json_id(scene_id);
    let studio_dir = data_dir.join("studio");
    fs::create_dir_all(&studio_dir)?;

    let glb_path = studio_dir.join(format!("{clean_id}.glb"));
    let obj_path = studio_dir.join(format!("{clean_id}.obj"));

    let glb_bytes = export_mesh_to_glb(&clean_id, preset, shader);
    let obj_text = export_mesh_to_wavefront_obj(&clean_id, preset, shader);

    fs::write(&glb_path, &glb_bytes)?;
    fs::write(&obj_path, obj_text.as_bytes())?;
    Ok((glb_path, obj_path))
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
                "qualia_vibe_3d_gltf_export_{}_{}",
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
    fn d19_2_glb_and_wavefront_obj_exporters_validate_all_four_presets() {
        let presets = [
            (
                "geodesic_dome",
                Vibe3dMeshPreset::GeodesicManifoldDome,
                Vibe3dPbrShader::BioluminescentPlasma,
            ),
            (
                "torus_quantum_core",
                Vibe3dMeshPreset::TorusKnotQuantumCore,
                Vibe3dPbrShader::ObsidianGlass,
            ),
            (
                "crystal_spire",
                Vibe3dMeshPreset::CrystalLatticeSpire,
                Vibe3dPbrShader::CrystallineQuartz,
            ),
            (
                "orbital_ring",
                Vibe3dMeshPreset::OrbitalStewardshipRing,
                Vibe3dPbrShader::BrushedTitanium,
            ),
        ];

        let tmp = ScopedTempDir::new();

        for (scene_id, preset, shader) in presets {
            let (positions, normals, faces) = build_indexed_mesh_f32(preset);
            assert_eq!(positions.len(), 144);
            assert_eq!(normals.len(), positions.len());
            assert_eq!(faces.len(), 256);

            for n in &normals {
                let len = (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt();
                assert!((len - 1.0).abs() < 1e-4, "normal must be unit length: {len}");
            }

            let glb = export_mesh_to_glb(scene_id, preset, shader);
            assert!(glb.len() > 28);
            assert_eq!(glb.len() % 4, 0, "GLB total length must be 4-byte aligned");
            assert_eq!(&glb[0..4], b"glTF");
            let version = u32::from_le_bytes([glb[4], glb[5], glb[6], glb[7]]);
            let total_len = u32::from_le_bytes([glb[8], glb[9], glb[10], glb[11]]) as usize;
            assert_eq!(version, 2);
            assert_eq!(total_len, glb.len());

            let json_len = u32::from_le_bytes([glb[12], glb[13], glb[14], glb[15]]) as usize;
            let json_type = u32::from_le_bytes([glb[16], glb[17], glb[18], glb[19]]);
            assert_eq!(json_len % 4, 0);
            assert_eq!(json_type, GLTF_CHUNK_JSON);
            assert_eq!(&glb[16..20], b"JSON");

            let json_end = 20 + json_len;
            let json_str = std::str::from_utf8(&glb[20..json_end]).unwrap().trim_end_matches(' ');
            assert!(json_str.starts_with(r#"{"asset":{"version":"2.0","generator":"Webizen Vibe 3D Studio"}"#));
            assert!(json_str.contains(r#""pbrMetallicRoughness""#));
            assert!(json_str.contains(r#""componentType":5123"#));
            assert!(json_str.ends_with('}'));

            let bin_len = u32::from_le_bytes([
                glb[json_end],
                glb[json_end + 1],
                glb[json_end + 2],
                glb[json_end + 3],
            ]) as usize;
            let bin_type = u32::from_le_bytes([
                glb[json_end + 4],
                glb[json_end + 5],
                glb[json_end + 6],
                glb[json_end + 7],
            ]);
            assert_eq!(bin_len % 4, 0);
            assert_eq!(bin_type, GLTF_CHUNK_BIN);
            assert_eq!(&glb[json_end + 4..json_end + 8], b"BIN\0");
            assert_eq!(json_end + 8 + bin_len, glb.len());

            let obj = export_mesh_to_wavefront_obj(scene_id, preset, shader);
            let v_lines = obj.lines().filter(|l| l.starts_with("v ")).count();
            let vn_lines = obj.lines().filter(|l| l.starts_with("vn ")).count();
            let f_lines = obj.lines().filter(|l| l.starts_with("f ")).count();
            assert_eq!(v_lines, positions.len());
            assert_eq!(vn_lines, normals.len());
            assert_eq!(f_lines, faces.len());
            assert!(obj.contains(&format!("o {scene_id}")));
            assert!(obj.contains("f 1//1 "));

            let (glb_path, obj_path) =
                write_scene_glb_and_obj(&tmp.0, scene_id, preset, shader).unwrap();
            assert_eq!(fs::read(&glb_path).unwrap(), glb);
            assert_eq!(fs::read_to_string(&obj_path).unwrap(), obj);
        }
    }
}
