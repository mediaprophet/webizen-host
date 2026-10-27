//! WP-11 (D11.3 & D11.4): VibeScript Projectional AST & Composite Widget Toolkit (`VibeUiUxToolkit`)
//! and 4-Modality Presentation Sheaf Compiler (`Visual`, `Haptic`, `Auditory`, `Braille`).
//!
//! Links directly to `vibe::presentation`, `vibe::web_runtime::call_web_or_ui`, and
//! `vibe::encode_value_cbor_ld` to compile declarative UI components into W3C CBOR-LD (`0xD9 0x05 0x01`)
//! sheaf artifacts without JavaScript.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vibe::presentation::{
    present, Presentation, PresentationKind, PresentationModality, PresentationSheaf,
};
use vibe::web_runtime::call_web_or_ui;
use vibe::{encode_value_cbor_ld, Span, Value};
use webizen_host_core::validate_human_centric_nomenclature;

/// Compiled 4-modality UI/UX Presentation Sheaf receipt persisted to `<data_dir>/ux/<component_id>.cbor-ld`.
#[derive(Clone, Debug, PartialEq)]
pub struct VibeUiSheafReceipt {
    pub component_id: String,
    pub label: String,
    pub projected_vibe_source: String,
    pub ast_cbor_byte_len: usize,
    pub modalities_compiled: Vec<String>,
    pub braille_unicode_preview: String,
    pub haptic_pulses: usize,
    pub auditory_cue: String,
    pub range_span: f64,
    pub dag_node_count: usize,
    pub cbor_ld_bytes: Vec<u8>,
    pub cbor_ld_path: PathBuf,
}

/// VibeScript UI/UX Projectional AST, Composite Widget, and 4-Modality Presentation Sheaf Toolkit.
pub struct VibeUiUxToolkit;

impl VibeUiUxToolkit {
    /// Convert each byte of `text` to a 6-dot/8-dot Braille cell offset (`b & 0x3F`) and map it
    /// to the Unicode Braille Patterns block (`U+2800`..`U+28FF`), returning both raw Braille cell
    /// bytes for `Presentation::braille_cells` and a human-visible Unicode Braille preview string.
    pub fn ascii_to_unicode_braille(text: &str) -> (Vec<u8>, String) {
        let mut cells = Vec::with_capacity(text.len());
        let mut preview = String::with_capacity(text.len() * 3);
        for b in text.bytes() {
            let cell = b & 0x3F;
            cells.push(cell);
            if let Some(ch) = char::from_u32(0x2800 + (cell as u32)) {
                preview.push(ch);
            }
        }
        (cells, preview)
    }

    /// Compile a VibeScript source snippet + composite UI controls into a 4-modality
    /// `PresentationSheaf` (`Visual`, `Haptic`, `Auditory`, `Braille`), encode the complete
    /// UI sheaf record into binary W3C CBOR-LD (`0xD9 0x05 0x01`), and persist it under
    /// `<data_dir>/ux/<component_id>.cbor-ld`.
    pub fn compile_and_persist_ui_sheaf(
        data_dir: &Path,
        component_id: &str,
        label: &str,
        vibe_source: &str,
        range_lo: f64,
        range_hi: f64,
    ) -> Result<VibeUiSheafReceipt, &'static str> {
        validate_human_centric_nomenclature(component_id)?;
        validate_human_centric_nomenclature(label)?;
        validate_human_centric_nomenclature(vibe_source)?;

        let safe_id: String = component_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        if safe_id.is_empty() {
            return Err("Component identifier must contain at least one alphanumeric character");
        }

        let span = Span::new(0, 0);

        // 1. Projectional AST editor (`ui.projectional_editor`)
        let proj_val = call_web_or_ui(
            "ui.projectional_editor",
            &[
                Value::String(component_id.into()),
                Value::String(vibe_source.into()),
            ],
            span,
        )
        .map_err(|_| "ui.projectional_editor failed to parse or project VibeScript AST")?
        .ok_or("ui.projectional_editor returned None")?;

        let (projected_vibe_source, ast_cbor_byte_len) = match &proj_val {
            Value::Record(rec) => {
                let src = match rec.get("projected_source") {
                    Some(Value::String(s)) => s.clone(),
                    _ => return Err("Missing projected_source in ui.projectional_editor record"),
                };
                let len = match rec.get("ast_cbor_byte_len") {
                    Some(Value::I64(n)) if *n >= 0 => *n as usize,
                    _ => return Err("Missing ast_cbor_byte_len in ui.projectional_editor record"),
                };
                (src, len)
            }
            _ => return Err("ui.projectional_editor must return a Record"),
        };

        // 2. Range interval composite control (`ui.range_interval`)
        let range_val = call_web_or_ui(
            "ui.range_interval",
            &[
                Value::String(format!("{component_id}-range")),
                Value::F64(0.0),
                Value::F64(100.0),
                Value::F64(range_lo),
                Value::F64(range_hi),
            ],
            span,
        )
        .map_err(|_| "ui.range_interval evaluation failed")?
        .ok_or("ui.range_interval returned None")?;

        let range_span = match &range_val {
            Value::Record(rec) => match rec.get("span") {
                Some(Value::F64(s)) => *s,
                _ => return Err("Missing span in ui.range_interval record"),
            },
            _ => return Err("ui.range_interval must return a Record"),
        };

        // 3. Tag input composite control (`ui.tag_input`)
        let tag_val = call_web_or_ui(
            "ui.tag_input",
            &[
                Value::String(format!("{component_id}-tags")),
                Value::List(vec![]),
                Value::String("human-centric,vibescript,cbor-ld,aaa-3d".into()),
            ],
            span,
        )
        .map_err(|_| "ui.tag_input evaluation failed")?
        .ok_or("ui.tag_input returned None")?;

        // 4. DAG canvas composite control (`ui.dag_canvas`)
        let dag_val = call_web_or_ui(
            "ui.dag_canvas",
            &[
                Value::String(format!("{component_id}-dag")),
                Value::List(vec![
                    Value::String("Ingest".into()),
                    Value::String("Project".into()),
                    Value::String("Render3D".into()),
                ]),
                Value::List(vec![
                    Value::String("Ingest->Project".into()),
                    Value::String("Project->Render3D".into()),
                ]),
            ],
            span,
        )
        .map_err(|_| "ui.dag_canvas evaluation failed")?
        .ok_or("ui.dag_canvas returned None")?;

        let dag_node_count = match &dag_val {
            Value::Record(rec) => match rec.get("node_count") {
                Some(Value::I64(n)) if *n >= 0 => *n as usize,
                _ => return Err("Missing node_count in ui.dag_canvas record"),
            },
            _ => return Err("ui.dag_canvas must return a Record"),
        };

        // 5. Construct 4-modality PresentationSheaf (Visual, Haptic, Auditory, Braille)
        let mut sheaf = PresentationSheaf::new(Value::String(label.to_string()));
        let base_sheaf = present(&Value::F64((range_span / 100.0).clamp(0.15, 1.0)));
        let base_opacity = base_sheaf
            .for_modality(PresentationModality::Visual)
            .first()
            .and_then(|p| {
                if p.kind == PresentationKind::CssProperties {
                    if let Value::Record(m) = &p.payload {
                        if let Some(Value::F64(op)) = m.get("opacity") {
                            return Some(*op);
                        }
                    }
                }
                None
            })
            .unwrap_or(0.95);

        // Modality 1: Visual (glassmorphic CSS properties + vector SVG badge)
        let mut css_props = BTreeMap::new();
        css_props.insert(
            "backdrop-filter".into(),
            Value::String("blur(24px) saturate(165%)".into()),
        );
        css_props.insert(
            "border".into(),
            Value::String("1px solid rgba(56, 189, 248, 0.42)".into()),
        );
        css_props.insert("opacity".into(), Value::F64(base_opacity));
        sheaf.add(Presentation::css(css_props));
        sheaf.add(Presentation::svg(
            "<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' stroke='#38bdf8' fill='none'/></svg>",
        ));

        // Modality 2: Haptic (3-pulse tactile feedback pattern)
        let haptic_schedule = vec![(45, 0.75), (90, 0.95), (30, 0.40)];
        let haptic_pulses = haptic_schedule.len();
        sheaf.add(Presentation::haptic_pattern(haptic_schedule));

        // Modality 3: Auditory (harmonic earcon + speech announcement)
        let earcon_id = "earcon.harmonic.c5";
        sheaf.add(Presentation::audio_earcon(earcon_id));
        sheaf.add(Presentation::speech(label));
        let auditory_cue = format!("{earcon_id} + speech(\"{label}\")");

        // Modality 4: Braille (refreshable Braille cell array + Unicode Braille preview)
        let (braille_cells, braille_unicode_preview) = Self::ascii_to_unicode_braille(label);
        sheaf.add(Presentation::braille_cells(braille_cells));

        // Verify all 4 modalities are compiled in the sheaf
        let compiled_mods = sheaf.modalities();
        for required in [
            PresentationModality::Visual,
            PresentationModality::Haptic,
            PresentationModality::Auditory,
            PresentationModality::Braille,
        ] {
            if !compiled_mods.contains(&required) {
                return Err("PresentationSheaf missing required sensory modality");
            }
        }
        let modalities_compiled: Vec<String> = compiled_mods
            .into_iter()
            .map(|m| m.as_str().to_string())
            .collect();

        // 6. Assemble top-level Record and encode to W3C CBOR-LD (`0xD9 0x05 0x01`)
        let mut top_map = BTreeMap::new();
        top_map.insert("component_id".into(), Value::String(component_id.into()));
        top_map.insert("label".into(), Value::String(label.into()));
        top_map.insert("projectional_editor".into(), proj_val);
        top_map.insert("range_interval".into(), range_val);
        top_map.insert("tag_input".into(), tag_val);
        top_map.insert("dag_canvas".into(), dag_val);
        top_map.insert("presentation_sheaf".into(), sheaf.to_value());
        top_map.insert(
            "braille_unicode_preview".into(),
            Value::String(braille_unicode_preview.clone()),
        );
        let top_record = Value::Record(top_map);

        let cbor_ld_bytes =
            encode_value_cbor_ld(&top_record, "https://ns.webcivics.net/ux/v1");
        if cbor_ld_bytes.len() < 3 || cbor_ld_bytes[0..3] != [0xD9, 0x05, 0x01] {
            return Err("Encoded UX sheaf missing W3C CBOR-LD tag header (0xD9 0x05 0x01)");
        }

        let ux_dir = data_dir.join("ux");
        fs::create_dir_all(&ux_dir)
            .map_err(|_| "Failed to create <data_dir>/ux directory for CBOR-LD sheaf")?;
        let cbor_ld_path = ux_dir.join(format!("{safe_id}.cbor-ld"));
        fs::write(&cbor_ld_path, &cbor_ld_bytes)
            .map_err(|_| "Failed to write compiled UI sheaf CBOR-LD artifact to disk")?;

        Ok(VibeUiSheafReceipt {
            component_id: component_id.to_string(),
            label: label.to_string(),
            projected_vibe_source,
            ast_cbor_byte_len,
            modalities_compiled,
            braille_unicode_preview,
            haptic_pulses,
            auditory_cue,
            range_span,
            dag_node_count,
            cbor_ld_bytes,
            cbor_ld_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct ScopedTempDir(PathBuf);

    impl ScopedTempDir {
        fn new(prefix: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "qualia_{prefix}_{}_{}",
                std::process::id(),
                id
            ));
            let _ = fs::create_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScopedTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn d11_3_and_d11_4_vibe_ux_toolkit_compiles_projectional_ast_composite_widgets_and_4_modality_sheaf(
    ) {
        let tmp = ScopedTempDir::new("vibe_ux_toolkit");
        let vibe_snippet = "pure fn hero_card(x: Int) budget(steps: 100) -> Int { return x; }";

        let receipt = VibeUiUxToolkit::compile_and_persist_ui_sheaf(
            tmp.path(),
            "cpanel-hero-card",
            "Human-Centric Spatial Bento Card",
            vibe_snippet,
            15.0,
            85.0,
        )
        .expect("VibeUiUxToolkit should compile projectional AST and 4-modality sheaf");

        assert_eq!(receipt.component_id, "cpanel-hero-card");
        assert!(receipt.projected_vibe_source.contains("hero_card"));
        assert!(receipt.ast_cbor_byte_len > 0);
        assert_eq!(receipt.haptic_pulses, 3);
        assert!(receipt.auditory_cue.contains("earcon.harmonic.c5"));
        assert!((receipt.range_span - 70.0).abs() < 1e-9);
        assert_eq!(receipt.dag_node_count, 3);

        // Verify all 4 sensory modalities are present
        for expected_mod in ["visual", "haptic", "auditory", "braille"] {
            assert!(
                receipt
                    .modalities_compiled
                    .iter()
                    .any(|m| m == expected_mod),
                "missing modality {expected_mod}"
            );
        }

        // Verify Unicode Braille preview contains characters in U+2800..=U+28FF
        assert!(!receipt.braille_unicode_preview.is_empty());
        assert!(receipt
            .braille_unicode_preview
            .chars()
            .all(|c| ('\u{2800}'..='\u{28FF}').contains(&c)));

        // Verify W3C CBOR-LD header (0xD9 0x05 0x01) and on-disk persistence
        assert!(receipt.cbor_ld_bytes.starts_with(&[0xD9, 0x05, 0x01]));
        let expected_path = tmp.path().join("ux").join("cpanel-hero-card.cbor-ld");
        assert_eq!(receipt.cbor_ld_path, expected_path);
        assert!(expected_path.exists());
        let disk_bytes = fs::read(&expected_path).unwrap();
        assert_eq!(disk_bytes, receipt.cbor_ld_bytes);
    }
}
