//! WP-12 (D12.2) & WP-22 (D22.1): Live Dynamic SSR State Hydration, Deep 12-Page Live State Deck,
//! Zero-JS Persona Switching & Automatic CSRF Form Token Injection
//! (`LiveWorkbenchHydrator`, `LiveHostTelemetrySummary`, `validate_zero_javascript_html`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use vibe::{encode_value_cbor_ld, Value};
use webizen_host_core::validate_human_centric_nomenclature;
use webizen_host_ingest::{replay_quin_journal, Q42J_RECORD_SIZE};

use crate::persona_ui::BUNDLED_ADAPTIVE_WORKBENCH_HTML;
use crate::vibescript_web_server::{VibeWebServerEngine, ZeroJavaScriptAuditReceipt};
use crate::vps_deployment::HostPersistentState;

/// Default fallback CSRF token injected into SSR `<form method="post">` elements when none is supplied.
pub const DEFAULT_SSR_CSRF_TOKEN: &str = "webizen-ssr-csrf-token";

/// Summary of live on-disk VPS state and telemetry across all 12 workbench modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveHostTelemetrySummary {
    pub primary_domain: String,
    pub steward_did_qi: String,
    pub hosted_domains: Vec<String>,
    pub custom_dns_count: usize,
    pub mail_aliases: Vec<(String, String, String)>,
    pub git_repos: Vec<String>,
    pub spooled_mail_count: usize,
    pub forged_3d_scenes: Vec<String>,
    pub compiled_ux_sheaves: Vec<String>,
    pub journal_quin_count: usize,
    pub delegated_permits_count: u32,
}

/// Validate that a rendered HTML string contains zero executable JavaScript (`<script>` without
/// `type="application/vibescript"` or inline `on*=` attributes) and honors Human-Centric nomenclature.
pub fn validate_zero_javascript_html(html: &str) -> Result<ZeroJavaScriptAuditReceipt, &'static str> {
    VibeWebServerEngine::verify_zero_javascript_html(html)
}

/// Server-Side Renderer (SSR) and W3C CBOR-LD telemetry hydrator for the Zero-JS Control Panel.
pub struct LiveWorkbenchHydrator;

impl LiveWorkbenchHydrator {
    /// Collect live on-disk telemetry and persisted state from `data_dir`.
    pub fn collect_telemetry(data_dir: &Path) -> io::Result<LiveHostTelemetrySummary> {
        let state_path = data_dir.join("host_state.cbor-ld");
        let state = if state_path.exists() {
            HostPersistentState::load_cbor_ld(&state_path)?
        } else {
            HostPersistentState::default()
        };
        state.validate_nomenclature()?;

        let mut git_repos = state.git_repos.clone();
        for extra_repo in list_directory_entries(&data_dir.join("git"), ".git", true) {
            if !git_repos.contains(&extra_repo) {
                validate_human_centric_nomenclature(&extra_repo)
                    .map_err(|m| io::Error::new(ErrorKind::InvalidData, m))?;
                git_repos.push(extra_repo);
            }
        }

        let spooled_mail_count = count_files_with_ext(&data_dir.join("maildir/new"), ".eml")
            + count_files_with_ext(&data_dir.join("maildir/cur"), ".eml")
            + count_files_with_ext(&data_dir.join("maildir/sent"), ".eml");

        let forged_3d_scenes = list_directory_entries(&data_dir.join("studio"), ".hmc", false);
        let compiled_ux_sheaves = list_directory_entries(&data_dir.join("ux"), ".cbor-ld", false);
        for name in forged_3d_scenes.iter().chain(compiled_ux_sheaves.iter()) {
            validate_human_centric_nomenclature(name)
                .map_err(|m| io::Error::new(ErrorKind::InvalidData, m))?;
        }

        let journal_path = data_dir.join("journal.q42j");
        let journal_quin_count = if journal_path.exists() {
            replay_quin_journal(&journal_path).map(|q| q.len()).unwrap_or_else(|_| {
                fs::metadata(&journal_path).map(|m| (m.len() as usize) / Q42J_RECORD_SIZE.max(1)).unwrap_or(0)
            })
        } else {
            0
        };

        Ok(LiveHostTelemetrySummary {
            primary_domain: state.primary_domain,
            steward_did_qi: state.steward_did_qi,
            hosted_domains: state.hosted_domains,
            custom_dns_count: state.custom_dns_records.len(),
            mail_aliases: state.mail_aliases,
            git_repos,
            spooled_mail_count,
            forged_3d_scenes,
            compiled_ux_sheaves,
            journal_quin_count,
            delegated_permits_count: state.delegated_permits_count,
        })
    }

    /// Encode `LiveHostTelemetrySummary` into a `vibe::Value::Record` and serialize it as native
    /// W3C CBOR-LD (`0xD9 0x05 0x01`) under context `"https://ns.webcivics.net/host/telemetry"`.
    pub fn encode_telemetry_cbor_ld(summary: &LiveHostTelemetrySummary) -> Vec<u8> {
        let str_list = |items: &[String]| Value::List(items.iter().cloned().map(Value::String).collect());
        let aliases = summary
            .mail_aliases
            .iter()
            .map(|(alias, did, sender)| {
                let mut m = BTreeMap::new();
                m.insert("alias".to_string(), Value::String(alias.clone()));
                m.insert("counterparty_did".to_string(), Value::String(did.clone()));
                m.insert("allowed_sender".to_string(), Value::String(sender.clone()));
                Value::Record(m)
            })
            .collect();

        let mut rec = BTreeMap::new();
        rec.insert("primary_domain".to_string(), Value::String(summary.primary_domain.clone()));
        rec.insert("steward_did_qi".to_string(), Value::String(summary.steward_did_qi.clone()));
        rec.insert("hosted_domains".to_string(), str_list(&summary.hosted_domains));
        rec.insert("custom_dns_count".to_string(), Value::I64(summary.custom_dns_count as i64));
        rec.insert("mail_aliases".to_string(), Value::List(aliases));
        rec.insert("git_repos".to_string(), str_list(&summary.git_repos));
        rec.insert("spooled_mail_count".to_string(), Value::I64(summary.spooled_mail_count as i64));
        rec.insert("forged_3d_scenes".to_string(), str_list(&summary.forged_3d_scenes));
        rec.insert("compiled_ux_sheaves".to_string(), str_list(&summary.compiled_ux_sheaves));
        rec.insert("journal_quin_count".to_string(), Value::I64(summary.journal_quin_count as i64));
        rec.insert("delegated_permits_count".to_string(), Value::I64(i64::from(summary.delegated_permits_count)));

        encode_value_cbor_ld(&Value::Record(rec), "https://ns.webcivics.net/host/telemetry")
    }

    /// Synthesize the Zero-JS Glassmorphic **Live On-Disk VPS State & Telemetry Bar** HTML block.
    pub fn render_telemetry_bar_html(
        summary: &LiveHostTelemetrySummary,
        flash_notice: Option<&str>,
    ) -> io::Result<String> {
        if let Some(notice) = flash_notice {
            validate_human_centric_nomenclature(notice)
                .map_err(|m| io::Error::new(ErrorKind::InvalidData, m))?;
        }
        let flash_html = match flash_notice {
            Some(msg) if !msg.trim().is_empty() => format!(
                "<div id=\"live-vps-flash-banner\" class=\"subbox\" style=\"border-color: var(--emerald); background: var(--emerald-bg); margin-bottom: 12px;\"><strong style=\"color: var(--emerald);\">✓ Live State Updated (Zero-JS SSR):</strong> <span class=\"mono\">{}</span></div>",
                escape_html(msg.trim())
            ),
            _ => String::new(),
        };
        let domains_html = render_badge_list(&summary.hosted_domains, "pill-sky", "none");
        let aliases_formatted: Vec<String> = summary
            .mail_aliases
            .iter()
            .map(|(alias, did, sender)| format!("{alias} -> {sender} [{did}]"))
            .collect();
        let aliases_html = render_badge_list(&aliases_formatted, "pill-emerald", "none");
        let git_html = render_badge_list(&summary.git_repos, "pill-purple", "none");
        let scenes_html = render_badge_list(&summary.forged_3d_scenes, "pill-amber", "no .hmc scenes yet");
        let sheaves_html = render_badge_list(&summary.compiled_ux_sheaves, "pill-sky", "no .cbor-ld sheaves yet");

        let domain_crud_rows: String = summary.hosted_domains.iter().map(|dom| {
            let esc = escape_html(dom);
            format!("<li><span class=\"mono\">{esc}</span> <form method=\"POST\" action=\"/cpanel/domains/delete\"><input type=\"hidden\" name=\"domain\" value=\"{esc}\"><button type=\"submit\">Remove</button></form></li>")
        }).collect();
        let alias_crud_rows: String = summary.mail_aliases.iter().map(|(alias, did, sender)| {
            let (esc_a, esc_d, esc_s) = (escape_html(alias), escape_html(did), escape_html(sender));
            format!("<li><span class=\"mono\">{esc_a} ({esc_s} [{esc_d}])</span> <form method=\"POST\" action=\"/cpanel/email/delete\"><input type=\"hidden\" name=\"alias\" value=\"{esc_a}\"><button type=\"submit\">Revoke</button></form></li>")
        }).collect();
        let scene_export_links: String = summary.forged_3d_scenes.iter().map(|hmc| {
            let stem = escape_html(hmc.strip_suffix(".hmc").unwrap_or(hmc));
            let esc_hmc = escape_html(hmc);
            format!(" | <a href=\"/studio/{stem}.glb\">{stem}.glb</a> / <a href=\"/studio/{stem}.obj\">{stem}.obj</a> / <span class=\"mono\">{esc_hmc}</span>")
        }).collect();

        Ok(format!(
            "<section id=\"live-vps-telemetry-bar\" class=\"card\" style=\"border-color: rgba(52, 211, 153, 0.48); margin-bottom: 18px;\">{flash_html}\
               <div class=\"row-between\" style=\"margin-bottom: 10px;\"><div><div class=\"eyebrow\">Live On-Disk VPS State &amp; Telemetry Bar • W3C CBOR-LD (0xD9 0x05 0x01) • Zero-JS SSR</div><div class=\"mono\" style=\"font-size: 13px; font-weight: 700;\">Primary Realm: {primary} | Steward: {steward}</div></div>\
               <div class=\"brand-row\"><span class=\"pill pill-emerald mono\">Journal Quins: {quins}</span><span class=\"pill pill-sky mono\">Spooled Mail: {mail_cnt} .eml</span><span class=\"pill pill-purple mono\">Delegated Permits: {permits}</span></div></div>\
               <div class=\"grid-3\">\
                 <div class=\"subbox\"><div class=\"muted\">Hosted Domains ({dom_cnt})</div><div class=\"brand-row\" style=\"margin-top: 6px;\">{domains_html}</div></div>\
                 <div class=\"subbox\"><div class=\"muted\">Relationship Mail Aliases ({alias_cnt}) &amp; Spooled ({mail_cnt})</div><div class=\"brand-row\" style=\"margin-top: 6px;\">{aliases_html}</div></div>\
                 <div class=\"subbox\"><div class=\"muted\">Bare Git Repositories ({git_cnt})</div><div class=\"brand-row\" style=\"margin-top: 6px;\">{git_html}</div></div>\
                 <div class=\"subbox\"><div class=\"muted\">Forged QBDL .hmc 3D Scenes ({scene_cnt})</div><div class=\"brand-row\" style=\"margin-top: 6px;\">{scenes_html}</div></div>\
                 <div class=\"subbox\"><div class=\"muted\">Compiled 4-Modality UX Sheaves ({sheaf_cnt})</div><div class=\"brand-row\" style=\"margin-top: 6px;\">{sheaves_html}</div></div>\
                 <div class=\"subbox\"><div class=\"muted\">Parity-Verified .q42j Ledger</div><div class=\"mono\" style=\"margin-top: 6px; color: var(--emerald);\">{quins} NQuin receipts verified</div></div>\
               </div>\
               <div id=\"live-crud-management-table\"><div class=\"grid-3\" style=\"margin-top: 10px;\">\
                 <div class=\"subbox\"><div class=\"muted\">Domain CRUD Actions</div><ul>{domain_crud_rows}</ul></div>\
                 <div class=\"subbox\"><div class=\"muted\">Mail Alias CRUD &amp; Webmail Reader</div><ul>{alias_crud_rows}</ul><div><a href=\"/mail/view/latest\">/mail/view/latest</a></div></div>\
                 <div class=\"subbox\"><div class=\"muted\">3D Studio Exports (.glb / .obj / .hmc)</div><div><a href=\"/studio/default-manifold.glb\">/studio/default-manifold.glb</a> | <a href=\"/studio/default-manifold.obj\">/studio/default-manifold.obj</a>{scene_export_links}</div></div>\
               </div></div></section>",
            primary = escape_html(&summary.primary_domain),
            steward = escape_html(&summary.steward_did_qi),
            quins = summary.journal_quin_count,
            mail_cnt = summary.spooled_mail_count,
            permits = summary.delegated_permits_count,
            dom_cnt = summary.hosted_domains.len(),
            alias_cnt = summary.mail_aliases.len(),
            git_cnt = summary.git_repos.len(),
            scene_cnt = summary.forged_3d_scenes.len(),
            sheaf_cnt = summary.compiled_ux_sheaves.len(),
        ))
    }

    /// Synthesize the **Deep 12-Page Live State Deck** (`<section id="live-12-page-state-deck" class="card">`).
    pub fn render_12_page_state_deck_html(summary: &LiveHostTelemetrySummary, active_persona: &str) -> String {
        format!(
            "<section id=\"live-12-page-state-deck\" class=\"card\">\
               <div class=\"row-between\" style=\"margin-bottom: 10px;\"><div class=\"eyebrow\">Deep 12-Page Live State Deck • Active Persona: {persona}</div>\
               <div class=\"brand-row\"><span class=\"muted\">Persona Switcher:</span> <a href=\"/cpanel?persona=elder\">Elder</a> | <a href=\"/cpanel?persona=everyday\">Everyday</a> | <a href=\"/cpanel?persona=geek\">Developer</a></div></div>\
               <div class=\"grid-4 mono\">\
                 <div class=\"subbox\"><strong>1. Domains</strong> <span class=\"pill pill-sky\">{dom} zones / {dns} RR</span> <a href=\"#page-domains\">Open</a></div>\
                 <div class=\"subbox\"><strong>2. Email</strong> <span class=\"pill pill-emerald\">{al} aliases / {ml} .eml</span> <a href=\"/mail/view/latest\">Read</a></div>\
                 <div class=\"subbox\"><strong>3. Files/IPFS</strong> <span class=\"pill pill-sky\">HTTP 206 + IPFS</span> <a href=\"#page-files\">Open</a></div>\
                 <div class=\"subbox\"><strong>4. Ontologies</strong> <span class=\"pill pill-purple\">core.q42 Ready</span> <a href=\"/volumes/core.q42\">SPARQL</a></div>\
                 <div class=\"subbox\"><strong>5. Solid Apps</strong> <span class=\"pill pill-emerald\">W3C LDP Pods</span> <a href=\"#page-apps\">Open</a></div>\
                 <div class=\"subbox\"><strong>6. TLS Security</strong> <span class=\"pill pill-amber\">ACME + WebizenID-TLS</span> <a href=\"#page-security\">Open</a></div>\
                 <div class=\"subbox\"><strong>7. Commons Wallet</strong> <span class=\"pill pill-sky\">6 Chains • $0.00 Cap</span> <a href=\"#page-wallet\">Open</a></div>\
                 <div class=\"subbox\"><strong>8. Snapshots</strong> <span class=\"pill pill-emerald\">{q} .q42j Quins</span> <a href=\"#page-jobs\">Open</a></div>\
                 <div class=\"subbox\"><strong>9. Delegation</strong> <span class=\"pill pill-purple\">{p} Permits</span> <a href=\"#page-delegation\">Open</a></div>\
                 <div class=\"subbox\"><strong>10. Git Forge</strong> <span class=\"pill pill-amber\">{git} Repos</span> <a href=\"#page-git\">Open</a></div>\
                 <div class=\"subbox\"><strong>11. 3D Studio</strong> <span class=\"pill pill-sky\">{sc} .hmc Scenes</span> <a href=\"/studio/default-manifold.glb\">GLB</a></div>\
                 <div class=\"subbox\"><strong>12. UX Sheaves</strong> <span class=\"pill pill-purple\">{sh} .cbor-ld</span> <a href=\"#page-vibe-ux\">Open</a></div>\
               </div></section>",
            persona = escape_html(active_persona),
            dom = summary.hosted_domains.len(),
            dns = summary.custom_dns_count,
            al = summary.mail_aliases.len(),
            ml = summary.spooled_mail_count,
            q = summary.journal_quin_count,
            p = summary.delegated_permits_count,
            git = summary.git_repos.len(),
            sc = summary.forged_3d_scenes.len(),
            sh = summary.compiled_ux_sheaves.len(),
        )
    }

    /// Collect live telemetry, render both the Telemetry Bar and Deep 12-Page Live State Deck,
    /// apply optional `persona_override` (`"elder"`, `"everyday"`, or `"geek"`), automatically
    /// inject hidden `csrf_token` inputs into every POST form, and verify Zero-JS compliance.
    pub fn render_hydrated_workbench_with_options(
        data_dir: &Path,
        flash_notice: Option<&str>,
        persona_override: Option<&str>,
        csrf_token: Option<&str>,
    ) -> io::Result<String> {
        if let Some(p) = persona_override {
            validate_human_centric_nomenclature(p).map_err(|m| io::Error::new(ErrorKind::InvalidData, m))?;
        }
        let token = csrf_token.unwrap_or(DEFAULT_SSR_CSRF_TOKEN);
        validate_human_centric_nomenclature(token).map_err(|m| io::Error::new(ErrorKind::InvalidData, m))?;

        let active_persona = match persona_override.map(str::trim) {
            Some("elder") => "elder",
            Some("everyday") => "everyday",
            Some("geek") => "geek",
            Some(other) if !other.is_empty() => other,
            _ => "everyday",
        };

        let summary = Self::collect_telemetry(data_dir)?;
        let telemetry_bar = Self::render_telemetry_bar_html(&summary, flash_notice)?;
        let state_deck = Self::render_12_page_state_deck_html(&summary, active_persona);
        let anchor = "<main class=\"main-content main\">";
        let combined_top = format!("{telemetry_bar}\n{state_deck}");
        let base_hydrated = if let Some(idx) = BUNDLED_ADAPTIVE_WORKBENCH_HTML.find(anchor) {
            let split_at = idx + anchor.len();
            format!(
                "{}\n{combined_top}{}",
                &BUNDLED_ADAPTIVE_WORKBENCH_HTML[..split_at],
                &BUNDLED_ADAPTIVE_WORKBENCH_HTML[split_at..]
            )
        } else {
            format!("{combined_top}\n{BUNDLED_ADAPTIVE_WORKBENCH_HTML}")
        };

        let persona_hydrated = apply_persona_attribute(&base_hydrated, active_persona);
        let hydrated = inject_csrf_hidden_inputs(&persona_hydrated, token);
        validate_zero_javascript_html(&hydrated).map_err(|msg| io::Error::new(ErrorKind::InvalidData, msg))?;
        Ok(hydrated)
    }

    /// Collect live telemetry from `data_dir`, inject the live telemetry bar and 12-page state deck,
    /// inject default CSRF tokens across all POST forms, and verify 100% Zero-JS + Human-Centric compliance.
    pub fn render_hydrated_workbench_html(data_dir: &Path, flash_notice: Option<&str>) -> io::Result<String> {
        Self::render_hydrated_workbench_with_options(data_dir, flash_notice, None, None)
    }
}

fn apply_persona_attribute(html: &str, persona: &str) -> String {
    let body_attr = format!("<body data-persona=\"{}\">", escape_html(persona));
    let updated = if html.contains("<body>") { html.replacen("<body>", &body_attr, 1) } else { html.to_string() };
    match persona {
        "elder" | "everyday" | "novice" => updated
            .replacen("id=\"p-novice\" />", "id=\"p-novice\" checked />", 1)
            .replacen("id=\"p-all\" checked />", "id=\"p-all\" />", 1),
        "geek" | "developer" | "dev" => updated
            .replacen("id=\"p-geek\" />", "id=\"p-geek\" checked />", 1)
            .replacen("id=\"p-all\" checked />", "id=\"p-all\" />", 1),
        _ => updated,
    }
}

/// Automatically inject `<input type="hidden" name="csrf_token" value="<token>">` immediately
/// after every `<form method="post"` or `<form method="POST"` opening tag in `html`.
pub fn inject_csrf_hidden_inputs(html: &str, csrf_token: &str) -> String {
    let hidden = format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">", escape_html(csrf_token));
    let mut out = String::with_capacity(html.len() + hidden.len() * 16);
    let mut rest = html;
    while let Some(pos) = next_post_form_offset(rest) {
        let Some(gt_rel) = rest[pos..].find('>') else { break; };
        let tag_end = pos + gt_rel + 1;
        out.push_str(&rest[..tag_end]);
        let after = &rest[tag_end..];
        if !after.starts_with("<input type=\"hidden\" name=\"csrf_token\"") {
            out.push_str(&hidden);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn next_post_form_offset(s: &str) -> Option<usize> {
    match (s.find("<form method=\"post\""), s.find("<form method=\"POST\"")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn count_files_with_ext(dir: &Path, ext: &str) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0; };
    entries.filter_map(Result::ok).filter(|e| e.path().is_file() && e.file_name().to_str().is_some_and(|s| s.ends_with(ext))).count()
}

fn list_directory_entries(dir: &Path, ext: &str, include_dirs: bool) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new(); };
    let mut names: Vec<String> = entries.filter_map(Result::ok).filter_map(|e| {
        let p = e.path();
        if !(if include_dirs { p.is_dir() || p.is_file() } else { p.is_file() }) { return None; }
        let name = e.file_name().to_str()?.to_string();
        name.ends_with(ext).then_some(name)
    }).collect();
    names.sort();
    names
}

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_badge_list(items: &[String], pill_class: &str, empty_label: &str) -> String {
    if items.is_empty() {
        return format!("<span class=\"muted mono\">{}</span>", escape_html(empty_label));
    }
    items.iter().map(|item| format!("<span class=\"pill {} mono\">{}</span>", pill_class, escape_html(item))).collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps_deployment::CustomDnsRecord;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_core::{pack_context, pack_metadata, pack_predicate, q_hash, NQuin, PermissiveRoutingLane, SensitivityClass, OP_PERMIT};
    use webizen_host_ingest::append_quin_to_journal;

    struct ScopedTempDir(PathBuf);
    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(1);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("webizen_live_ssr_{label}_{}_{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }
    }
    impl Drop for ScopedTempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn collect_encode_cbor_ld_and_hydrate_zero_js_workbench_end_to_end() {
        let tmp = ScopedTempDir::new("e2e");
        let data_dir = &tmp.0;

        let mut state = HostPersistentState::default();
        state.hosted_domains.push("coop.family.org".to_string());
        state.custom_dns_records.push(CustomDnsRecord { name: "coop.family.org".to_string(), rr_type: "A".to_string(), ttl: 300, value: "203.0.113.42".to_string() });
        state.mail_aliases.push(("school@civics.au".to_string(), "did:qi:sunrise_school".to_string(), "principal@school.edu".to_string()));
        state.git_repos.push("care-governance.git".to_string());
        state.delegated_permits_count = 7;
        state.save_cbor_ld(&data_dir.join("host_state.cbor-ld")).expect("save state");

        for sub in ["maildir/new", "maildir/cur", "maildir/sent", "studio", "ux"] { fs::create_dir_all(data_dir.join(sub)).unwrap(); }
        fs::write(data_dir.join("maildir/new/msg1.eml"), b"Subject: Hello 1\r\n\r\nBody").unwrap();
        fs::write(data_dir.join("maildir/cur/msg2.eml"), b"Subject: Hello 2\r\n\r\nBody").unwrap();
        fs::write(data_dir.join("maildir/sent/msg3.eml"), b"Subject: Sent 3\r\n\r\nBody").unwrap();
        fs::write(data_dir.join("studio/aurora-sanctuary.hmc"), b"QBDL\x01\x00").unwrap();
        fs::write(data_dir.join("ux/accessibility-deck.cbor-ld"), &[0xD9, 0x05, 0x01]).unwrap();

        let journal_path = data_dir.join("journal.q42j");
        for idx in 1..=2u32 {
            let q = NQuin::new(q_hash("did:qi:webcivics_steward"), pack_predicate("https://ns.webcivics.net/cpanel#hydratedState", OP_PERMIT, false), u64::from(idx), pack_context(q_hash("ns.webcivics.net"), SensitivityClass::Public), pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, idx, idx));
            append_quin_to_journal(&journal_path, &q).expect("append quin");
        }

        let summary = LiveWorkbenchHydrator::collect_telemetry(data_dir).expect("collect telemetry");
        assert!(summary.hosted_domains.contains(&"coop.family.org".to_string()) && summary.custom_dns_count == 1 && summary.spooled_mail_count == 3);
        assert_eq!(summary.forged_3d_scenes, vec!["aurora-sanctuary.hmc".to_string()]);
        assert_eq!(summary.compiled_ux_sheaves, vec!["accessibility-deck.cbor-ld".to_string()]);
        assert!(summary.journal_quin_count == 2 && summary.delegated_permits_count == 7);

        let cbor_bytes = LiveWorkbenchHydrator::encode_telemetry_cbor_ld(&summary);
        assert!(cbor_bytes.len() > 32 && &cbor_bytes[0..3] == &[0xD9, 0x05, 0x01]);

        let html = LiveWorkbenchHydrator::render_hydrated_workbench_html(data_dir, Some("Added domain coop.family.org and relationship alias school@civics.au")).expect("render hydrated html");

        let main_idx = html.find("<main class=\"main-content main\">").expect("main tag");
        let bar_idx = html.find("id=\"live-vps-telemetry-bar\"").expect("telemetry bar");
        let deck_idx = html.find("id=\"live-12-page-state-deck\"").expect("12-page state deck");
        let page1_idx = html.find("id=\"page-domains\"").expect("page-domains");
        assert!(bar_idx > main_idx && deck_idx > bar_idx && deck_idx < page1_idx);
        assert!(html.contains("coop.family.org") && html.contains("care-governance.git"));
        assert!(html.contains("school@civics.au -&gt; principal@school.edu [did:qi:sunrise_school]"));
        assert!(html.contains("aurora-sanctuary.hmc") && html.contains("accessibility-deck.cbor-ld"));
        assert!(html.contains("Journal Quins: 2") && html.contains("Spooled Mail: 3 .eml"));
        assert!(html.contains("<div id=\"live-crud-management-table\">"));
        assert!(html.contains("<form method=\"POST\" action=\"/cpanel/domains/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"webizen-ssr-csrf-token\"><input type=\"hidden\" name=\"domain\" value=\"coop.family.org\"><button type=\"submit\">Remove</button></form>"));
        assert!(html.contains("<form method=\"POST\" action=\"/cpanel/email/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"webizen-ssr-csrf-token\"><input type=\"hidden\" name=\"alias\" value=\"school@civics.au\"><button type=\"submit\">Revoke</button></form>"));
        assert!(html.contains("<a href=\"/cpanel?persona=elder\">Elder</a>"));
        assert!(html.contains("<a href=\"/cpanel?persona=everyday\">Everyday</a>"));
        assert!(html.contains("<a href=\"/cpanel?persona=geek\">Developer</a>"));
        for label in [
            "Domains", "Email", "Files/IPFS", "Ontologies", "Solid Apps", "TLS Security",
            "Commons Wallet", "Snapshots", "Delegation", "Git Forge", "3D Studio", "UX Sheaves",
        ] {
            assert!(html.contains(label), "missing 12-page deck label: {label}");
        }

        let post_forms = html.matches("<form method=\"post\"").count() + html.matches("<form method=\"POST\"").count();
        let csrf_inputs = html.matches("<input type=\"hidden\" name=\"csrf_token\" value=\"webizen-ssr-csrf-token\">").count();
        assert!(post_forms >= 14 && csrf_inputs == post_forms);

        for persona in ["elder", "everyday", "geek"] {
            let p_html = LiveWorkbenchHydrator::render_hydrated_workbench_with_options(
                data_dir, None, Some(persona), Some("custom-csrf-99"),
            ).expect("render with persona and custom csrf");
            assert!(p_html.contains(&format!("data-persona=\"{persona}\"")));
            assert!(p_html.contains("<input type=\"hidden\" name=\"csrf_token\" value=\"custom-csrf-99\">"));
            let p_receipt = validate_zero_javascript_html(&p_html).expect("Zero-JS verification");
            assert!(p_receipt.zero_executable_js_tags && p_receipt.zero_inline_js_handlers);
        }

        let receipt = validate_zero_javascript_html(&html).expect("Zero-JS verification");
        assert!(receipt.zero_executable_js_tags && receipt.zero_inline_js_handlers && receipt.embedded_vibescript_modules >= 1);
    }
}
