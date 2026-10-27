//! WP-18 (D18.2 & D18.3): Guided 4-Step First-Boot Retail Setup Wizard (`/setup`, `/setup/complete`)
//! and Zero-JS Steward Authentication Login/Logout Workflow (`/login`, `/cpanel/auth/login`, `/cpanel/auth/logout`).
//!
//! Strictly adheres to the Human-Centric & International Human-Rights Nomenclature Rule and
//! enforces 100% Zero-JavaScript (`script-src 'none'`) HTML5/CSS3 rendering.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use webizen_host_core::{
    pack_context, pack_metadata, pack_predicate, q_hash, sha256,
    validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass,
    OP_OBLIGATE,
};
use webizen_host_dns::WebizenIdTlsCertificateBundle;
use webizen_host_ingest::append_quin_to_journal;
use webizen_host_stewardship::FamilyHouseholdStewardship;

use crate::auth_and_session::{current_unix_epoch_secs, StewardSessionGuard};
use crate::smtp_mail::synthesize_mail_dns_records;
use crate::vps_deployment::{write_linux_vps_deployment_bundle, HostPersistentState};

/// Marker file created in `<data_dir>/setup_completed.marker` once the 4-step retail setup finishes.
pub const SETUP_COMPLETED_MARKER_FILE: &str = "setup_completed.marker";

/// Guided 4-Step First-Boot Retail Setup Wizard and Zero-JS Login/Logout Coordinator.
pub struct RetailSetupWizard;

impl RetailSetupWizard {
    #[inline]
    pub fn is_first_boot_unconfigured(data_dir: &Path) -> bool {
        is_first_boot_unconfigured(data_dir)
    }

    #[inline]
    pub fn render_setup_wizard_html(state: &HostPersistentState, public_ipv4: &str) -> String {
        render_setup_wizard_html(state, public_ipv4)
    }

    #[inline]
    pub fn complete_retail_setup(
        data_dir: &Path,
        journal_path: &Path,
        form: &BTreeMap<String, String>,
    ) -> io::Result<(HostPersistentState, String, String, NQuin)> {
        complete_retail_setup(data_dir, journal_path, form)
    }

    #[inline]
    pub fn render_login_page_html(steward_did: &str, error_msg: Option<&str>) -> String {
        render_login_page_html(steward_did, error_msg)
    }

    #[inline]
    pub const fn build_logout_clear_cookie() -> &'static str {
        build_logout_clear_cookie()
    }
}

#[inline]
fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Returns `true` when `<data_dir>/setup_completed.marker` does not exist.
#[inline]
pub fn is_first_boot_unconfigured(data_dir: &Path) -> bool {
    !data_dir.join(SETUP_COMPLETED_MARKER_FILE).exists()
}

/// Render a 100% Zero-JS (`script-src 'none'`, zero executable `<script>` tags, zero `on*=` attributes)
/// HTML5/CSS3 page for `GET /setup` containing the 4-Step First-Boot Retail Setup Wizard:
/// - **Step 1**: Primary Domain & Public IPv4/IPv6 Configuration
/// - **Step 2**: Steward `did:qi:` & Passphrase (`PBKDF2-HMAC-SHA256`) + Ed25519 TLS/DKIM Key Provisioning
/// - **Step 3**: Copy-Paste DNS Glue Records, `MX 10 mail.<domain>`, `SPF` (`v=spf1 mx -all`), `DKIM` (`default._domainkey`), and `DMARC` (`_dmarc`) Checklist
/// - **Step 4**: Sanctuary Keep 2-of-3 $\text{GF}(2^8)$ Shamir Share Ceremony & `<form method="POST" action="/setup/complete">`
pub fn render_setup_wizard_html(state: &HostPersistentState, public_ipv4: &str) -> String {
    let domain = escape_html(state.primary_domain.trim());
    let steward_did = escape_html(state.steward_did_qi.trim());
    let ipv4 = escape_html(if public_ipv4.trim().is_empty() {
        "203.0.113.42"
    } else {
        public_ipv4.trim()
    });
    let dkim_seed = sha256(
        format!("webizen.dkim.seed.v1|{}|{}", state.primary_domain, state.steward_did_qi).as_bytes(),
    );
    let mail_dns = synthesize_mail_dns_records(&state.primary_domain, "default", &dkim_seed);
    let dkim_selector = escape_html(&mail_dns.dkim_selector_domain);
    let dkim_txt = escape_html(&mail_dns.dkim_txt);
    let dmarc_txt = escape_html(&mail_dns.dmarc_txt);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Webizen Host — 4-Step First-Boot Retail Setup Wizard</title>
  <style>
    :root {{ --bg: #070b14; --panel: #101726; --border: #22304a; --accent: #38bdf8; --emerald: #34d399; --text: #e2e8f0; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 2rem 1rem; background: radial-gradient(circle at top, #132038 0%, var(--bg) 70%); color: var(--text); font-family: system-ui, -apple-system, sans-serif; line-height: 1.5; }}
    .wizard-shell {{ max-width: 960px; margin: 0 auto; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 2rem; }}
    h1, h2, h3 {{ margin-top: 0; color: #f8fafc; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.65rem; border-radius: 999px; background: rgba(56, 189, 248, 0.14); border: 1px solid var(--accent); color: var(--accent); font-size: 0.8rem; font-weight: 600; }}
    .step-card {{ border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem; background: rgba(15, 23, 42, 0.65); }}
    label {{ display: block; font-weight: 600; margin-bottom: 0.35rem; }}
    input[type="text"], input[type="password"] {{ width: 100%; padding: 0.65rem 0.8rem; border-radius: 8px; border: 1px solid var(--border); background: #0b1120; color: var(--text); margin-bottom: 0.85rem; }}
    pre.dns-box {{ background: #050811; border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem; overflow-x: auto; color: var(--emerald); font-size: 0.85rem; }}
    .btn-primary {{ display: inline-block; padding: 0.8rem 1.5rem; border-radius: 8px; border: none; background: linear-gradient(135deg, #0284c7, #10b981); color: #ffffff; font-weight: 700; font-size: 1rem; cursor: pointer; }}
  </style>
  <script type="application/vibescript">
    module webizen_retail_setup_wizard;
    pure fn verify_setup_step(step_index: Int) budget(steps: 64) -> Bool {{
      return step_index >= 1;
    }}
  </script>
</head>
<body>
  <main class="wizard-shell">
    <span class="badge">Human-Centric Personal &amp; Family Stewardship • Zero-JS (script-src 'none')</span>
    <h1>Webizen Host — 4-Step First-Boot Retail Setup Wizard</h1>
    <p>Configure your turnkey Human-Centric VPS host with hard $0.00 overage protection, authoritative NQuin DNS, Relationship-Scoped Mail, and Sanctuary Keep recovery.</p>

    <form method="POST" action="/setup/complete">
      <section class="step-card" id="step-1-domain-network">
        <h2>Step 1: Primary Domain &amp; Public IPv4/IPv6 Configuration</h2>
        <label for="primary_domain">Primary Realm Domain</label>
        <input id="primary_domain" name="primary_domain" type="text" value="{domain}" required>
        <label for="public_ipv4">Public IPv4 Address (A / Glue Record Target)</label>
        <input id="public_ipv4" name="public_ipv4" type="text" value="{ipv4}" required>
        <label for="public_ipv6">Public IPv6 / QDNF Prefix (AAAA Target)</label>
        <input id="public_ipv6" name="public_ipv6" type="text" value="2001:db8:4242::1">
      </section>

      <section class="step-card" id="step-2-steward-keys">
        <h2>Step 2: Steward did:qi: &amp; Passphrase (PBKDF2-HMAC-SHA256) + Ed25519 TLS/DKIM Key Provisioning</h2>
        <label for="steward_did_qi">Natural Person Steward Identifier (did:qi:)</label>
        <input id="steward_did_qi" name="steward_did_qi" type="text" value="{steward_did}" required>
        <label for="steward_passphrase">Steward Master Passphrase (PBKDF2-HMAC-SHA256 310,000-Iteration Lane Derivation)</label>
        <input id="steward_passphrase" name="steward_passphrase" type="password" value="human-centric-sanctuary-2026" required>
        <p>Automatically provisions dual-authority <code>WebizenID-TLS</code> X.509v3 + RFC 8555 ACME certificates and RFC 8463 <code>ed25519-sha256</code> DKIM signing keys.</p>
      </section>

      <section class="step-card" id="step-3-dns-checklist">
        <h2>Step 3: Copy-Paste DNS Glue Records, MX, SPF, DKIM &amp; DMARC Checklist</h2>
        <p>Publish these authoritative DNS records at your registrar or delegate glue records to this host:</p>
        <pre class="dns-box">ns1.{domain}.                  300 IN A     {ipv4}
{domain}.                      300 IN A     {ipv4}
mail.{domain}.                 300 IN A     {ipv4}
{domain}.                      300 IN MX    10 mail.{domain}.
{domain}.                      300 IN TXT   "v=spf1 mx -all"
{dkim_selector}. 300 IN TXT   "{dkim_txt}"
_dmarc.{domain}.               300 IN TXT   "{dmarc_txt}"</pre>
      </section>

      <section class="step-card" id="step-4-sanctuary-shamir">
        <h2>Step 4: Sanctuary Keep 2-of-3 GF(2^8) Shamir Share Ceremony</h2>
        <p>Your Sanctuary Keep (*Freedom of Thought* vault) is sealed with client-side <code>ChaCha20-Poly1305</code> and split into a 2-of-3 <code>GF(2^8)</code> Shamir secret-sharing quorum across your personal and family guardianship devices.</p>
        <label>
          <input type="checkbox" name="confirm_shamir_ceremony" value="1" checked>
          I have recorded the 2-of-3 GF(2^8) Shamir recovery shares and verified the $0.00 hard monthly overage ceiling.
        </label>
        <div style="margin-top: 1rem;">
          <button type="submit" class="btn-primary">Complete Retail Host Setup &amp; Launch Workbench</button>
        </div>
      </section>
    </form>
  </main>
</body>
</html>
"#
    )
}

/// Complete the 4-Step First-Boot Retail Setup (`POST /setup/complete`), persisting `host_state.cbor-ld`
/// and `setup_completed.marker`, issuing a `StewardSessionGuard` cookie and CSRF token, and appending
/// a parity-valid `NQuin` receipt to `journal_path`.
pub fn complete_retail_setup(
    data_dir: &Path,
    journal_path: &Path,
    form: &BTreeMap<String, String>,
) -> io::Result<(HostPersistentState, String, String, NQuin)> {
    fs::create_dir_all(data_dir)?;
    let state_path = data_dir.join("host_state.cbor-ld");
    let mut state = if state_path.exists() {
        HostPersistentState::load_cbor_ld(&state_path)?
    } else {
        HostPersistentState::default()
    };

    if let Some(dom) = form
        .get("primary_domain")
        .or_else(|| form.get("domain"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        validate_human_centric_nomenclature(dom)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        state.primary_domain = dom.to_string();
        if !state.hosted_domains.iter().any(|d| d == dom) {
            state.hosted_domains.insert(0, dom.to_string());
        }
    }

    if let Some(did) = form
        .get("steward_did_qi")
        .or_else(|| form.get("steward_did"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        validate_human_centric_nomenclature(did)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        state.steward_did_qi = did.to_string();
    }

    state.validate_nomenclature()?;
    state.save_cbor_ld(&state_path)?;

    let provided_passphrase = form
        .get("passphrase")
        .or_else(|| form.get("steward_passphrase"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let passphrase = provided_passphrase.unwrap_or("human-centric-sanctuary-2026");
    let lane_key = FamilyHouseholdStewardship::derive_member_lane_key(
        passphrase,
        b"webizen_retail_setup_2026",
        &state.steward_did_qi,
    );
    WebizenIdTlsCertificateBundle::issue_and_persist(
        &state.primary_domain,
        &state.steward_did_qi,
        &lane_key,
        &data_dir.join("tls"),
    )?;
    write_linux_vps_deployment_bundle(data_dir, &state)?;

    let now_epoch = current_unix_epoch_secs();
    let marker_content = format!(
        "status=completed\ncompleted_epoch={now_epoch}\nprimary_domain={}\nsteward_did_qi={}\n",
        state.primary_domain, state.steward_did_qi
    );
    validate_human_centric_nomenclature(&marker_content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    fs::write(data_dir.join(SETUP_COMPLETED_MARKER_FILE), marker_content)?;

    let guard = StewardSessionGuard::load_or_create(data_dir, &state.steward_did_qi)?;
    if let Some(passphrase) = provided_passphrase {
        guard.set_passphrase(data_dir, passphrase)?;
    }
    let expiry_epoch = now_epoch.saturating_add(86_400);
    let cookie = guard.issue_session_cookie(expiry_epoch);
    let csrf = guard.issue_csrf_token(expiry_epoch);

    let steward_hash = q_hash(&state.steward_did_qi);
    let quin = NQuin::new(
        steward_hash,
        pack_predicate("https://ns.webcivics.net/host#completedRetailFirstBootSetup", OP_OBLIGATE, false),
        q_hash(&state.primary_domain) & 0x0FFF_FFFF_FFFF_FFFF,
        pack_context(steward_hash, SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, now_epoch as u32),
    );
    if let Some(parent) = journal_path.parent() {
        fs::create_dir_all(parent)?;
    }
    append_quin_to_journal(journal_path, &quin)?;

    Ok((state, cookie, csrf, quin))
}

/// Render a 100% Zero-JS HTML5 login form (`<form method="POST" action="/cpanel/auth/login">`)
/// for Steward session authentication.
pub fn render_login_page_html(steward_did: &str, error_msg: Option<&str>) -> String {
    let did_escaped = escape_html(if steward_did.trim().is_empty() {
        "did:qi:webcivics_steward"
    } else {
        steward_did.trim()
    });
    let error_banner = match error_msg {
        Some(msg) if !msg.trim().is_empty() => format!(
            r#"<div class="alert-error" role="alert">Authentication Notice: {}</div>"#,
            escape_html(msg.trim())
        ),
        _ => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Webizen Host — Steward Session Login</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #070b14; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }}
    .login-card {{ width: 100%; max-width: 460px; background: #101726; border: 1px solid #22304a; border-radius: 12px; padding: 2rem; }}
    .alert-error {{ background: rgba(239, 68, 68, 0.16); border: 1px solid #ef4444; color: #fca5a5; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; }}
    label {{ display: block; font-weight: 600; margin-bottom: 0.35rem; }}
    input {{ width: 100%; padding: 0.65rem 0.8rem; border-radius: 8px; border: 1px solid #22304a; background: #0b1120; color: #e2e8f0; margin-bottom: 1rem; box-sizing: border-box; }}
    button {{ width: 100%; padding: 0.75rem; border: none; border-radius: 8px; background: linear-gradient(135deg, #0284c7, #10b981); color: #ffffff; font-weight: 700; cursor: pointer; }}
  </style>
  <script type="application/vibescript">
    module webizen_steward_login;
    pure fn check_login_ready(active: Bool) budget(steps: 32) -> Bool {{
      return active;
    }}
  </script>
</head>
<body>
  <main class="login-card">
    <h1>Steward Session Login</h1>
    <p>Human-Centric Personal &amp; Family Host Control Plane (Zero-JS)</p>
    {error_banner}
    <form method="POST" action="/cpanel/auth/login">
      <label for="steward_did">Steward Identifier (did:qi:)</label>
      <input id="steward_did" name="steward_did" type="text" value="{did_escaped}" required>
      <label for="passphrase">Steward Passphrase</label>
      <input id="passphrase" name="passphrase" type="password" value="" placeholder="Enter Steward Passphrase" required>
      <button type="submit">Authenticate &amp; Issue DNI_SESSION Cookie</button>
    </form>
  </main>
</body>
</html>
"#
    )
}

/// Return the strict `Set-Cookie` header value that clears `DNI_SESSION` on `POST /cpanel/auth/logout`.
#[inline]
pub const fn build_logout_clear_cookie() -> &'static str {
    "DNI_SESSION=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_ssr_hydration::validate_zero_javascript_html;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_ingest::replay_quin_journal;

    #[test]
    fn retail_setup_wizard_html_completion_login_and_logout_verify_end_to_end() {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "webizen_wp18_retail_wizard_test_{}_{}",
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&data_dir);
        fs::create_dir_all(&data_dir).unwrap();
        let journal_path = data_dir.join("journal.q42j");

        assert!(is_first_boot_unconfigured(&data_dir));
        assert!(RetailSetupWizard::is_first_boot_unconfigured(&data_dir));

        let default_state = HostPersistentState::default();
        let wizard_html = render_setup_wizard_html(&default_state, "203.0.113.88");
        let audit = validate_zero_javascript_html(&wizard_html).unwrap();
        assert!(audit.zero_executable_js_tags && audit.zero_inline_js_handlers);
        assert!(wizard_html.contains("Step 1: Primary Domain"));
        assert!(wizard_html.contains("Step 2: Steward did:qi:"));
        assert!(wizard_html.contains("Step 3: Copy-Paste DNS Glue Records"));
        assert!(wizard_html.contains("MX    10 mail.ns.webcivics.net."));
        assert!(wizard_html.contains("v=spf1 mx -all"));
        assert!(wizard_html.contains("default._domainkey.ns.webcivics.net."));
        assert!(wizard_html.contains("_dmarc.ns.webcivics.net."));
        assert!(wizard_html.contains("Step 4: Sanctuary Keep 2-of-3 GF(2^8) Shamir Share Ceremony"));
        assert!(wizard_html.contains(r#"<form method="POST" action="/setup/complete">"#));

        let mut form = BTreeMap::new();
        form.insert("primary_domain".to_string(), "family.civics.au".to_string());
        form.insert("steward_did_qi".to_string(), "did:qi:alice_household".to_string());
        form.insert("passphrase".to_string(), "HumanRightsSteward2026!".to_string());

        let (updated_state, cookie, csrf, quin) =
            complete_retail_setup(&data_dir, &journal_path, &form).unwrap();
        assert!(!is_first_boot_unconfigured(&data_dir));
        assert!(data_dir.join(SETUP_COMPLETED_MARKER_FILE).exists());
        assert!(data_dir.join("tls").join("steward_auth.verifier").exists());
        assert_eq!(updated_state.primary_domain, "family.civics.au");
        assert_eq!(updated_state.steward_did_qi, "did:qi:alice_household");
        assert!(quin.verify_parity());

        let reloaded =
            HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld")).unwrap();
        assert_eq!(reloaded, updated_state);

        let guard =
            StewardSessionGuard::load_or_create(&data_dir, "did:qi:alice_household").unwrap();
        assert!(guard.verify_passphrase(&data_dir, "HumanRightsSteward2026!"));
        assert!(!guard.verify_passphrase(&data_dir, "wrong-passphrase"));
        assert_eq!(
            guard.verify_session_cookie(&cookie, current_unix_epoch_secs()).unwrap(),
            "did:qi:alice_household"
        );
        assert!(!csrf.is_empty());

        let journal_quins = replay_quin_journal(&journal_path).unwrap();
        assert_eq!(journal_quins, vec![quin]);

        let login_html =
            render_login_page_html("did:qi:alice_household", Some("Session expired; please sign in"));
        let login_audit = validate_zero_javascript_html(&login_html).unwrap();
        assert!(login_audit.zero_executable_js_tags);
        assert!(login_html.contains(r#"<form method="POST" action="/cpanel/auth/login">"#));
        assert!(login_html.contains("Session expired; please sign in"));
        assert_eq!(
            build_logout_clear_cookie(),
            "DNI_SESSION=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        );

        let _ = fs::remove_dir_all(&data_dir);
    }
}
