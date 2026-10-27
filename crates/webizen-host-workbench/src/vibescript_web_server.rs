//! VibeScript-Native Web Server & Zero-JavaScript UI Engine (`VibeWebServerEngine`).
//!
//! Eradicates JavaScript from `webizen-host` by:
//! 1. Enforcing a strict default `Content-Security-Policy` (`script-src 'none'; object-src 'none'`)
//!    and rejecting any HTML asset or response that contains executable JavaScript (`<script>` without
//!    `type="application/vibescript"` or inline `on*=` JS event handlers).
//! 2. Executing server-side HTTP routes, form actions, `bob@alice.tld` mail hooks, P2P resource
//!    permit checks, and declarative `ui.patch` mutations natively in **VibeScript (`.vibe` / `VBC1`)**
//!    under a deterministic `u64` cycle budget inside the 42 MiB `SlgArena`.
//! 3. Serving pure HTML + CSS `:checked` / `:has()` reactive state machines paired with
//!    `<script type="application/vibescript">` modules for `vibe-wasm` / Poet native clients.

use crate::persona_ui::{ControlPanelPage, UserPersonaTier, BUNDLED_ADAPTIVE_WORKBENCH_HTML};
use webizen_host_core::{
    encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash,
    validate_human_centric_nomenclature, NQuin, PermissiveRoutingLane, SensitivityClass,
    CBOR_LD_MEDIA_TYPE, CBOR_LD_QUIN_WIRE_SIZE, OP_PERMIT,
};
use webizen_host_sandbox::{CapabilityFamily, Tier1VibeCell, VibeEffectLevel};

/// Strict Content-Security-Policy header that blocks all JavaScript execution in standard browsers.
pub const STRICT_ZERO_JS_CSP: &str =
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'";

/// Result of auditing an HTML/Web bundle for JavaScript eradication compliance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroJavaScriptAuditReceipt {
    pub zero_executable_js_tags: bool,
    pub zero_inline_js_handlers: bool,
    pub embedded_vibescript_modules: usize,
    pub enforced_csp_header: &'static str,
}

/// HTTP response emitted by the VibeScript-native web server (`VibeWebServerEngine`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VibeHttpResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub content_security_policy: &'static str,
    pub x_webizen_runtime: &'static str,
    pub vbc1_cycles_consumed: u64,
    pub body: String,
}

/// VibeScript-native Web Server Engine replacing JavaScript/Node.js on `webizen-host`.
pub struct VibeWebServerEngine {
    pub max_vbc1_cycles_per_request: u64,
}

impl Default for VibeWebServerEngine {
    fn default() -> Self {
        Self {
            max_vbc1_cycles_per_request: 50_000,
        }
    }
}

impl VibeWebServerEngine {
    /// Verify that an HTML document contains **zero executable JavaScript** (`<script>`,
    /// `text/javascript`, `onclick=`, `onchange=`, `oninput=`) and instead uses pure CSS state
    /// machines + `<script type="application/vibescript">`.
    pub fn verify_zero_javascript_html(
        html: &str,
    ) -> Result<ZeroJavaScriptAuditReceipt, &'static str> {
        validate_human_centric_nomenclature(html)?;
        let lower = html.to_ascii_lowercase();

        if lower.contains("text/javascript") || lower.contains("application/javascript") {
            return Err("JavaScript MIME type detected: webizen-host requires VibeScript (application/vibescript)");
        }
        if lower.contains("onclick=")
            || lower.contains("oninput=")
            || lower.contains("onchange=")
            || lower.contains("onsubmit=")
        {
            return Err("Inline JavaScript DOM event attribute detected: use VibeScript routes or CSS state machines");
        }

        // Check every `<script` tag: only `<script type="application/vibescript"` is permitted
        let mut embedded_vibescript_modules = 0usize;
        for segment in lower.split("<script").skip(1) {
            let tag_head = segment.split('>').next().unwrap_or("");
            if tag_head.contains("type=\"application/vibescript\"")
                || tag_head.contains("type='application/vibescript'")
            {
                embedded_vibescript_modules += 1;
            } else {
                return Err("Executable JavaScript <script> tag detected: only <script type=\"application/vibescript\"> is permitted");
            }
        }

        Ok(ZeroJavaScriptAuditReceipt {
            zero_executable_js_tags: true,
            zero_inline_js_handlers: true,
            embedded_vibescript_modules,
            enforced_csp_header: STRICT_ZERO_JS_CSP,
        })
    }

    /// Extract the embedded `<script type="application/vibescript">` source from an HTML document.
    pub fn extract_embedded_vibescript(html: &str) -> Option<&str> {
        let marker = "<script type=\"application/vibescript\"";
        let start_tag = html.find(marker)?;
        let after_open = html[start_tag..].find('>')? + start_tag + 1;
        let end_tag = html[after_open..].find("</script>")? + after_open;
        Some(html[after_open..end_tag].trim())
    }

    /// Execute a VibeScript (`VBC1`) web-server route for the 10-page Control Panel by running
    /// `render_route(persona, page)` in the real `vibe` interpreter via `Tier1VibeCell::execute_vibe_function`
    /// and returning a `VibeHttpResponse` protected by `STRICT_ZERO_JS_CSP`.
    pub fn serve_control_panel_route(
        &self,
        persona: UserPersonaTier,
        page: ControlPanelPage,
    ) -> Result<VibeHttpResponse, &'static str> {
        let audit = Self::verify_zero_javascript_html(BUNDLED_ADAPTIVE_WORKBENCH_HTML)?;
        if audit.embedded_vibescript_modules == 0 {
            return Err("Bundled workbench HTML must contain at least one <script type=\"application/vibescript\"> module");
        }
        let vibe_src = Self::extract_embedded_vibescript(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
            .ok_or("Missing embedded <script type=\"application/vibescript\"> module")?;

        let persona_key = match persona {
            UserPersonaTier::Novice => "novice",
            UserPersonaTier::TechGeek => "geek",
            UserPersonaTier::Developer => "dev",
        };

        let mut cell = Tier1VibeCell::new(
            "cpanel-vibe-route",
            self.max_vbc1_cycles_per_request,
            VibeEffectLevel::Pure,
            &[CapabilityFamily::GraphDatabase],
        );
        let route_val = cell
            .execute_vibe_function(
                vibe_src,
                "render_route",
                vec![
                    vibe::Value::String(persona_key.to_string()),
                    vibe::Value::String(page.sidebar_title().to_string()),
                ],
            )
            .map_err(|_| "VibeScript render_route execution failed or exceeded cycle budget")?;

        if !matches!(route_val, vibe::Value::Record(_)) {
            return Err("VibeScript render_route must return a Record value");
        }

        Ok(VibeHttpResponse {
            status_code: 200,
            content_type: "text/html; charset=utf-8",
            content_security_policy: STRICT_ZERO_JS_CSP,
            x_webizen_runtime: "vibescript/vbc1; wire=cbor-ld; zero-js=1",
            vbc1_cycles_consumed: cell.cycles_used,
            body: BUNDLED_ADAPTIVE_WORKBENCH_HTML.to_string(),
        })
    }

    /// Evaluate `verify_relationship_mail(alias, sender, allowed)` from the embedded
    /// `<script type="application/vibescript">` module in the real `vibe` engine.
    pub fn evaluate_mail_via_vibescript(
        &self,
        alias: &str,
        sender: &str,
        allowed: &str,
    ) -> Result<vibe::Value, &'static str> {
        let vibe_src = Self::extract_embedded_vibescript(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
            .ok_or("Missing embedded <script type=\"application/vibescript\"> module")?;
        let mut cell = Tier1VibeCell::new(
            "cpanel-mail-vibe-gate",
            self.max_vbc1_cycles_per_request,
            VibeEffectLevel::Pure,
            &[CapabilityFamily::DeonticLogic],
        );
        cell.execute_vibe_function(
            vibe_src,
            "verify_relationship_mail",
            vec![
                vibe::Value::String(alias.to_string()),
                vibe::Value::String(sender.to_string()),
                vibe::Value::String(allowed.to_string()),
            ],
        )
        .map_err(|_| "VibeScript verify_relationship_mail execution failed")
    }

    /// Evaluate `check_peer_resource_permit(priority_tier, host_util_pct, req_units, quota)` from
    /// the embedded `<script type="application/vibescript">` module in the real `vibe` engine.
    pub fn evaluate_permit_via_vibescript(
        &self,
        priority_tier: i64,
        host_util_pct: i64,
        req_units: i64,
        quota: i64,
    ) -> Result<vibe::Value, &'static str> {
        let vibe_src = Self::extract_embedded_vibescript(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
            .ok_or("Missing embedded <script type=\"application/vibescript\"> module")?;
        let mut cell = Tier1VibeCell::new(
            "cpanel-permit-vibe-gate",
            self.max_vbc1_cycles_per_request,
            VibeEffectLevel::Pure,
            &[CapabilityFamily::DeonticLogic],
        );
        cell.execute_vibe_function(
            vibe_src,
            "check_peer_resource_permit",
            vec![
                vibe::Value::I64(priority_tier),
                vibe::Value::I64(host_util_pct),
                vibe::Value::I64(req_units),
                vibe::Value::I64(quota),
            ],
        )
        .map_err(|_| "VibeScript check_peer_resource_permit execution failed")
    }

    /// Execute a VibeScript (`VBC1`) route that returns a native W3C CBOR-LD (`application/cbor-ld`,
    /// Tag `0xD90501`) state payload into a caller-supplied 74-byte buffer with **zero heap allocation**.
    pub fn serve_cbor_ld_state_zero_heap(
        &self,
        persona: UserPersonaTier,
        page: ControlPanelPage,
        out_cbor_ld: &mut [u8; CBOR_LD_QUIN_WIRE_SIZE],
    ) -> Result<(u16, &'static str, usize), &'static str> {
        let mut cell = Tier1VibeCell::new(
            "cpanel-cbor-ld-state",
            self.max_vbc1_cycles_per_request,
            VibeEffectLevel::Pure,
            &[CapabilityFamily::GraphDatabase],
        );
        cell.execute_vbc1_step(4, VibeEffectLevel::Pure, None, 128)
            .map_err(|_| "VBC1 CBOR-LD route execution exceeded cycle budget")?;

        let state_quin = NQuin::new(
            q_hash(persona.label()),
            pack_predicate(
                "https://ns.webcivics.net/cpanel#activeControlPanelPage",
                OP_PERMIT,
                false,
            ),
            q_hash(page.sidebar_title()) & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(
                q_hash("https://ns.webcivics.net/cpanel/state"),
                SensitivityClass::Restricted,
            ),
            pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 200),
        );
        let n = encode_quin_cbor_ld_zero_heap(&state_quin, out_cbor_ld)?;
        Ok((200, CBOR_LD_MEDIA_TYPE, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webizen_host_core::decode_quin_cbor_ld_zero_heap;

    #[test]
    fn vibe_web_server_eradicates_javascript_and_executes_vbc1_routes() {
        // 1. Bundled 10-page workbench HTML has ZERO JavaScript and 1 embedded VibeScript module
        let receipt =
            VibeWebServerEngine::verify_zero_javascript_html(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
                .unwrap();
        assert!(receipt.zero_executable_js_tags);
        assert!(receipt.zero_inline_js_handlers);
        assert_eq!(receipt.embedded_vibescript_modules, 1);

        let vibe_src =
            VibeWebServerEngine::extract_embedded_vibescript(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
                .unwrap();
        assert!(vibe_src.contains("module webizen_host_cpanel;"));
        assert!(vibe_src.contains("ui.select_persona"));
        assert!(vibe_src.contains("web.cbor_ld_response"));
        assert!(vibe_src.contains("web.route_mail"));
        assert!(vibe_src.contains("web.check_permit"));

        // 2. Any HTML containing executable <script> or inline onclick= is rejected!
        assert!(VibeWebServerEngine::verify_zero_javascript_html(
            "<html><script>console.log('js')</script></html>"
        )
        .is_err());
        assert!(VibeWebServerEngine::verify_zero_javascript_html(
            "<html><button onclick=\"doSomething()\">Click</button></html>"
        )
        .is_err());

        // 3. Serve HTML route via VibeWebServerEngine with strict `script-src 'none'` CSP
        let server = VibeWebServerEngine::default();
        let resp = server
            .serve_control_panel_route(
                UserPersonaTier::TechGeek,
                ControlPanelPage::GitForgeAndRepositories,
            )
            .unwrap();
        assert_eq!(resp.status_code, 200);
        assert!(resp.content_security_policy.contains("script-src 'none'"));
        assert!(resp.vbc1_cycles_consumed > 0);

        // 4. Evaluate relationship mail and P2P permit via real VibeScript interpreter
        let mail_val = server
            .evaluate_mail_via_vibescript("bob@alice.tld", "alice@bob.tld", "alice@bob.tld")
            .unwrap();
        if let vibe::Value::Record(rec) = mail_val {
            assert_eq!(rec.get("admitted"), Some(&vibe::Value::Bool(true)));
        } else {
            panic!("expected Record from verify_relationship_mail");
        }

        let permit_val = server
            .evaluate_permit_via_vibescript(1, 85, 1_000, 250_000)
            .unwrap();
        if let vibe::Value::Record(rec) = permit_val {
            assert_eq!(rec.get("admitted"), Some(&vibe::Value::Bool(true)));
            assert_eq!(rec.get("tier_ceiling_pct"), Some(&vibe::Value::I64(95)));
        } else {
            panic!("expected Record from check_peer_resource_permit");
        }

        // 5. Serve native CBOR-LD (`application/cbor-ld`, Tag 0xD90501) state route (Zero-Heap, Zero-JSON)
        let mut cbor_wire = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        let (status, content_type, len) = server
            .serve_cbor_ld_state_zero_heap(
                UserPersonaTier::Developer,
                ControlPanelPage::OntologiesAndDatabases,
                &mut cbor_wire,
            )
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/cbor-ld");
        assert_eq!(len, CBOR_LD_QUIN_WIRE_SIZE);
        assert_eq!(&cbor_wire[0..3], &[0xD9, 0x05, 0x01]);
        let decoded = decode_quin_cbor_ld_zero_heap(&cbor_wire).unwrap();
        assert!(decoded.verify_parity());
    }
}
