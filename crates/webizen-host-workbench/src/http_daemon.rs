//! Live TCP/HTTP/1.1 Daemon (`WebizenHostDaemon`) & 48-Point Retail VPS Readiness Verifier (WP-09..WP-31).

use std::{fs::{self, OpenOptions}, io::{self, BufRead, BufReader, Read, Write}, net::{SocketAddr, TcpListener, TcpStream, UdpSocket}, path::{Path, PathBuf}, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, thread::{self, JoinHandle}, time::{Duration, SystemTime, UNIX_EPOCH}};
use crate::auth_and_session::{parse_urlencoded_form, IpRateLimiterRing, StewardSessionGuard};
use crate::git_forge_and_qcdn_routes::{handle_git_forge_route, handle_qcdn_extended_route};
use crate::git_smart_http::{build_info_refs_advertisement, handle_git_receive_pack_push, render_git_repo_log_html, OnDiskGitRepoStore};
use crate::http_routes_ext::{encode_quin_receipt, handle_acme_http01_challenge, handle_commons_ledger_cbor_ld, handle_commons_settle, handle_cpanel_studio_forge_3d, handle_cpanel_ux_compile_sheaf, handle_cpanel_wallet_swap, handle_doh_dns_query, handle_healthz_and_metrics, handle_qcdn_route, handle_sanctuary_or_peer_route, handle_steward_auth_login, handle_studio_viewport_svg};
use crate::jmap_maildir_api::{handle_jmap_mail_route, JmapMaildirEngine};
use crate::live_ssr_hydration::LiveWorkbenchHydrator;
use crate::persona_ui::{ControlPanelPage, UserPersonaTier};
use crate::smtp_mail::SmtpWireServer;
use crate::solid_ipfs_webseed::{handle_solid_ldp_get, handle_solid_ldp_put, publish_file_to_ipfs_and_webseed, serve_ipfs_block, serve_webtorrent_webseed_range};
use crate::stewardship_and_qapp_routes::{handle_qapp_route, handle_stewardship_route, install_qapp_isolate, issue_stewardship_delegation};
use crate::vibe_3d_studio::{Vibe3dMeshPreset, Vibe3dPbrShader};
use crate::vibescript_web_server::{VibeWebServerEngine, STRICT_ZERO_JS_CSP};
use crate::vps_backup_and_git_pack::{handle_git_upload_pack_fetch, run_vps_doctor_diagnostics, serve_git_repo_bundle};
use crate::vps_deployment::{write_linux_vps_deployment_bundle, CustomDnsRecord, HostPersistentState};
use crate::RelationshipScopedMailAlias;
use webizen_host_core::{encode_quin_cbor_ld_zero_heap, pack_context, pack_metadata, pack_predicate, q_hash, NQuin, PermissiveRoutingLane, SensitivityClass, CBOR_LD_MEDIA_TYPE, CBOR_LD_QUIN_WIRE_SIZE, OP_OBLIGATE, OP_PERMIT};
use webizen_host_dns::{build_rfc1035_query_packet, serve_udp_dns_requests, AcmeChallengeManager, DnsQueryContext, DnsRcode, DnsRrType, NQuinDnsZoneRing, WebizenIdTlsCertificateBundle};
use webizen_host_ingest::{append_quin_to_journal, read_file_byte_range, CompiledQ42Volume, SourceEnvelope, StreamingOntologyCompiler};
use webizen_host_namespace::{format_quins_to_rdf, query_superblock_term_zero_heap, NegotiatedFormat, RangeSparqlEngine};
use webizen_host_sandbox::Tier3SolidAndEbpfSandbox;

pub const DEFAULT_ACME_BOOTSTRAP_TOKEN: &str = "bootstrap-acme-token-2026";

#[derive(Clone)]
pub struct WebizenHostDaemon {
    pub data_dir: PathBuf, pub q42_path: PathBuf, pub journal_path: PathBuf, pub state_path: PathBuf,
    pub host_state_path: PathBuf, pub git_root: PathBuf, pub tls_dir: PathBuf,
    pub acme_manager: Arc<Mutex<AcmeChallengeManager>>, pub vibe_server: Arc<VibeWebServerEngine>,
    pub solid_sandbox: Arc<Mutex<Tier3SolidAndEbpfSandbox>>, pub session_guard: StewardSessionGuard,
    pub rate_limiter: Arc<Mutex<IpRateLimiterRing>>,
}

impl WebizenHostDaemon {
    pub fn new(data_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&data_dir)?;
        let (q42_path, journal_path, state_path, git_root, tls_dir) = (data_dir.join("core.q42"), data_dir.join("journal.q42j"), data_dir.join("host_state.cbor-ld"), data_dir.join("git"), data_dir.join("tls"));
        if !q42_path.exists() {
            let env = SourceEnvelope { repo_url: "https://github.com/WebCivics/ns".to_string(), commit_hash: "20261027cpanel".to_string(), spdx_license: "SocialPermissiveCommons".to_string(), production_cost_cents: 25_000, roi_cap_percent: 150 };
            let ttl = "<https://ns.webcivics.net/agent#NaturalAgent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> .\n<https://ns.webcivics.net/agent#NaturalAgent> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> .\n<https://ns.webcivics.net/care#Guardianship> <https://ns.webcivics.net/hr#supports> <https://ns.webcivics.net/agent#NaturalAgent> .";
            StreamingOntologyCompiler::default().compile_chunks(&env, &[ttl], &[]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?.write_to_disk(&q42_path)?;
        }
        let _ = OpenOptions::new().create(true).append(true).open(&journal_path)?;
        let host_state = if state_path.exists() { HostPersistentState::load_cbor_ld(&state_path)? } else { let st = HostPersistentState::default(); st.save_cbor_ld(&state_path)?; st };
        write_linux_vps_deployment_bundle(&data_dir, &host_state)?;
        WebizenIdTlsCertificateBundle::issue_and_persist(&host_state.primary_domain, &host_state.steward_did_qi, &[0x42u8; 32], &tls_dir)?;
        OnDiskGitRepoStore::init_bare_repo(&git_root, "webcivics-ns.git")?;
        let session_guard = StewardSessionGuard::load_or_create(&data_dir, &host_state.steward_did_qi)?;
        let mut acme = AcmeChallengeManager::new(br#"{"crv":"Ed25519","kty":"OKP","x":"webizen-host-acme-account-key-2026"}"#);
        acme.register_challenge(DEFAULT_ACME_BOOTSTRAP_TOKEN);
        let solid_sandbox = Tier3SolidAndEbpfSandbox { pod_root_uri: format!("https://{}/solid/", host_state.primary_domain), owner_did_hash: q_hash(&host_state.steward_did_qi), ebpf_egress_ceiling_bytes: host_state.hard_monthly_egress_cap_bytes, ebpf_egress_used_bytes: 0 };
        Ok(Self { data_dir, q42_path, journal_path, host_state_path: state_path.clone(), state_path, git_root, tls_dir, acme_manager: Arc::new(Mutex::new(acme)), vibe_server: Arc::new(VibeWebServerEngine::default()), solid_sandbox: Arc::new(Mutex::new(solid_sandbox)), session_guard, rate_limiter: Arc::new(Mutex::new(IpRateLimiterRing::new(1024))) })
    }

    pub fn register_acme_challenge(&self, token: &str) -> (String, String) { self.acme_manager.lock().expect("lock acme_manager").register_challenge(token) }

    pub fn handle_http_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        let _ = (stream.set_read_timeout(Some(Duration::from_secs(5))), stream.set_write_timeout(Some(Duration::from_secs(5))));
        let Some((method, path, headers, body)) = Self::read_http_request(&mut stream)? else { return Ok(()); };
        let csp = &[("Content-Security-Policy", STRICT_ZERO_JS_CSP)];
        let peer_ip_str = stream.peer_addr().ok().map(|a| a.ip().to_string()).unwrap_or_else(|| "127.0.0.1".to_string());
        let window = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 60).unwrap_or(1);
        if self.rate_limiter.lock().expect("lock rate_limiter").check_and_record_zero_heap(&peer_ip_str, window).is_err() {
            return Self::write_http_response(&mut stream, 429, "Too Many Requests", "text/plain; charset=utf-8", csp, b"Rate limit exceeded");
        }
        if headers.iter().any(|(k, v)| k == "x-webizen-require-auth" && v == "1") {
            let cookie = headers.iter().find_map(|(k, v)| (k == "cookie").then_some(v.as_str())).unwrap_or("");
            let csrf = headers.iter().find_map(|(k, v)| (k == "x-webizen-csrf-token").then_some(v.as_str())).unwrap_or("");
            let exp = cookie.split(';').map(str::trim).find_map(|s| s.strip_prefix("DNI_SESSION=")).and_then(|v| v.split('|').next()).and_then(|e| e.parse::<u64>().ok()).unwrap_or(0);
            let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(1_700_000_000).min(1_999_999_999);
            let form = parse_urlencoded_form(std::str::from_utf8(&body).unwrap_or(""));
            if self.session_guard.verify_session_cookie(cookie, now_secs).is_err() || !self.session_guard.verify_request_csrf(csrf, form.get("csrf_token").map(String::as_str), exp) {
                return Self::write_http_response(&mut stream, 401, "Unauthorized", "text/plain; charset=utf-8", csp, b"Unauthorized: valid DNI_SESSION cookie and CSRF token required");
            }
        }
        if method == "GET" && (path == "/health" || path == "/healthz" || path == "/metrics") {
            let (st, ct, payload) = handle_healthz_and_metrics(if path == "/health" { "/healthz" } else { path.as_str() }, &self.q42_path, &self.journal_path)?;
            return Self::write_http_response(&mut stream, st, "OK", ct, csp, &payload);
        }
        if path.starts_with("/dns-query") && (method == "POST" || method == "GET") {
            let (st, ct, payload) = handle_doh_dns_query(&body, &self.data_dir, "ns.webcivics.net");
            return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Bad Request" }, ct, csp, &payload);
        }
        if let Some((st, ct, p)) = handle_qcdn_route(&self.data_dir, &self.journal_path, &method, &path, &body)? { return Self::write_http_response(&mut stream, st, "OK", ct, csp, &p); }
        if let Some((st, ct, p)) = handle_qcdn_extended_route(&self.data_dir, &self.q42_path, &self.journal_path, &method, &path, &body)? {
            let hdrs: &[(&str, &str)] = if st == 307 { &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("Location", "https://peer1.civics.au/torrent/webseed/core.q42")] } else { csp };
            return Self::write_http_response(&mut stream, st, if st == 307 { "Temporary Redirect" } else { "OK" }, ct, hdrs, &p);
        }
        if let Some((st, ct, p)) = handle_stewardship_route(&self.data_dir, &self.journal_path, &method, &path, &body)? { return Self::write_http_response(&mut stream, st, "OK", ct, csp, &p); }
        if let Some((st, ct, p)) = handle_qapp_route(&self.data_dir, &self.journal_path, &method, &path, &body)? { return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Forbidden" }, ct, csp, &p); }
        if let Some((st, ct, p)) = handle_git_forge_route(&self.data_dir, &self.journal_path, &method, &path, &body)? { return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Bad Request" }, ct, csp, &p); }
        if method == "GET" && path == "/commons/ledger.cbor-ld" { let (st, ct, p) = handle_commons_ledger_cbor_ld(&self.data_dir, &self.journal_path)?; return Self::write_http_response(&mut stream, st, "OK", ct, csp, &p); }
        if method == "PUT" {
            if let Some(rest) = path.strip_prefix("/solid/") {
                let (pod, rel) = rest.split_once('/').unwrap_or((rest, "card.ttl"));
                let mut sb = self.solid_sandbox.lock().expect("lock solid_sandbox");
                return match handle_solid_ldp_put(&self.data_dir, &self.journal_path, &mut sb, pod, rel, std::str::from_utf8(&body).unwrap_or("")) {
                    Ok(r) => Self::write_http_response(&mut stream, 200, "OK", CBOR_LD_MEDIA_TYPE, csp, &r.cbor_ld_bytes),
                    Err(e) => Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", csp, e.as_bytes()),
                };
            }
        }
        if method == "DELETE" {
            if let Some(rest) = path.strip_prefix("/solid/") {
                let (pod, rel) = rest.split_once('/').unwrap_or((rest, "card.ttl"));
                let actor = headers.iter().find_map(|(k, v)| (k == "x-webizen-actor-did" || k == "x-actor-did").then_some(v.clone())).unwrap_or_else(|| format!("did:qi:{pod}"));
                return match crate::solid_ipfs_webseed::handle_solid_ldp_delete(&self.data_dir, &self.journal_path, pod, rel, &actor) {
                    Ok(q) => Self::write_http_response(&mut stream, 200, "OK", "application/ld+cbor", &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("X-Content-Type-Alias", CBOR_LD_MEDIA_TYPE)], &encode_quin_receipt(&q)),
                    Err(e) => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", csp, e.as_bytes()),
                };
            }
        }
        let resolved_mail_path = if method == "GET" && path == "/mail/view/latest" {
            let Some(last) = JmapMaildirEngine::list_messages(&self.data_dir.join("maildir"), None).ok().and_then(|mut m| m.pop()) else {
                return Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", csp, b"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Webmail Reader</title></head><body><article class=\"webmail-reader-card\"><h1>Webmail Reader</h1><p>No spooled messages yet.</p></article></body></html>");
            };
            format!("/mail/view/{}", last.message_id)
        } else { path.clone() };
        if let Some((st, ct, payload)) = handle_jmap_mail_route(&self.data_dir, &self.journal_path, &method, &resolved_mail_path, &body)? {
            return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Bad Request" }, ct, csp, &payload);
        }
        if method == "GET" {
            if path == "/" || path == "/cpanel" || path.starts_with("/cpanel?") {
                let persona = path.strip_prefix("/cpanel?").and_then(|q| parse_urlencoded_form(q).get("persona").cloned());
                let csrf = self.session_guard.issue_csrf_token(2_000_000_000);
                return match LiveWorkbenchHydrator::render_hydrated_workbench_with_options(&self.data_dir, None, persona.as_deref(), Some(&csrf)) {
                    Ok(html) => Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("X-Webizen-Runtime", "VBC1-ZeroJS")], html.as_bytes()),
                    Err(e) => Self::write_http_response(&mut stream, 500, "Internal Server Error", "text/plain; charset=utf-8", csp, e.to_string().as_bytes()),
                };
            }
            if path == "/setup" { return Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", csp, crate::retail_setup_wizard::render_setup_wizard_html(&HostPersistentState::load_cbor_ld(&self.host_state_path).unwrap_or_default(), "203.0.113.42").as_bytes()); }
            if path == "/login" { return Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", csp, crate::retail_setup_wizard::render_login_page_html(&self.session_guard.steward_did_qi, None).as_bytes()); }
            if path == "/api/telemetry.cbor-ld" { return Self::write_http_response(&mut stream, 200, "OK", CBOR_LD_MEDIA_TYPE, csp, &LiveWorkbenchHydrator::encode_telemetry_cbor_ld(&LiveWorkbenchHydrator::collect_telemetry(&self.data_dir)?)); }
            if path == "/studio/viewport.svg" { let (st, ct, svg_bytes) = handle_studio_viewport_svg(); return Self::write_http_response(&mut stream, st, "OK", ct, csp, &svg_bytes); }
            if let Some(scene) = path.strip_prefix("/studio/").and_then(|s| s.strip_suffix(".glb")) { return Self::write_http_response(&mut stream, 200, "OK", "model/gltf-binary", csp, &crate::vibe_3d_gltf_export::export_mesh_to_glb(scene, Vibe3dMeshPreset::from_name(scene), Vibe3dPbrShader::BioluminescentPlasma)); }
            if let Some(scene) = path.strip_prefix("/studio/").and_then(|s| s.strip_suffix(".obj")) { return Self::write_http_response(&mut stream, 200, "OK", "model/obj; charset=utf-8", csp, crate::vibe_3d_gltf_export::export_mesh_to_wavefront_obj(scene, Vibe3dMeshPreset::from_name(scene), Vibe3dPbrShader::BioluminescentPlasma).as_bytes()); }
            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                if let Some(a) = self.acme_manager.lock().ok().and_then(|m| m.respond_http01(token).map(str::to_string)) { return Self::write_http_response(&mut stream, 200, "OK", "text/plain; charset=utf-8", csp, a.as_bytes()); }
                let (st, ct, out) = handle_acme_http01_challenge(token, "ns.webcivics.net", &self.session_guard.steward_did_qi);
                return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Not Found" }, ct, csp, &out);
            }
            if let Some(term) = path.strip_prefix("/ns/") { return self.serve_virtual_namespace_term(&mut stream, term, &headers); }
            if let Some(rest) = path.strip_prefix("/solid/") {
                let (pod, rel) = rest.split_once('/').unwrap_or((rest, "card.ttl"));
                let accept = headers.iter().find_map(|(k, v)| (k == "accept").then_some(v.as_str())).unwrap_or("*/*");
                return match handle_solid_ldp_get(&self.data_dir, pod, rel, accept) { Ok((ct, bytes)) => Self::write_http_response(&mut stream, 200, "OK", ct, csp, &bytes), Err(e) => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", csp, e.as_bytes()) };
            }
            if let Some(cid) = path.strip_prefix("/ipfs/") { return match serve_ipfs_block(&self.data_dir, cid) { Ok(b) => Self::write_http_response(&mut stream, 200, "OK", "application/octet-stream", csp, &b), Err(e) => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", csp, e.as_bytes()) }; }
            if let Some(file_name) = path.strip_prefix("/torrent/webseed/") {
                let (start, end) = Self::parse_range_header(&headers).unwrap_or((0, 63));
                return match serve_webtorrent_webseed_range(&self.data_dir, file_name, start, end) { Ok((st, cr, slice)) => Self::write_http_response(&mut stream, st, "Partial Content", "application/octet-stream", &[("Accept-Ranges", "bytes"), ("Content-Range", &cr)], &slice), Err(e) => Self::write_http_response(&mut stream, 416, "Range Not Satisfiable", "text/plain; charset=utf-8", &[], e.as_bytes()) };
            }
            if let Some(repo_name) = path.strip_prefix("/git/").and_then(|r| r.strip_suffix("/log")) { return match render_git_repo_log_html(&self.git_root.join(repo_name), repo_name) { Ok(html) => Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", csp, html.as_bytes()), Err(e) => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", csp, e.to_string().as_bytes()) }; }
            if let Some(repo_name) = path.strip_prefix("/git/").and_then(|r| r.strip_suffix("/bundle")) { return match serve_git_repo_bundle(&self.git_root.join(repo_name)) { Ok(b) => Self::write_http_response(&mut stream, 200, "OK", "application/x-git-bundle", csp, &b), Err(e) => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", &[], e.to_string().as_bytes()) }; }
            if let Some((repo_name, query_part)) = path.strip_prefix("/git/").and_then(|r| r.split_once("/info/refs")) { return match build_info_refs_advertisement(&self.git_root.join(repo_name), query_part.strip_prefix("?service=").unwrap_or("git-upload-pack")) { Ok((ct, pkt)) => Self::write_http_response(&mut stream, 200, "OK", &ct, &[("Cache-Control", "no-cache")], &pkt), Err(e) => Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", &[], e.to_string().as_bytes()) }; }
        }
        if method == "POST" {
            if path == "/setup/complete" {
                let (_st, cookie, csrf, quin) = crate::retail_setup_wizard::complete_retail_setup(&self.data_dir, &self.journal_path, &parse_urlencoded_form(std::str::from_utf8(&body).unwrap_or("")))?;
                let auth_hdrs = &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("Set-Cookie", cookie.as_str()), ("X-Webizen-Csrf-Token", csrf.as_str())];
                if headers.iter().any(|(k, v)| k == "accept" && v.contains("text/html")) { return Self::write_http_response(&mut stream, 200, "OK", "text/html; charset=utf-8", auth_hdrs, LiveWorkbenchHydrator::render_hydrated_workbench_html(&self.data_dir, Some("Completed 4-step retail setup"))?.as_bytes()); }
                return Self::write_http_response(&mut stream, 200, "OK", CBOR_LD_MEDIA_TYPE, auth_hdrs, &encode_quin_receipt(&quin));
            }
            if path == "/logout" || path == "/cpanel/auth/logout" { return Self::write_http_response(&mut stream, 200, "OK", "text/plain; charset=utf-8", &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("Set-Cookie", "DNI_SESSION=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")], b"Signed out"); }
            if path == "/cpanel/auth/login" { let (st, ct, cookie, csrf, payload) = handle_steward_auth_login(&self.data_dir, &self.journal_path, &self.session_guard.steward_did_qi, &body)?; return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Unauthorized" }, ct, &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("Set-Cookie", &cookie), ("X-Webizen-Csrf-Token", &csrf)], &payload); }
            if path == "/peer/pair" || path.starts_with("/sanctuary/") { let (st, ct, payload) = handle_sanctuary_or_peer_route(&self.data_dir, &self.journal_path, &path, &body)?; return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Not Found" }, ct, csp, &payload); }
            if path == "/commons/settle" {
                let (st, ct, payload) = handle_commons_settle(&self.journal_path, &body)?;
                let settle_hdrs: &[(&str, &str)] = if st == 402 { &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("WWW-Authenticate", "L402 mac=\"webizen-commons-pool\", invoice=\"lnbc2500n1webizen\"")] } else { csp };
                return Self::write_http_response(&mut stream, st, if st == 200 { "OK" } else { "Payment Required" }, ct, settle_hdrs, &payload);
            }
            if path.starts_with("/cpanel/") { return self.handle_cpanel_post(&mut stream, &path, &headers, &body); }
            if let Some(repo_name) = path.strip_prefix("/git/").and_then(|r| r.strip_suffix("/git-upload-pack")) { return match handle_git_upload_pack_fetch(&self.git_root.join(repo_name), &body) { Ok((ct, pkt)) => Self::write_http_response(&mut stream, 200, "OK", &ct, &[("Cache-Control", "no-cache")], &pkt), Err(e) => Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", &[], e.to_string().as_bytes()) }; }
            if let Some(repo_name) = path.strip_prefix("/git/").and_then(|r| r.strip_suffix("/git-receive-pack")) { return match handle_git_receive_pack_push(&self.git_root.join(repo_name), &self.journal_path, "did:qi:webcivics_steward", std::str::from_utf8(&body).unwrap_or(""), 2, 1) { Ok(r) => Self::write_http_response(&mut stream, 200, "OK", "application/x-git-receive-pack-result", &[("Cache-Control", "no-cache")], &r.smart_http_response), Err(msg) => Self::write_http_response(&mut stream, 403, "Forbidden", "text/plain; charset=utf-8", &[], msg.as_bytes()) }; }
        }
        match (method.as_str(), path.as_str()) {
            ("GET", "/api/state.cbor-ld") => {
                let mut wire = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
                match self.vibe_server.serve_cbor_ld_state_zero_heap(UserPersonaTier::Developer, ControlPanelPage::OntologiesAndDatabases, &mut wire) {
                    Ok((st, ct, len)) => Self::write_http_response(&mut stream, st, "OK", ct, csp, &wire[..len]),
                    Err(m) => Self::write_http_response(&mut stream, 500, "Internal Server Error", "text/plain; charset=utf-8", &[], m.as_bytes()),
                }
            }
            ("GET", "/volumes/core.q42") => if let Some((start, end)) = Self::parse_range_header(&headers) {
                match read_file_byte_range(&self.q42_path, start, end) {
                    Ok((total, slice)) => Self::write_http_response(&mut stream, 206, "Partial Content", "application/q42", &[("Accept-Ranges", "bytes"), ("Content-Range", &format!("bytes {start}-{end}/{total}"))], &slice),
                    Err(e) => Self::write_http_response(&mut stream, 416, "Range Not Satisfiable", "text/plain; charset=utf-8", &[("Accept-Ranges", "bytes")], e.to_string().as_bytes()),
                }
            } else { Self::write_http_response(&mut stream, 200, "OK", "application/q42", &[("Accept-Ranges", "bytes")], &fs::read(&self.q42_path)?) },
            ("POST", "/sparql") => match RangeSparqlEngine::execute_sparql_or_update_on_disk(&self.q42_path, &self.journal_path, std::str::from_utf8(&body).unwrap_or("")) {
                Ok(r) => Self::write_http_response(&mut stream, 200, "OK", r.content_type, csp, &r.cbor_ld_payload),
                Err(m) => Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", &[], m.as_bytes()),
            },
            ("POST", "/mail/evaluate") => {
                let parts: Vec<&str> = std::str::from_utf8(&body).unwrap_or("").trim().split('|').collect();
                if parts.len() < 3 { return Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", &[], b"Expected alias|sender|allowed"); }
                match self.vibe_server.evaluate_mail_via_vibescript(parts[0], parts[1], parts[2]) {
                    Ok(val) => {
                        let admitted = matches!(&val, vibe::Value::Record(r) if matches!(r.get("admitted"), Some(vibe::Value::Bool(true))));
                        let q = NQuin::new(q_hash(parts[0]), pack_predicate("https://ns.webcivics.net/mail#evaluatedInboundEnvelope", if admitted { OP_PERMIT } else { OP_OBLIGATE }, false), q_hash(parts[1]) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(parts[2]), SensitivityClass::Restricted), pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, u32::from(admitted)));
                        append_quin_to_journal(&self.journal_path, &q)?;
                        Self::write_http_response(&mut stream, 200, "OK", CBOR_LD_MEDIA_TYPE, csp, &vibe::encode_value_cbor_ld(&val, "https://ns.webcivics.net/mail"))
                    }
                    Err(m) => Self::write_http_response(&mut stream, 500, "Internal Server Error", "text/plain; charset=utf-8", &[], m.as_bytes()),
                }
            }
            ("POST", "/permit/evaluate") => {
                let nums: Vec<i64> = std::str::from_utf8(&body).unwrap_or("").trim().split('|').filter_map(|s| s.trim().parse().ok()).collect();
                if nums.len() < 4 { return Self::write_http_response(&mut stream, 400, "Bad Request", "text/plain; charset=utf-8", &[], b"Expected tier|util_pct|req_units|quota"); }
                match self.vibe_server.evaluate_permit_via_vibescript(nums[0], nums[1], nums[2], nums[3]) {
                    Ok(val) => Self::write_http_response(&mut stream, 200, "OK", CBOR_LD_MEDIA_TYPE, csp, &vibe::encode_value_cbor_ld(&val, "https://ns.webcivics.net/permit")),
                    Err(m) => Self::write_http_response(&mut stream, 500, "Internal Server Error", "text/plain; charset=utf-8", &[], m.as_bytes()),
                }
            }
            _ => Self::write_http_response(&mut stream, 404, "Not Found", "text/plain; charset=utf-8", csp, b"Route not found"),
        }
    }

    fn handle_cpanel_post(&self, stream: &mut TcpStream, path: &str, headers: &[(String, String)], body: &[u8]) -> io::Result<()> {
        let (form, mut state, mut extra_cid, mut sparql_matches) = (parse_urlencoded_form(std::str::from_utf8(body).unwrap_or("")), HostPersistentState::load_cbor_ld(&self.host_state_path)?, String::new(), None);
        match path {
            "/cpanel/domains/add" => {
                let dom = form.get("domain").cloned().unwrap_or_else(|| "civic-coop.org".to_string());
                if !state.hosted_domains.contains(&dom) { state.hosted_domains.push(dom.clone()); }
                if let (Some(rr), Some(val)) = (form.get("rr_type"), form.get("value")) { state.custom_dns_records.push(CustomDnsRecord { name: dom, rr_type: rr.clone(), ttl: form.get("ttl").and_then(|t| t.parse().ok()).unwrap_or(300), value: val.clone() }); }
            }
            "/cpanel/domains/delete" => { let target = form.get("domain").map(String::as_str).unwrap_or("").trim(); state.hosted_domains.retain(|d| d != target); state.custom_dns_records.retain(|r| r.name != target); }
            "/cpanel/email/add" => {
                let (local, dom) = (form.get("local_part").cloned().unwrap_or_else(|| "bob".to_string()), form.get("domain").cloned().unwrap_or_else(|| state.primary_domain.clone()));
                state.mail_aliases.push((form.get("alias").cloned().unwrap_or_else(|| format!("{local}@{dom}")), form.get("counterparty_did").cloned().unwrap_or_else(|| format!("did:qi:{local}")), form.get("allowed_sender").cloned().unwrap_or_else(|| "alice@bob.tld".to_string())));
            }
            "/cpanel/email/delete" => { let target = form.get("alias").map(String::as_str).unwrap_or("").trim(); state.mail_aliases.retain(|alias| alias.0 != target); }
            "/cpanel/files/publish" => {
                let (fname, payload) = (form.get("file_name").cloned().unwrap_or_else(|| "dataset.q42".to_string()), form.get("content").or_else(|| form.get("payload")).cloned().unwrap_or_else(|| "PermissiveCommonsDataset".to_string()));
                extra_cid = publish_file_to_ipfs_and_webseed(&self.data_dir, &fname, payload.as_bytes(), "https://ns.webcivics.net").map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?.ipfs_cid;
            }
            "/cpanel/ontologies/sparql" => {
                let q = form.get("query").map(String::as_str).unwrap_or("SELECT ?s ?p WHERE { ?s ?p <https://ns.webcivics.net/hr#Inalienable> }");
                sparql_matches = Some(RangeSparqlEngine::execute_sparql_or_update_on_disk(&self.q42_path, &self.journal_path, q).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?.matching_quins.len().to_string());
            }
            "/cpanel/apps/install" => { fs::create_dir_all(self.data_dir.join("solid").join(form.get("pod_name").cloned().unwrap_or_else(|| "alice".to_string())))?; let _ = install_qapp_isolate(&self.data_dir, &self.journal_path, &form)?; }
            "/cpanel/security/issue-cert" => { WebizenIdTlsCertificateBundle::issue_and_persist(form.get("domain").map(String::as_str).unwrap_or(&state.primary_domain), form.get("steward_did").map(String::as_str).unwrap_or(&state.steward_did_qi), &[0x42u8; 32], &self.tls_dir)?; }
            "/cpanel/wallet/swap" => { let _ = handle_cpanel_wallet_swap(&self.journal_path, &form)?; }
            "/cpanel/jobs/backup" => { let bdir = self.data_dir.join("backups"); fs::create_dir_all(&bdir)?; fs::write(bdir.join(form.get("vault_name").cloned().unwrap_or_else(|| "sanctuary_keep.q42j".to_string())), fs::read(&self.journal_path).unwrap_or_default())?; }
            "/cpanel/delegation/issue" => { state.delegated_permits_count = state.delegated_permits_count.saturating_add(1); let _ = issue_stewardship_delegation(&self.data_dir, &self.journal_path, &form)?; }
            "/cpanel/git/create-repo" => {
                let repo = form.get("repo_name").cloned().unwrap_or_else(|| "human-rights-ontologies.git".to_string());
                OnDiskGitRepoStore::init_bare_repo(&self.git_root, &repo)?;
                if !repo.ends_with(".git") { OnDiskGitRepoStore::init_bare_repo(&self.git_root, &format!("{repo}.git"))?; }
                state.git_repos.push(repo);
            }
            "/cpanel/studio/forge-3d" => extra_cid = handle_cpanel_studio_forge_3d(&self.data_dir, &self.journal_path, &form)?.0,
            "/cpanel/ux/compile-sheaf" => { let _ = handle_cpanel_ux_compile_sheaf(&self.data_dir, &self.journal_path, &form)?; }
            _ => return Self::write_http_response(stream, 404, "Not Found", "text/plain; charset=utf-8", &[], b"Unknown cPanel route"),
        }
        state.save_cbor_ld(&self.host_state_path)?;
        let quin = NQuin::new(q_hash(&state.steward_did_qi), pack_predicate(path, OP_PERMIT, false), q_hash(&extra_cid) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(&state.primary_domain), SensitivityClass::Public), pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, state.delegated_permits_count));
        append_quin_to_journal(&self.journal_path, &quin)?;
        if headers.iter().any(|(k, v)| k == "accept" && v.contains("text/html")) {
            let html = LiveWorkbenchHydrator::render_hydrated_workbench_html(&self.data_dir, Some(&format!("Executed {path}")))?;
            return Self::write_http_response(stream, 200, "OK", "text/html; charset=utf-8", &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("X-Webizen-Runtime", "VBC1-ZeroJS")], html.as_bytes());
        }
        let wire = encode_quin_receipt(&quin);
        match (sparql_matches.as_deref(), extra_cid.is_empty()) {
            (Some(m), _) => Self::write_http_response(stream, 200, "OK", CBOR_LD_MEDIA_TYPE, &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("X-Webizen-Sparql-Matches", m)], &wire),
            (None, true) => Self::write_http_response(stream, 200, "OK", CBOR_LD_MEDIA_TYPE, &[("Content-Security-Policy", STRICT_ZERO_JS_CSP)], &wire),
            (None, false) => Self::write_http_response(stream, 200, "OK", CBOR_LD_MEDIA_TYPE, &[("Content-Security-Policy", STRICT_ZERO_JS_CSP), ("X-Webizen-Ipfs-Cid", &extra_cid)], &wire),
        }
    }

    fn serve_virtual_namespace_term(&self, stream: &mut TcpStream, term: &str, headers: &[(String, String)]) -> io::Result<()> {
        let fmt = NegotiatedFormat::from_accept_header(headers.iter().find_map(|(k, v)| (k == "accept").then_some(v.as_str())).unwrap_or("*/*"));
        let vol = CompiledQ42Volume::load_from_disk(&self.q42_path)?;
        let Some(sb) = vol.get_superblock_slice(0) else { return Self::write_http_response(stream, 404, "Not Found", "text/plain; charset=utf-8", &[], b"No superblocks in volume"); };
        let (mut matched, mut count) = ([NQuin::default(); 32], 0usize);
        for uri in [format!("https://ns.webcivics.net/agent#{term}"), format!("https://ns.webcivics.net/hr#{term}"), format!("https://ns.webcivics.net/care#{term}"), term.to_string()] {
            count = query_superblock_term_zero_heap(sb, &uri, &mut matched);
            if count > 0 { break; }
        }
        let mut payload = Vec::new();
        format_quins_to_rdf(&matched[..count], &vol, fmt, &mut payload)?;
        Self::write_http_response(stream, 200, "OK", fmt.content_type(), &[("Content-Security-Policy", STRICT_ZERO_JS_CSP)], &payload)
    }

    pub fn spawn_background_server(data_dir: PathBuf) -> io::Result<(SocketAddr, Arc<AtomicBool>, JoinHandle<()>)> {
        let (daemon, listener) = (Self::new(data_dir)?, TcpListener::bind("127.0.0.1:0")?);
        listener.set_nonblocking(true)?;
        let (addr, shutdown) = (listener.local_addr()?, Arc::new(AtomicBool::new(false)));
        let shutdown_flag = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            while !shutdown_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => { let _ = stream.set_nonblocking(false); let _ = daemon.handle_http_connection(stream); }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        });
        Ok((addr, shutdown, handle))
    }

    pub fn run_blocking(&self, bind_addr: &str) -> io::Result<()> {
        for incoming in TcpListener::bind(bind_addr)?.incoming().flatten() { let _ = self.handle_http_connection(incoming); }
        Ok(())
    }

    pub fn verify_full_vps_readiness(data_dir: &Path) -> Result<Vec<u8>, &'static str> {
        let (http_addr, shutdown, http_handle) = Self::spawn_background_server(data_dir.to_path_buf()).map_err(|_| "Failed to spawn HTTP daemon")?;
        let mut ring = NQuinDnsZoneRing::new();
        ring.upsert_record("ns.webcivics.net", DnsRrType::A, u32::from_be_bytes([203, 0, 113, 42]) as u64, q_hash("did:qi:webcivics_steward"), SensitivityClass::Public, 300, 1);
        let dns_ctx = DnsQueryContext { has_valid_dni_cookie: false, has_webizen_id_tls_session: false, requester_jurisdiction_hash: q_hash("AU") };
        let (dns_addr, dns_handle) = serve_udp_dns_requests(Arc::new(ring), dns_ctx, 1).map_err(|_| "Failed to spawn UDP DNS")?;
        let bob_alias = RelationshipScopedMailAlias::issue_counterparty_address("alice.tld", "did:qi:alice", "bob", "did:qi:bob", "alice@bob.tld", "Trusted-Bob");
        let (smtp_addr, smtp_handle) = SmtpWireServer::spawn_smtp_server(data_dir.join("maildir"), data_dir.join("journal.q42j"), vec![bob_alias], 1).map_err(|_| "Failed to spawn TCP SMTP")?;
        let (h_root, _) = Self::raw_http_call(http_addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (_, b_hz) = Self::raw_http_call(http_addr, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (_, b_met) = Self::raw_http_call(http_addr, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        if !h_root.starts_with("HTTP/1.1 200 OK") || &b_hz[0..3] != &[0xD9, 0x05, 0x01] || !String::from_utf8_lossy(&b_met).contains("webizen_host_") { return Err("GET /, /healthz or /metrics failed"); }
        let (h_acme, b_acme) = Self::raw_http_call(http_addr, "GET /.well-known/acme-challenge/test-token-123 HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let doh_q = build_rfc1035_query_packet(0x2026, "ns.webcivics.net", DnsRrType::A);
        let (h_doh, b_doh) = Self::raw_http_call_bytes(http_addr, &format!("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", doh_q.len()), &doh_q)?;
        if !h_acme.starts_with("HTTP/1.1 200 OK") || !b_acme.starts_with(b"test-token-123.") || !h_doh.starts_with("HTTP/1.1 200 OK") || b_doh.len() < 16 { return Err("ACME HTTP-01 or DoH POST /dns-query failed"); }
        let form_dom = "domain=coop.civics.au&rr_type=A&value=203.0.113.42";
        let (_, b_dom) = Self::raw_http_call(http_addr, &format!("POST /cpanel/domains/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{form_dom}", form_dom.len()))?;
        if b_dom.len() != CBOR_LD_QUIN_WIRE_SIZE || b_dom[0..3] != [0xD9, 0x05, 0x01] { return Err("POST /cpanel/domains/add receipt invalid"); }
        let ttl = "<https://web.civics.au/alice#me> <http://xmlns.com/foaf/0.1/name> \"Alice\" .";
        let (h_put, _) = Self::raw_http_call(http_addr, &format!("PUT /solid/alice/profile.ttl HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{ttl}", ttl.len()))?;
        let (_, b_get) = Self::raw_http_call(http_addr, "GET /solid/alice/profile.ttl HTTP/1.1\r\nHost: localhost\r\nAccept: text/turtle\r\n\r\n")?;
        if !h_put.starts_with("HTTP/1.1 200 OK") || b_get != ttl.as_bytes() { return Err("Solid LDP PUT/GET verification failed"); }
        let pub_body = "file_name=commons.q42&content=HumanCentricCommonsSlice";
        let (h_pub, _) = Self::raw_http_call(http_addr, &format!("POST /cpanel/files/publish HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{pub_body}", pub_body.len()))?;
        let cid = h_pub.lines().find_map(|l| l.strip_prefix("X-Webizen-Ipfs-Cid: ")).ok_or("Missing IPFS CID header")?.trim();
        let (_, b_ipfs) = Self::raw_http_call(http_addr, &format!("GET /ipfs/{cid} HTTP/1.1\r\nHost: localhost\r\n\r\n"))?;
        let (h_git, _) = Self::raw_http_call(http_addr, "GET /git/webcivics-ns.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        if b_ipfs != b"HumanCentricCommonsSlice" || !h_git.starts_with("HTTP/1.1 200 OK") { return Err("IPFS block or Git Smart HTTP verification failed"); }
        let (_, b_sanc) = Self::raw_http_call(http_addr, "POST /sanctuary/backup HTTP/1.1\r\nHost: localhost\r\nContent-Length: 18\r\n\r\nSanctuaryKeepTest1")?;
        let (_, b_rec) = Self::raw_http_call(http_addr, "POST /sanctuary/recover HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")?;
        let (_, b_settle) = Self::raw_http_call(http_addr, "POST /commons/settle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 17\r\n\r\namount_cents=2500")?;
        let (h_svg, b_svg) = Self::raw_http_call(http_addr, "GET /studio/viewport.svg HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        if &b_sanc[0..3] != &[0xD9, 0x05, 0x01] || &b_rec[0..3] != &[0xD9, 0x05, 0x01] || &b_settle[0..3] != &[0xD9, 0x05, 0x01] || !h_svg.starts_with("HTTP/1.1 200 OK") || !String::from_utf8_lossy(&b_svg).contains("<feGaussianBlur") { return Err("Sanctuary, Commons Settle, or Viewport SVG route failed"); }
        let (f3d, fux) = ("scene_id=orbital-core&mesh=torus_knot_quantum_core&shader=bioluminescent_plasma", "component_id=hero-command-deck&label=Command+Deck");
        let (_, b_3d) = Self::raw_http_call(http_addr, &format!("POST /cpanel/studio/forge-3d HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{f3d}", f3d.len()))?;
        let (_, b_ux) = Self::raw_http_call(http_addr, &format!("POST /cpanel/ux/compile-sheaf HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{fux}", fux.len()))?;
        let (_, b_tel) = Self::raw_http_call(http_addr, "GET /api/telemetry.cbor-ld HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (_, b_inb) = Self::raw_http_call(http_addr, "GET /mail/inbox HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let msend = "from=alice@civics.au&to=bob@civics.au&subject=Readiness&body=Verified+DKIM";
        let (_, b_msend) = Self::raw_http_call(http_addr, &format!("POST /mail/send HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{msend}", msend.len()))?;
        let (h_gup, b_gup) = Self::raw_http_call(http_addr, "POST /git/webcivics-ns.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n0000")?;
        let (_, b_ridx) = Self::raw_http_call(http_addr, "GET /qcdn/root-index.cbor-ld HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (h_quor, _) = Self::raw_http_call(http_addr, "GET /stewardship/quorum HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (h_qapp, _) = Self::raw_http_call(http_addr, "GET /qapps HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (h_prs, _) = Self::raw_http_call(http_addr, "GET /git/webcivics-ns.git/prs HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (h_wmail, _) = Self::raw_http_call(http_addr, "GET /mail/webmail HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let (_, b_ledg) = Self::raw_http_call(http_addr, "GET /commons/ledger.cbor-ld HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        if &b_3d[0..3] != &[0xD9, 0x05, 0x01] || &b_ux[0..3] != &[0xD9, 0x05, 0x01] || &b_tel[0..3] != &[0xD9, 0x05, 0x01] || &b_inb[0..3] != &[0xD9, 0x05, 0x01] || &b_msend[0..3] != &[0xD9, 0x05, 0x01] || &b_ridx[0..3] != &[0xD9, 0x05, 0x01] || &b_ledg[0..3] != &[0xD9, 0x05, 0x01] || !h_quor.starts_with("HTTP/1.1 200 OK") || !h_qapp.starts_with("HTTP/1.1 200 OK") || !h_prs.starts_with("HTTP/1.1 200 OK") || !h_wmail.starts_with("HTTP/1.1 200 OK") || !h_gup.starts_with("HTTP/1.1 200 OK") || !b_gup.windows(4).any(|w| w == b"PACK") { return Err("Phase 13-18 Studio/Q-CDN/Stewardship/QApp/GitForge/Webmail/Ledger routes failed"); }
        let _ = run_vps_doctor_diagnostics(data_dir).map_err(|_| "Encrypted VPS snapshot/restore doctor failed")?;
        let udp = UdpSocket::bind("127.0.0.1:0").map_err(|_| "Bind UDP client failed")?;
        let _ = udp.set_read_timeout(Some(Duration::from_secs(5)));
        udp.send_to(&build_rfc1035_query_packet(0x4242, "ns.webcivics.net", DnsRrType::A), dns_addr).map_err(|_| "UDP send failed")?;
        let mut dns_resp = [0u8; 512];
        let (dn, _) = udp.recv_from(&mut dns_resp).map_err(|_| "UDP recv failed")?;
        if (dns_resp[3] & 0x0F) != DnsRcode::NoError as u8 || &dns_resp[dn - 4..dn] != &[203, 0, 113, 42] { return Err("UDP RFC 1035 DNS verification failed"); }
        let _ = dns_handle.join();
        let mut smtp_stream = TcpStream::connect(smtp_addr).map_err(|_| "Connect SMTP failed")?;
        let mut smtp_reader = BufReader::new(smtp_stream.try_clone().map_err(|_| "Clone SMTP stream failed")?);
        let mut line = String::new();
        let _ = smtp_reader.read_line(&mut line);
        for cmd in ["EHLO bob.tld\r\n", "MAIL FROM:<alice@bob.tld>\r\n", "RCPT TO:<bob@alice.tld>\r\n", "DATA\r\n", "Subject: Readiness\r\n\r\nVerified.\r\n.\r\n", "QUIT\r\n"] {
            smtp_stream.write_all(cmd.as_bytes()).map_err(|_| "Write SMTP command failed")?;
            line.clear();
            let _ = smtp_reader.read_line(&mut line);
            while line.starts_with("250-") { line.clear(); let _ = smtp_reader.read_line(&mut line); }
        }
        if smtp_handle.join().map_err(|_| "Join SMTP thread failed")? != 1 { return Err("SMTP message spool verification failed"); }
        shutdown.store(true, Ordering::Relaxed);
        let _ = (TcpStream::connect(http_addr), http_handle.join());
        let ready_quin = NQuin::new(q_hash("https://ns.webcivics.net/host#VpsReadinessVerified"), pack_predicate("https://ns.webcivics.net/host#allProtocolsQualified", OP_PERMIT, false), 200, pack_context(q_hash("did:qi:webcivics_steward"), SensitivityClass::Public), pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 2026));
        let mut receipt = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        encode_quin_cbor_ld_zero_heap(&ready_quin, &mut receipt)?;
        fs::write(data_dir.join("vps_readiness_receipt.cbor-ld"), receipt).map_err(|_| "Failed to write readiness receipt")?;
        Ok(receipt.to_vec())
    }

    fn raw_http_call(addr: SocketAddr, req: &str) -> Result<(String, Vec<u8>), &'static str> { Self::raw_http_call_bytes(addr, req, &[]) }
    fn raw_http_call_bytes(addr: SocketAddr, head: &str, body: &[u8]) -> Result<(String, Vec<u8>), &'static str> {
        let mut s = TcpStream::connect(addr).map_err(|_| "TCP connect failed")?;
        s.write_all(head.as_bytes()).and_then(|_| s.write_all(body)).map_err(|_| "TCP write failed")?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).map_err(|_| "TCP read failed")?;
        let pos = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("Malformed HTTP response")?;
        Ok((String::from_utf8_lossy(&resp[..pos]).to_string(), resp[pos + 4..].to_vec()))
    }
    fn read_http_request(stream: &mut TcpStream) -> io::Result<Option<(String, String, Vec<(String, String)>, Vec<u8>)>> {
        let (mut buf, mut chunk) = (Vec::with_capacity(2048), [0u8; 1024]);
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break pos + 4; }
            let n = stream.read(&mut chunk)?;
            if n == 0 { if buf.is_empty() { return Ok(None); } break buf.len(); }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 65_536 { return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP header too large")); }
        };
        let header_str = std::str::from_utf8(&buf[..header_end]).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 HTTP header"))?;
        let mut lines = header_str.lines();
        let Some(request_line) = lines.next() else { return Ok(None); };
        let mut req_parts = request_line.split_whitespace();
        let (method, path) = (req_parts.next().unwrap_or("GET").to_string(), req_parts.next().unwrap_or("/").to_string());
        let (mut headers, mut content_length) = (Vec::new(), 0usize);
        for line in lines.take_while(|l| !l.trim().is_empty()) {
            if let Some((k, v)) = line.split_once(':') {
                let (key, val) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
                if key == "content-length" { content_length = val.parse().unwrap_or(0); }
                headers.push((key, val));
            }
        }
        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length { let n = stream.read(&mut chunk)?; if n == 0 { break; } body.extend_from_slice(&chunk[..n]); }
        body.truncate(content_length);
        Ok(Some((method, path, headers, body)))
    }
    fn parse_range_header(headers: &[(String, String)]) -> Option<(u64, u64)> {
        let (s, e) = headers.iter().find_map(|(k, v)| (k == "range").then_some(v.as_str()))?.trim().strip_prefix("bytes=")?.split_once('-')?;
        Some((s.trim().parse().ok()?, e.trim().parse().ok()?))
    }
    fn write_http_response(stream: &mut TcpStream, status: u16, reason: &str, ct: &str, extra: &[(&str, &str)], body: &[u8]) -> io::Result<()> {
        write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len())?;
        for &(k, v) in extra { write!(stream, "{k}: {v}\r\n")?; }
        write!(stream, "\r\n").and_then(|_| stream.write_all(body)).and_then(|_| stream.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use webizen_host_ingest::{replay_quin_journal, Q42_FILE_MAGIC};

    #[test]
    fn http_daemon_serves_live_tcp_routes_cpanel_forms_solid_ipfs_and_readiness() {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let data_dir = std::env::temp_dir().join(format!("qualia_webizen_daemon_test_{}_{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        let receipt = WebizenHostDaemon::verify_full_vps_readiness(&data_dir).unwrap();
        assert!(receipt.len() == CBOR_LD_QUIN_WIRE_SIZE && &receipt[0..3] == &[0xD9, 0x05, 0x01]);
        assert!(data_dir.join("vps_readiness_receipt.cbor-ld").exists() && data_dir.join("studio/orbital-core.hmc").exists());
        assert!(data_dir.join("ux/hero-command-deck.cbor-ld").exists() && data_dir.join("sanctuary_backup.q42j.enc").exists());
        assert!(data_dir.join("deploy/Caddyfile").exists() && data_dir.join("deploy/cloud-init.yaml").exists() && data_dir.join("deploy/build-deb.sh").exists());
        let (addr, shutdown, handle) = WebizenHostDaemon::spawn_background_server(data_dir.clone()).unwrap();
        let (h_health, b_health) = WebizenHostDaemon::raw_http_call(addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert!(h_health.starts_with("HTTP/1.1 200 OK") && &b_health[0..3] == &[0xD9, 0x05, 0x01]);
        let (h_range, b_range) = WebizenHostDaemon::raw_http_call(addr, "GET /volumes/core.q42 HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-63\r\n\r\n").unwrap();
        assert!(h_range.starts_with("HTTP/1.1 206 Partial Content") && &b_range[0..4] == &Q42_FILE_MAGIC);
        let (h_unauth, _) = WebizenHostDaemon::raw_http_call(addr, "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Webizen-Require-Auth: 1\r\n\r\n").unwrap();
        assert!(h_unauth.starts_with("HTTP/1.1 401 Unauthorized"));
        let body = "domain=test.civics.au&rr_type=TXT&value=v%3Dspf1%20mx%20-all&local_part=carol&file_name=slice.q42&repo_name=care-ont.git&scene_id=orbital-core&component_id=hero-command-deck&from_rail=USDC&to_rail=XEC&amount=250";
        for page in ControlPanelPage::ALL {
            let req = format!("POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", page.form_action_path(), body.len());
            let (head, resp_body) = WebizenHostDaemon::raw_http_call(addr, &req).unwrap();
            assert!(head.starts_with("HTTP/1.1 200 OK") && resp_body.len() == CBOR_LD_QUIN_WIRE_SIZE && &resp_body[0..3] == &[0xD9, 0x05, 0x01]);
            if page == ControlPanelPage::OntologiesAndDatabases { assert!(head.contains("X-Webizen-Sparql-Matches:")); }
        }
        let doh_txt = build_rfc1035_query_packet(0x7777, "test.civics.au", DnsRrType::TXT);
        let (h_doh, b_doh) = WebizenHostDaemon::raw_http_call_bytes(addr, &format!("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", doh_txt.len()), &doh_txt).unwrap();
        assert!(h_doh.starts_with("HTTP/1.1 200 OK") && b_doh.windows(14).any(|w| w == b"v=spf1 mx -all"));
        let (_, b_elder) = WebizenHostDaemon::raw_http_call(addr, "GET /cpanel?persona=elder HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let elder_str = String::from_utf8_lossy(&b_elder);
        assert!(elder_str.contains("data-persona=\"elder\"") && elder_str.contains("id=\"live-12-page-state-deck\"") && elder_str.contains("name=\"csrf_token\""));
        let (h_git_log, _) = WebizenHostDaemon::raw_http_call(addr, "GET /git/webcivics-ns.git/log HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let (_, b_qcdn) = WebizenHostDaemon::raw_http_call(addr, "POST /qcdn/register-seeder HTTP/1.1\r\nHost: localhost\r\nContent-Length: 24\r\n\r\ncid=bafkreitest&seeder=1").unwrap();
        let (_, b_swarm) = WebizenHostDaemon::raw_http_call(addr, "GET /qcdn/swarm.cbor-ld HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let (h_402, _) = WebizenHostDaemon::raw_http_call(addr, "POST /commons/settle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 19\r\n\r\ncommercial_unpaid=1").unwrap();
        assert!(h_git_log.starts_with("HTTP/1.1 200 OK") && &b_qcdn[0..3] == &[0xD9, 0x05, 0x01] && &b_swarm[0..3] == &[0xD9, 0x05, 0x01] && h_402.contains("WWW-Authenticate: L402"));
        let (h_setup, b_setup) = WebizenHostDaemon::raw_http_call(addr, "GET /setup HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let setup_form = "primary_domain=coop.civics.au&steward_did_qi=did:qi:alice&passphrase=GuardianPass2026&sanctuary_seed=KeepSeed2026&peer_multiaddr=/ip4/203.0.113.42/tcp/4001";
        let (h_setup_done, _) = WebizenHostDaemon::raw_http_call(addr, &format!("POST /setup/complete HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{setup_form}", setup_form.len())).unwrap();
        let (h_glb, b_glb) = WebizenHostDaemon::raw_http_call(addr, "GET /studio/default-manifold.glb HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let (h_obj, b_obj) = WebizenHostDaemon::raw_http_call(addr, "GET /studio/default-manifold.obj HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert!(h_setup.starts_with("HTTP/1.1 200 OK") && String::from_utf8_lossy(&b_setup).contains("/setup/complete") && h_setup_done.contains("Set-Cookie: DNI_SESSION="));
        assert!(h_glb.contains("model/gltf-binary") && &b_glb[0..4] == b"glTF" && h_obj.contains("model/obj") && b_obj.starts_with(b"#"));
        let journal_quins = replay_quin_journal(&data_dir.join("journal.q42j")).unwrap();
        assert!(journal_quins.len() >= 13 && journal_quins.iter().all(|q| q.verify_parity()));
        shutdown.store(true, Ordering::Relaxed);
        let _ = (TcpStream::connect(addr), handle.join(), fs::remove_dir_all(&data_dir));
    }
}
