//! WP-12 (D12.1) & WP-18 (D18.1): Multi-Protocol Concurrent VPS Supervisor & Dynamic Hot-Reload Engine.
//!
//! Concurrently binds and supervises all four production `webizen-host` protocol listeners:
//! 1. **Socket 1 (`http_bind`, default `:4242`)**: Concurrent HTTP/1.1 worker pool (`MAX_HTTP_WORKERS = 16`)
//!    serving RFC 8484 DoH + W3C Solid LDP + IPFS Block Gateway + WebTorrent WebSeed (`HTTP 206`) +
//!    Git Smart HTTP + Zero-JS Control Panel without head-of-line blocking.
//! 2. **Socket 2 (`dns_bind`, default `:5353`)**: Dynamic Authoritative Dual-Stack (`A` + `AAAA`) UDP DNS
//!    (`RFC 1035`) + TCP DNS (`RFC 7766`) over [`NQuinDnsZoneRing`], hot-reloading hosted domains.
//! 3. **Socket 3 (`smtp_bind`, default `:2525`)**: Dynamic Inbound/Submission TCP SMTP (`RFC 5321`),
//!    hot-reloading [`RelationshipScopedMailAlias`] rules from [`HostPersistentState`] on each session.
//! 4. **Socket 4 (`sanctuary_bind`, default `127.0.0.1:8080`)**: Hardware Loopback-Guarded Sanctuary
//!    Keep listener enforcing [`SanctuaryLoopbackGuard`] (`peer_addr.ip().is_loopback()`).
//!
//! Strictly adheres to the Human-Centric & International Human-Rights Nomenclature Rule.

use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use webizen_host_core::{q_hash, SensitivityClass};
use webizen_host_dns::{handle_rfc1035_packet_zero_heap, DnsQueryContext, DnsRrType, NQuinDnsZoneRing};

use crate::http_daemon::WebizenHostDaemon;
use crate::smtp_mail::handle_smtp_stream;
use crate::vps_deployment::HostPersistentState;
use crate::RelationshipScopedMailAlias;

/// Authoritative public IPv4 address (`203.0.113.42`) assigned to dynamically hosted domains.
pub const DEFAULT_AUTHORITATIVE_IPV4: [u8; 4] = [203, 0, 113, 42];
/// Authoritative public IPv6 address (`2001:db8::42`) assigned to dynamically hosted domains.
pub const DEFAULT_AUTHORITATIVE_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
/// Default authoritative DNS TTL (in seconds) for dynamically hosted domains.
pub const DEFAULT_DYNAMIC_DNS_TTL_SECS: u32 = 300;
/// Maximum concurrent HTTP/1.1 worker threads dispatched by Socket 1 (`http_bind`).
pub const MAX_HTTP_WORKERS: usize = 16;

fn resolve_env_public_ips() -> ([u8; 4], [u8; 16]) {
    let ipv4 = std::env::var("WEBIZEN_PUBLIC_IPV4").ok()
        .and_then(|s| Ipv4Addr::from_str(s.trim()).ok()).map(|ip| ip.octets())
        .unwrap_or(DEFAULT_AUTHORITATIVE_IPV4);
    let ipv6 = std::env::var("WEBIZEN_PUBLIC_IPV6").ok()
        .and_then(|s| Ipv6Addr::from_str(s.trim()).ok()).map(|ip| ip.octets())
        .unwrap_or(DEFAULT_AUTHORITATIVE_IPV6);
    (ipv4, ipv6)
}

/// Configuration for [`MultiProtocolVpsSupervisor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProtocolVpsConfig {
    pub data_dir: PathBuf,
    pub http_bind: String,
    pub dns_bind: String,
    pub smtp_bind: String,
    pub sanctuary_bind: String,
    pub public_ipv4: [u8; 4],
    pub public_ipv6: [u8; 16],
}

impl MultiProtocolVpsConfig {
    /// Construct an ephemeral local test configuration binding all four protocol sockets to `127.0.0.1:0`.
    pub fn ephemeral(data_dir: PathBuf) -> Self {
        let (public_ipv4, public_ipv6) = resolve_env_public_ips();
        Self {
            data_dir, http_bind: "127.0.0.1:0".to_string(), dns_bind: "127.0.0.1:0".to_string(),
            smtp_bind: "127.0.0.1:0".to_string(), sanctuary_bind: "127.0.0.1:0".to_string(),
            public_ipv4, public_ipv6,
        }
    }

    /// Construct the standard production Linux VPS bind configuration (`:4242`, `:5353`, `:2525`, `127.0.0.1:8080`).
    pub fn production_defaults(data_dir: PathBuf) -> Self {
        let (public_ipv4, public_ipv6) = resolve_env_public_ips();
        Self {
            data_dir, http_bind: "0.0.0.0:4242".to_string(), dns_bind: "0.0.0.0:5353".to_string(),
            smtp_bind: "0.0.0.0:2525".to_string(), sanctuary_bind: "127.0.0.1:8080".to_string(),
            public_ipv4, public_ipv6,
        }
    }

    /// Override the authoritative public IPv4 and IPv6 addresses advertised in dynamic DNS records.
    pub fn with_public_ips(mut self, ipv4: [u8; 4], ipv6: [u8; 16]) -> Self {
        self.public_ipv4 = ipv4;
        self.public_ipv6 = ipv6;
        self
    }
}

/// Violation emitted when a non-loopback peer attempts to connect to the `:8080` Sanctuary Keep listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SanctuaryLoopbackOnlyViolation {
    pub peer_addr: SocketAddr,
}

/// Hardware loopback perimeter guard protecting the Sanctuary Keep (`:8080`) Freedom-of-Thought vault.
pub struct SanctuaryLoopbackGuard;

impl SanctuaryLoopbackGuard {
    /// Verify that `peer_addr` originates from the local hardware loopback interface (`127.0.0.0/8` or `::1`).
    #[inline]
    pub fn verify_peer(peer_addr: &SocketAddr) -> Result<(), SanctuaryLoopbackOnlyViolation> {
        if verify_sanctuary_loopback_peer(peer_addr) { Ok(()) } else { Err(SanctuaryLoopbackOnlyViolation { peer_addr: *peer_addr }) }
    }
}

/// Check whether `peer_addr` is a hardware loopback address (`peer_addr.ip().is_loopback()`).
#[inline]
pub fn verify_sanctuary_loopback_peer(peer_addr: &SocketAddr) -> bool {
    peer_addr.ip().is_loopback()
}

/// Write an `HTTP/1.1 403 Forbidden` response recording a [`SanctuaryLoopbackOnlyViolation`] and close the stream.
pub fn reject_non_loopback_sanctuary_stream(stream: &mut TcpStream, peer_addr: &SocketAddr) -> io::Result<()> {
    let body = format!("SanctuaryLoopbackOnlyViolation: Sanctuary Keep (:8080) rejects non-loopback peer {peer_addr}");
    write!(
        stream,
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )?;
    stream.flush()
}

pub fn parse_dns_rr_type_str(rr_str: &str) -> DnsRrType {
    match rr_str.trim().to_ascii_uppercase().as_str() {
        "A" => DnsRrType::A, "AAAA" => DnsRrType::AAAA, "TXT" => DnsRrType::TXT,
        "CNAME" => DnsRrType::CNAME, "NS" => DnsRrType::NS, "MX" => DnsRrType::MX,
        "CAA" => DnsRrType::CAA, "SOA" => DnsRrType::SOA, _ => DnsRrType::TXT,
    }
}

/// Populate a fresh [`NQuinDnsZoneRing`] from [`HostPersistentState`] with explicit public IPv4 (`A`),
/// IPv6 (`AAAA`), and custom RDATA resource records (`TXT`, `CNAME`, `MX`, `NS`, `CAA`).
pub fn build_dynamic_dns_ring_with_ips(state: &HostPersistentState, ipv4: [u8; 4], ipv6: [u8; 16]) -> NQuinDnsZoneRing {
    let (mut ring, zone_did) = (NQuinDnsZoneRing::new(), q_hash(&state.steward_did_qi));
    let (ipv4_packed, ipv6_low64) = (u32::from_be_bytes(ipv4) as u64, u64::from_be_bytes(ipv6[8..16].try_into().unwrap()));
    let mut upsert_dual = |domain: &str, clock: u32| {
        ring.upsert_record(domain, DnsRrType::A, ipv4_packed, zone_did, SensitivityClass::Public, DEFAULT_DYNAMIC_DNS_TTL_SECS, clock);
        ring.upsert_record(domain, DnsRrType::AAAA, ipv6_low64, zone_did, SensitivityClass::Public, DEFAULT_DYNAMIC_DNS_TTL_SECS, clock);
    };
    upsert_dual(state.primary_domain.trim(), 1);
    for (idx, domain) in state.hosted_domains.iter().enumerate() {
        let trimmed = domain.trim();
        if !trimmed.is_empty() { upsert_dual(trimmed, (idx as u32).saturating_add(2)); }
    }
    for (idx, rec) in state.custom_dns_records.iter().enumerate() {
        let rr = parse_dns_rr_type_str(&rec.rr_type);
        let obj = match rr {
            DnsRrType::A => Ipv4Addr::from_str(rec.value.trim()).map(|ip| u32::from_be_bytes(ip.octets()) as u64).unwrap_or(ipv4_packed),
            DnsRrType::AAAA => Ipv6Addr::from_str(rec.value.trim()).map(|ip| u64::from_be_bytes(ip.octets()[8..16].try_into().unwrap())).unwrap_or(ipv6_low64),
            _ => q_hash(&rec.value),
        };
        ring.upsert_record_with_rdata(rec.name.trim(), rr, obj, rec.value.trim().as_bytes(), zone_did, SensitivityClass::Public, rec.ttl.max(60), (idx as u32).saturating_add(100));
    }
    ring
}

/// Populate a fresh [`NQuinDnsZoneRing`] from [`HostPersistentState`] using [`DEFAULT_AUTHORITATIVE_IPV4`]
/// and [`DEFAULT_AUTHORITATIVE_IPV6`].
pub fn build_dynamic_dns_ring_from_state(state: &HostPersistentState) -> NQuinDnsZoneRing {
    build_dynamic_dns_ring_with_ips(state, DEFAULT_AUTHORITATIVE_IPV4, DEFAULT_AUTHORITATIVE_IPV6)
}

/// Evaluate an incoming RFC 1035 UDP DNS query packet against `ring` and `dns_ctx`.
pub fn handle_rfc1035_udp_packet(req_packet: &[u8], ring: &NQuinDnsZoneRing, dns_ctx: &DnsQueryContext) -> Result<Vec<u8>, &'static str> {
    let mut resp_buf = [0u8; 512];
    let len = handle_rfc1035_packet_zero_heap(ring, dns_ctx, req_packet, &mut resp_buf)?;
    Ok(resp_buf[..len].to_vec())
}

/// Serve RFC 7766 two-byte length-prefixed TCP DNS queries on `stream` against `ring` and `dns_ctx`.
pub fn handle_rfc7766_tcp_dns_stream(stream: &mut TcpStream, ring: &NQuinDnsZoneRing, dns_ctx: &DnsQueryContext) -> io::Result<usize> {
    let (mut req_buf, mut resp_buf, mut len_buf, mut served) = ([0u8; 512], [0u8; 512], [0u8; 2], 0usize);
    while stream.read_exact(&mut len_buf).is_ok() {
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > req_buf.len() { break; }
        stream.read_exact(&mut req_buf[..msg_len])?;
        if let Ok(resp_len) = handle_rfc1035_packet_zero_heap(ring, dns_ctx, &req_buf[..msg_len], &mut resp_buf) {
            stream.write_all(&(resp_len as u16).to_be_bytes())?;
            stream.write_all(&resp_buf[..resp_len])?;
            stream.flush()?;
            served += 1;
        } else {
            break;
        }
    }
    Ok(served)
}

/// Convert all `(alias_addr, counterparty_did, allowed_sender)` tuples in [`HostPersistentState`]
/// into active [`RelationshipScopedMailAlias`] instances.
pub fn build_dynamic_mail_aliases_from_state(state: &HostPersistentState) -> Vec<RelationshipScopedMailAlias> {
    let mut aliases = Vec::with_capacity(state.mail_aliases.len());
    for (alias_addr, counterparty_did, allowed_sender) in &state.mail_aliases {
        let (local_part, domain) = alias_addr.split_once('@').unwrap_or((alias_addr.as_str(), state.primary_domain.as_str()));
        let mut alias = RelationshipScopedMailAlias::issue_counterparty_address(
            domain.trim(), &state.steward_did_qi, local_part.trim(), counterparty_did.trim(), allowed_sender.trim(), "Dynamic-Relationship-Scoped-Mail",
        );
        if alias_addr.contains('@') { alias.alias_address = alias_addr.trim().to_ascii_lowercase(); }
        aliases.push(alias);
    }
    aliases
}

#[inline]
fn load_state_or_default(host_state_path: &Path) -> HostPersistentState {
    HostPersistentState::load_cbor_ld(host_state_path).unwrap_or_default()
}

/// Handle to a running 4-socket [`MultiProtocolVpsSupervisor`] instance.
pub struct MultiProtocolVpsHandle {
    pub http_addr: SocketAddr,
    pub dns_addr: SocketAddr,
    pub smtp_addr: SocketAddr,
    pub sanctuary_addr: SocketAddr,
    pub shutdown: Arc<AtomicBool>,
    pub threads: Vec<JoinHandle<()>>,
}

impl MultiProtocolVpsHandle {
    /// Signal graceful shutdown across all protocol listeners, poke each socket on `127.0.0.1`
    /// so poll/blocking loops wake immediately, and join all worker threads.
    pub fn shutdown_and_join(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for port in [self.http_addr.port(), self.dns_addr.port(), self.smtp_addr.port(), self.sanctuary_addr.port()] {
            let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(50));
        }
        if let Ok(udp_poke) = UdpSocket::bind("127.0.0.1:0") {
            let _ = udp_poke.send_to(&[0u8; 1], SocketAddr::from(([127, 0, 0, 1], self.dns_addr.port())));
        }
        for handle in self.threads { let _ = handle.join(); }
    }
}

/// Concurrent supervisor for the 4 production `webizen-host` network listeners.
pub struct MultiProtocolVpsSupervisor;

impl MultiProtocolVpsSupervisor {
    /// Initialize [`WebizenHostDaemon`] and spawn all concurrent protocol listener threads.
    pub fn spawn(config: MultiProtocolVpsConfig) -> io::Result<MultiProtocolVpsHandle> {
        let daemon = WebizenHostDaemon::new(config.data_dir.clone())?;
        let shutdown = Arc::new(AtomicBool::new(false));

        let http_listener = TcpListener::bind(&config.http_bind)?;
        http_listener.set_nonblocking(true)?;
        let http_addr = http_listener.local_addr()?;

        let dns_socket = UdpSocket::bind(&config.dns_bind)?;
        dns_socket.set_read_timeout(Some(Duration::from_millis(25)))?;
        let dns_addr = dns_socket.local_addr()?;
        let dns_tcp_listener = TcpListener::bind(dns_addr)?;
        dns_tcp_listener.set_nonblocking(true)?;

        let smtp_listener = TcpListener::bind(&config.smtp_bind)?;
        smtp_listener.set_nonblocking(true)?;
        let smtp_addr = smtp_listener.local_addr()?;

        let sanctuary_listener = TcpListener::bind(&config.sanctuary_bind)?;
        sanctuary_listener.set_nonblocking(true)?;
        let sanctuary_addr = sanctuary_listener.local_addr()?;

        let mut threads = Vec::with_capacity(5);

        // Socket 1: Concurrent HTTP/1.1 + DoH + Solid + IPFS + Git + cPanel worker pool (MAX_HTTP_WORKERS = 16)
        let (daemon_http, shutdown_http) = (daemon.clone(), Arc::clone(&shutdown));
        threads.push(thread::spawn(move || {
            let active_workers = Arc::new(AtomicUsize::new(0));
            while !shutdown_http.load(Ordering::Relaxed) {
                match http_listener.accept() {
                    Ok((stream, _)) => {
                        if shutdown_http.load(Ordering::Relaxed) { break; }
                        let _ = (stream.set_nonblocking(false), stream.set_read_timeout(Some(Duration::from_secs(5))), stream.set_write_timeout(Some(Duration::from_secs(5))));
                        while active_workers.load(Ordering::Acquire) >= MAX_HTTP_WORKERS && !shutdown_http.load(Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(1));
                        }
                        active_workers.fetch_add(1, Ordering::AcqRel);
                        let (d, counter) = (daemon_http.clone(), Arc::clone(&active_workers));
                        thread::spawn(move || {
                            let _ = d.handle_http_connection(stream);
                            counter.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
            for _ in 0..50 {
                if active_workers.load(Ordering::Acquire) == 0 { break; }
                thread::sleep(Duration::from_millis(2));
            }
        }));

        // Socket 2A: Dynamic Authoritative UDP DNS (RFC 1035)
        let (state_path_dns, shutdown_dns) = (daemon.host_state_path.clone(), Arc::clone(&shutdown));
        let (pub_ipv4, pub_ipv6) = (config.public_ipv4, config.public_ipv6);
        let dns_ctx = DnsQueryContext { has_valid_dni_cookie: false, has_webizen_id_tls_session: false, requester_jurisdiction_hash: q_hash("AU") };
        threads.push(thread::spawn(move || {
            let mut pkt = [0u8; 512];
            while !shutdown_dns.load(Ordering::Relaxed) {
                match dns_socket.recv_from(&mut pkt) {
                    Ok((n, peer)) => {
                        if shutdown_dns.load(Ordering::Relaxed) { break; }
                        let ring = build_dynamic_dns_ring_with_ips(&load_state_or_default(&state_path_dns), pub_ipv4, pub_ipv6);
                        if let Ok(resp) = handle_rfc1035_udp_packet(&pkt[..n], &ring, &dns_ctx) {
                            let _ = dns_socket.send_to(&resp, peer);
                        }
                    }
                    Err(_) => thread::sleep(Duration::from_millis(2)),
                }
            }
        }));

        // Socket 2B: Dynamic Authoritative TCP DNS (RFC 7766) on dns_addr
        let (state_path_dns_tcp, shutdown_dns_tcp) = (daemon.host_state_path.clone(), Arc::clone(&shutdown));
        threads.push(thread::spawn(move || {
            while !shutdown_dns_tcp.load(Ordering::Relaxed) {
                match dns_tcp_listener.accept() {
                    Ok((mut stream, _)) => {
                        if shutdown_dns_tcp.load(Ordering::Relaxed) { break; }
                        let _ = (stream.set_nonblocking(false), stream.set_read_timeout(Some(Duration::from_secs(5))), stream.set_write_timeout(Some(Duration::from_secs(5))));
                        let ring = build_dynamic_dns_ring_with_ips(&load_state_or_default(&state_path_dns_tcp), pub_ipv4, pub_ipv6);
                        let _ = handle_rfc7766_tcp_dns_stream(&mut stream, &ring, &dns_ctx);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        }));

        // Socket 3: Dynamic Inbound TCP SMTP (RFC 5321)
        let state_path_smtp = daemon.host_state_path.clone();
        let (mail_root, journal_path, shutdown_smtp) = (daemon.data_dir.join("maildir"), daemon.journal_path.clone(), Arc::clone(&shutdown));
        threads.push(thread::spawn(move || {
            while !shutdown_smtp.load(Ordering::Relaxed) {
                match smtp_listener.accept() {
                    Ok((stream, _)) => {
                        if shutdown_smtp.load(Ordering::Relaxed) { break; }
                        let _ = (stream.set_nonblocking(false), stream.set_read_timeout(Some(Duration::from_secs(5))), stream.set_write_timeout(Some(Duration::from_secs(5))));
                        let aliases = build_dynamic_mail_aliases_from_state(&load_state_or_default(&state_path_smtp));
                        if let Ok(mut writer) = stream.try_clone() {
                            let mut reader = BufReader::new(stream);
                            let _ = handle_smtp_stream(&mut reader, &mut writer, &mail_root, &journal_path, &aliases);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
        }));

        // Socket 4: Hardware Loopback-Guarded Sanctuary Keep (:8080)
        let (daemon_sanctuary, shutdown_sanctuary) = (daemon, Arc::clone(&shutdown));
        threads.push(thread::spawn(move || {
            while !shutdown_sanctuary.load(Ordering::Relaxed) {
                match sanctuary_listener.accept() {
                    Ok((mut stream, peer_addr)) => {
                        if shutdown_sanctuary.load(Ordering::Relaxed) { break; }
                        let _ = stream.set_nonblocking(false);
                        if !verify_sanctuary_loopback_peer(&peer_addr) {
                            let _ = reject_non_loopback_sanctuary_stream(&mut stream, &peer_addr);
                        } else {
                            let _ = daemon_sanctuary.handle_http_connection(stream);
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
        }));

        Ok(MultiProtocolVpsHandle { http_addr, dns_addr, smtp_addr, sanctuary_addr, shutdown, threads })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::BufRead;
    use std::net::IpAddr;
    use std::sync::atomic::AtomicU64;
    use crate::smtp_mail::list_spooled_messages;
    use webizen_host_core::CBOR_LD_QUIN_WIRE_SIZE;
    use webizen_host_dns::{build_rfc1035_query_packet, query_dns_over_tcp, DnsRcode};

    fn http_post_form(addr: SocketAddr, path: &str, form_body: &str) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).expect("connect HTTP listener");
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form_body}",
            form_body.len()
        );
        stream.write_all(req.as_bytes()).expect("write HTTP POST");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read HTTP response");
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("HTTP header delimiter");
        (String::from_utf8_lossy(&resp[..split]).to_string(), resp[split + 4..].to_vec())
    }

    #[test]
    fn multi_protocol_supervisor_hot_reloads_domains_and_mail_aliases_live() {
        static TEST_ID: AtomicU64 = AtomicU64::new(1);
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!("qualia_wp12_sup_{}_{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&data_dir);

        let custom_ipv4 = [198, 51, 100, 88];
        let custom_ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xCA, 0xFE];
        let cfg = MultiProtocolVpsConfig::ephemeral(data_dir.clone()).with_public_ips(custom_ipv4, custom_ipv6);
        assert_eq!((cfg.public_ipv4, cfg.public_ipv6), (custom_ipv4, custom_ipv6));

        let vps = MultiProtocolVpsSupervisor::spawn(cfg).expect("spawn MultiProtocolVpsSupervisor");

        let public_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 54321);
        assert!(!verify_sanctuary_loopback_peer(&public_peer));
        assert!(SanctuaryLoopbackGuard::verify_peer(&public_peer).is_err());
        assert!(verify_sanctuary_loopback_peer(&vps.sanctuary_addr));

        // 1. Dynamically add a new domain via POST /cpanel/domains/add and query A + AAAA over UDP & RFC 7766 TCP DNS
        let (hdr_dom, body_dom) = http_post_form(vps.http_addr, "/cpanel/domains/add", "domain=regenerative.coop.au&rr_type=A&value=198.51.100.88");
        assert!(hdr_dom.starts_with("HTTP/1.1 200 OK") && body_dom.len() == CBOR_LD_QUIN_WIRE_SIZE && &body_dom[0..3] == &[0xD9, 0x05, 0x01]);

        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
        udp.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let query_a = build_rfc1035_query_packet(0x1201, "regenerative.coop.au", DnsRrType::A);
        let mut dns_resp = [0u8; 512];
        let mut n = 0usize;
        for _ in 0..6 {
            udp.send_to(&query_a, vps.dns_addr).expect("send UDP DNS A query");
            if let Ok((len, _)) = udp.recv_from(&mut dns_resp) { n = len; break; }
        }
        assert!(n > 16, "recv UDP DNS A response");
        assert_eq!((dns_resp[3] & 0x0F, &dns_resp[n - 4..n]), (DnsRcode::NoError as u8, &custom_ipv4[..]));

        let query_aaaa = build_rfc1035_query_packet(0x1202, "regenerative.coop.au", DnsRrType::AAAA);
        let tcp_aaaa_resp = query_dns_over_tcp(vps.dns_addr, &query_aaaa).expect("RFC 7766 TCP DNS AAAA query");
        assert_eq!((tcp_aaaa_resp[3] & 0x0F, &tcp_aaaa_resp[tcp_aaaa_resp.len() - 8..]), (DnsRcode::NoError as u8, &custom_ipv6[8..16]));

        // 2. Verify concurrent HTTP worker pool (MAX_HTTP_WORKERS = 16) avoids head-of-line blocking
        let mut slow_stream = TcpStream::connect(vps.http_addr).expect("connect slow stream");
        slow_stream.write_all(b"GET /healthz HTTP/1.1\r\n").unwrap();
        let workers: Vec<_> = (0..6).map(|_| {
            let addr = vps.http_addr;
            thread::spawn(move || {
                let mut s = TcpStream::connect(addr).unwrap();
                s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).unwrap();
                assert!(buf.starts_with(b"HTTP/1.1 200 OK"));
            })
        }).collect();
        for w in workers { w.join().expect("concurrent HTTP worker succeeded"); }
        slow_stream.write_all(b"Host: localhost\r\n\r\n").unwrap();

        // 3. Dynamically add a relationship mail alias via POST /cpanel/email/add and deliver mail via live TCP SMTP
        let (hdr_mail, body_mail) = http_post_form(
            vps.http_addr, "/cpanel/email/add",
            "local_part=diana&domain=regenerative.coop.au&counterparty_did=did:qi:diana&allowed_sender=steward@diana.org",
        );
        assert!(hdr_mail.starts_with("HTTP/1.1 200 OK") && &body_mail[0..3] == &[0xD9, 0x05, 0x01]);

        let mut smtp_stream = TcpStream::connect(vps.smtp_addr).expect("connect live SMTP");
        let mut smtp_reader = BufReader::new(smtp_stream.try_clone().unwrap());
        let mut line = String::new();
        smtp_reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("220 "));
        for cmd in [
            "EHLO diana.org\r\n",
            "MAIL FROM:<steward@diana.org>\r\n",
            "RCPT TO:<diana@regenerative.coop.au>\r\n",
            "DATA\r\n",
            "From: steward@diana.org\r\nTo: diana@regenerative.coop.au\r\nSubject: Live Hot Reload\r\n\r\nVerified dynamic alias!\r\n.\r\n",
            "QUIT\r\n",
        ] {
            smtp_stream.write_all(cmd.as_bytes()).unwrap();
            line.clear();
            smtp_reader.read_line(&mut line).unwrap();
            while line.starts_with("250-") { line.clear(); smtp_reader.read_line(&mut line).unwrap(); }
        }
        let spooled = list_spooled_messages(&data_dir.join("maildir"), "diana@regenerative.coop.au").unwrap();
        assert_eq!(spooled.len(), 1);
        assert!(spooled[0].1.contains("Verified dynamic alias!"));

        // 4. Verify Sanctuary Keep loopback socket serves /sanctuary/backup over 127.0.0.1
        let (hdr_sanc, body_sanc) = http_post_form(vps.sanctuary_addr, "/sanctuary/backup", "SanctuaryLoopbackSegment");
        assert!(hdr_sanc.starts_with("HTTP/1.1 200 OK") && &body_sanc[0..3] == &[0xD9, 0x05, 0x01]);

        vps.shutdown_and_join();
        let _ = fs::remove_dir_all(&data_dir);
    }
}
