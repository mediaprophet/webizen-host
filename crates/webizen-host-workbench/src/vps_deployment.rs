//! WP-09 (D4.1), WP-10 (D10.6), WP-20 (D20.1) & WP-25 (D25.2): Persistent Host Configuration
//! (`HostPersistentState`, `CustomDnsRecord` in W3C CBOR-LD `0xD90501`) and Turnkey Linux VPS
//! Deployment Artifact Generator (`systemd`, `nftables`, `install-vps.sh`, `Caddyfile`,
//! `Containerfile`, `backup-cron.sh`, `cloud-init.yaml`, and `build-deb.sh`).
//!
//! Strictly adheres to the Human-Centric & International Human-Rights Nomenclature Rule.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use webizen_host_core::{sha256, validate_human_centric_nomenclature};

/// W3C CBOR-LD compressed tag header (`0xD9 0x05 0x01`, Tag 1281).
pub const CBOR_LD_HEADER: [u8; 3] = [0xD9, 0x05, 0x01];

/// Format version marker following the 3-byte CBOR-LD tag header.
const HOST_STATE_VERSION: u8 = 1;

/// User-defined authoritative DNS resource record persisted in [`HostPersistentState`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomDnsRecord {
    pub name: String,
    pub rr_type: String,
    pub ttl: u32,
    pub value: String,
}

/// Persistent configuration and operational state for a Human-Centric `webizen-host` instance,
/// serialized to `host_state.cbor-ld` with a 32-byte FIPS 180-4 `SHA-256` integrity seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPersistentState {
    pub primary_domain: String,
    pub steward_did_qi: String,
    pub hard_monthly_egress_cap_bytes: u64,
    pub hosted_domains: Vec<String>,
    /// Relationship-scoped mail aliases: `(alias_address, counterparty_did, allowed_sender_email)`.
    pub mail_aliases: Vec<(String, String, String)>,
    pub git_repos: Vec<String>,
    pub delegated_permits_count: u32,
    pub custom_dns_records: Vec<CustomDnsRecord>,
}

impl Default for HostPersistentState {
    fn default() -> Self {
        Self {
            primary_domain: "ns.webcivics.net".to_string(),
            steward_did_qi: "did:qi:webcivics_steward".to_string(),
            hard_monthly_egress_cap_bytes: 1_500 * 1024 * 1024 * 1024, // 1.5 TiB
            hosted_domains: vec!["ns.webcivics.net".to_string(), "civics.au".to_string()],
            mail_aliases: vec![(
                "bob@civics.au".to_string(),
                "did:qi:bob".to_string(),
                "alice@bob.tld".to_string(),
            )],
            git_repos: vec!["webcivics-ns.git".to_string()],
            delegated_permits_count: 1,
            custom_dns_records: Vec::new(),
        }
    }
}

impl HostPersistentState {
    /// Validate that all configured domains, DIDs, aliases, and custom DNS records comply with
    /// the Human-Centric nomenclature rule before persisting or loading.
    pub fn validate_nomenclature(&self) -> io::Result<()> {
        let check = |s: &str| {
            validate_human_centric_nomenclature(s)
                .map_err(|msg| io::Error::new(ErrorKind::InvalidData, msg))
        };
        check(&self.primary_domain)?;
        check(&self.steward_did_qi)?;
        for d in &self.hosted_domains {
            check(d)?;
        }
        for (alias, did, sender) in &self.mail_aliases {
            check(alias)?;
            check(did)?;
            check(sender)?;
        }
        for repo in &self.git_repos {
            check(repo)?;
        }
        for rec in &self.custom_dns_records {
            check(&rec.name)?;
            check(&rec.rr_type)?;
            check(&rec.value)?;
        }
        Ok(())
    }

    /// Serialize `HostPersistentState` to `path` with W3C CBOR-LD compressed tag header
    /// `[0xD9, 0x05, 0x01]`, length-prefixed fields, and a trailing 32-byte FIPS 180-4 `SHA-256` seal.
    pub fn save_cbor_ld(&self, path: &Path) -> io::Result<()> {
        self.validate_nomenclature()?;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&CBOR_LD_HEADER);
        buf.push(HOST_STATE_VERSION);

        write_lp_str(&mut buf, &self.primary_domain);
        write_lp_str(&mut buf, &self.steward_did_qi);
        buf.extend_from_slice(&self.hard_monthly_egress_cap_bytes.to_be_bytes());

        buf.extend_from_slice(&(self.hosted_domains.len() as u32).to_be_bytes());
        for d in &self.hosted_domains {
            write_lp_str(&mut buf, d);
        }

        buf.extend_from_slice(&(self.mail_aliases.len() as u32).to_be_bytes());
        for (alias, did, sender) in &self.mail_aliases {
            write_lp_str(&mut buf, alias);
            write_lp_str(&mut buf, did);
            write_lp_str(&mut buf, sender);
        }

        buf.extend_from_slice(&(self.git_repos.len() as u32).to_be_bytes());
        for repo in &self.git_repos {
            write_lp_str(&mut buf, repo);
        }

        buf.extend_from_slice(&self.delegated_permits_count.to_be_bytes());

        buf.extend_from_slice(&(self.custom_dns_records.len() as u32).to_be_bytes());
        for rec in &self.custom_dns_records {
            write_lp_str(&mut buf, &rec.name);
            write_lp_str(&mut buf, &rec.rr_type);
            buf.extend_from_slice(&rec.ttl.to_be_bytes());
            write_lp_str(&mut buf, &rec.value);
        }

        let seal = sha256(&buf);
        buf.extend_from_slice(&seal);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &buf)
    }

    /// Load and verify `HostPersistentState` from `path`, checking the `[0xD9, 0x05, 0x01]`
    /// CBOR-LD header and the trailing 32-byte `SHA-256` seal (failing closed with `InvalidData` on tamper).
    pub fn load_cbor_ld(path: &Path) -> io::Result<Self> {
        let raw = fs::read(path)?;
        if raw.len() < 4 + 32 {
            return Err(io::Error::new(ErrorKind::InvalidData, "CBOR-LD host state file truncated"));
        }
        if raw[0..3] != CBOR_LD_HEADER {
            return Err(io::Error::new(ErrorKind::InvalidData, "Missing W3C CBOR-LD tag header (0xD9 0x05 0x01)"));
        }
        if raw[3] != HOST_STATE_VERSION {
            return Err(io::Error::new(ErrorKind::InvalidData, "Unsupported HostPersistentState version"));
        }

        let payload_len = raw.len() - 32;
        let (payload, stored_seal) = (&raw[..payload_len], &raw[payload_len..]);
        let computed_seal = sha256(payload);

        let mut diff = 0u8;
        for i in 0..32 {
            diff |= stored_seal[i] ^ computed_seal[i];
        }
        if diff != 0 {
            return Err(io::Error::new(ErrorKind::InvalidData, "HostPersistentState SHA-256 integrity seal verification failed"));
        }

        let mut cur = 4usize;
        let primary_domain = read_lp_str(payload, &mut cur)?;
        let steward_did_qi = read_lp_str(payload, &mut cur)?;
        let hard_monthly_egress_cap_bytes = read_u64(payload, &mut cur)?;

        let domains_len = read_u32(payload, &mut cur)? as usize;
        let mut hosted_domains = Vec::with_capacity(domains_len.min(1024));
        for _ in 0..domains_len {
            hosted_domains.push(read_lp_str(payload, &mut cur)?);
        }

        let aliases_len = read_u32(payload, &mut cur)? as usize;
        let mut mail_aliases = Vec::with_capacity(aliases_len.min(1024));
        for _ in 0..aliases_len {
            mail_aliases.push((read_lp_str(payload, &mut cur)?, read_lp_str(payload, &mut cur)?, read_lp_str(payload, &mut cur)?));
        }

        let repos_len = read_u32(payload, &mut cur)? as usize;
        let mut git_repos = Vec::with_capacity(repos_len.min(1024));
        for _ in 0..repos_len {
            git_repos.push(read_lp_str(payload, &mut cur)?);
        }

        let delegated_permits_count = read_u32(payload, &mut cur)?;

        let mut custom_dns_records = Vec::new();
        if cur < payload.len() {
            let dns_len = read_u32(payload, &mut cur)? as usize;
            custom_dns_records.reserve(dns_len.min(1024));
            for _ in 0..dns_len {
                let name = read_lp_str(payload, &mut cur)?;
                let rr_type = read_lp_str(payload, &mut cur)?;
                let ttl = read_u32(payload, &mut cur)?;
                let value = read_lp_str(payload, &mut cur)?;
                custom_dns_records.push(CustomDnsRecord { name, rr_type, ttl, value });
            }
        }
        if cur != payload.len() {
            return Err(io::Error::new(ErrorKind::InvalidData, "Trailing unparsed bytes in HostPersistentState CBOR-LD payload"));
        }

        let state = Self {
            primary_domain,
            steward_did_qi,
            hard_monthly_egress_cap_bytes,
            hosted_domains,
            mail_aliases,
            git_repos,
            delegated_permits_count,
            custom_dns_records,
        };
        state.validate_nomenclature()?;
        Ok(state)
    }
}

fn write_lp_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_u32(buf: &[u8], cur: &mut usize) -> io::Result<u32> {
    if *cur + 4 > buf.len() {
        return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading u32"));
    }
    let val = u32::from_be_bytes(buf[*cur..*cur + 4].try_into().unwrap());
    *cur += 4;
    Ok(val)
}

fn read_u64(buf: &[u8], cur: &mut usize) -> io::Result<u64> {
    if *cur + 8 > buf.len() {
        return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading u64"));
    }
    let val = u64::from_be_bytes(buf[*cur..*cur + 8].try_into().unwrap());
    *cur += 8;
    Ok(val)
}

fn read_lp_str(buf: &[u8], cur: &mut usize) -> io::Result<String> {
    let len = read_u32(buf, cur)? as usize;
    if *cur + len > buf.len() {
        return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading string field"));
    }
    let s = std::str::from_utf8(&buf[*cur..*cur + len])
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid UTF-8 in host state"))?
        .to_string();
    *cur += len;
    Ok(s)
}

/// Generated file paths for the Turnkey Linux VPS Deployment Bundle (`<data_dir>/deploy/`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpsDeploymentPaths {
    pub deploy_dir: PathBuf,
    pub systemd_unit_path: PathBuf,
    pub nftables_conf_path: PathBuf,
    pub install_script_path: PathBuf,
    pub caddyfile_path: PathBuf,
    pub containerfile_path: PathBuf,
    pub backup_cron_path: PathBuf,
}

/// Generator for production-hardened Linux VPS deployment artifacts.
pub struct VpsDeploymentBundle;

impl VpsDeploymentBundle {
    /// Write the complete Linux VPS deployment bundle into `<data_dir>/deploy/`.
    pub fn write_linux_vps_deployment_bundle(
        data_dir: &Path,
        state: &HostPersistentState,
    ) -> io::Result<VpsDeploymentPaths> {
        write_linux_vps_deployment_bundle(data_dir, state)
    }
}

/// Write eight production-hardened Linux VPS deployment files into `<data_dir>/deploy/`:
/// `webizen-hostd.service`, `nftables-qpolicy.conf`, `install-vps.sh`, `Caddyfile`,
/// `Containerfile`, `backup-cron.sh`, `cloud-init.yaml`, and `build-deb.sh`.
pub fn write_linux_vps_deployment_bundle(
    data_dir: &Path,
    state: &HostPersistentState,
) -> io::Result<VpsDeploymentPaths> {
    state.validate_nomenclature()?;
    let deploy_dir = data_dir.join("deploy");
    fs::create_dir_all(&deploy_dir)?;

    let systemd_unit_path = deploy_dir.join("webizen-hostd.service");
    let nftables_conf_path = deploy_dir.join("nftables-qpolicy.conf");
    let install_script_path = deploy_dir.join("install-vps.sh");
    let caddyfile_path = deploy_dir.join("Caddyfile");
    let containerfile_path = deploy_dir.join("Containerfile");
    let backup_cron_path = deploy_dir.join("backup-cron.sh");
    let cloud_init_path = deploy_dir.join("cloud-init.yaml");
    let build_deb_path = deploy_dir.join("build-deb.sh");
    let (domain, did, cap) = (&state.primary_domain, &state.steward_did_qi, state.hard_monthly_egress_cap_bytes);

    let systemd_unit = format!(
        "# Webizen-Host Systemd Service Unit — Human-Centric Personal & Family Stewardship\n\
         # Primary Domain: {domain} | Steward DID: {did}\n\
         [Unit]\nDescription=Webizen Human-Centric Host Daemon (QualiaDB NQuin DNS, Range-SPARQL, Relationship Mail)\n\
         After=network-online.target nftables.service\nWants=network-online.target\n\n\
         [Service]\nType=simple\nUser=webizen\nGroup=webizen\nWorkingDirectory=/var/lib/webizen-host\n\
         Environment=\"WEBIZEN_HOST_BIND=0.0.0.0:4242\"\nEnvironment=\"WEBIZEN_HOST_DATA_DIR=/var/lib/webizen-host\"\n\
         ExecStart=/usr/local/bin/webizen-hostd --serve /var/lib/webizen-host\nRestart=on-failure\nRestartSec=5s\n\
         ProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nReadWritePaths=/var/lib/webizen-host\nNoNewPrivileges=true\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nMemoryMax=512M\n\n\
         [Install]\nWantedBy=multi-user.target\n"
    );

    let nftables_conf = format!(
        "#!/usr/sbin/nft -f\n# Webizen-Host QPolicy nftables Firewall — {domain} ({cap} bytes)\n\
         table inet webizen_qpolicy {{\n\tchain input {{\n\t\ttype filter hook input priority 0; policy drop;\n\
         \t\tiifname \"lo\" accept\n\t\tct state established,related accept\n\
         \t\tiifname != \"lo\" tcp dport 8080 drop\n\t\tiifname != \"lo\" udp dport 8080 drop\n\
         \t\tudp dport 53 accept\n\t\ttcp dport 53 accept\n\t\ttcp dport {{ 80, 443 }} accept\n\t\tudp dport 443 accept\n\
         \t\ttcp dport {{ 25, 587 }} accept\n\t\ttcp dport 4242 accept\n\t\tudp dport 4242 accept\n\
         \t\tip protocol icmp accept\n\t\tip6 nexthdr icmpv6 accept\n\t}}\n}}\n"
    );

    let install_script = format!(
        "#!/usr/bin/env bash\n# Webizen-Host Turnkey Linux VPS Provisioning Script — {domain}\nset -euo pipefail\n\
         DATA_DIR=\"${{WEBIZEN_HOST_DATA_DIR:-/var/lib/webizen-host}}\"\nBIN_SRC=\"${{WEBIZEN_HOST_BIN:-./webizen-hostd}}\"\n\
         if ! id -u webizen >/dev/null 2>&1; then useradd --system --home-dir \"$DATA_DIR\" --shell /usr/sbin/nologin webizen; fi\n\
         install -d -m 0750 -o webizen -g webizen \"$DATA_DIR\"\n\
         if [ -f \"$BIN_SRC\" ]; then install -m 0755 \"$BIN_SRC\" /usr/local/bin/webizen-hostd; fi\n\
         /usr/local/bin/webizen-hostd --init-vps \"$DATA_DIR\"\nchown -R webizen:webizen \"$DATA_DIR\"\n\
         install -m 0644 \"$DATA_DIR/deploy/nftables-qpolicy.conf\" /etc/nftables-qpolicy.conf && nft -f /etc/nftables-qpolicy.conf\n\
         install -m 0644 \"$DATA_DIR/deploy/webizen-hostd.service\" /etc/systemd/system/webizen-hostd.service\n\
         systemctl daemon-reload && systemctl enable --now webizen-hostd.service\n"
    );

    let caddyfile = format!(
        "# Webizen-Host Automatic HTTPS / HTTP3 Reverse Proxy — Human-Centric Stewardship\n\
         {domain} {{\n\theader Content-Security-Policy \"default-src 'self'; script-src 'none'\"\n\
         \theader X-Content-Type-Options \"nosniff\"\n\treverse_proxy 127.0.0.1:4242\n}}\n"
    );

    let containerfile = format!(
        "# Webizen-Host Minimal Debian Containerfile — Human-Centric Stewardship ({domain})\nFROM debian:bookworm-slim\n\
         RUN useradd --system --home-dir /var/lib/webizen-host --shell /usr/sbin/nologin webizen \\\n\
             && mkdir -p /var/lib/webizen-host && chown -R webizen:webizen /var/lib/webizen-host\n\
         COPY webizen-hostd /usr/local/bin/webizen-hostd\nUSER webizen\nWORKDIR /var/lib/webizen-host\n\
         EXPOSE 4242/tcp 4242/udp 53/udp 25/tcp\nENTRYPOINT [\"/usr/local/bin/webizen-hostd\", \"--serve\", \"/var/lib/webizen-host\"]\n"
    );

    let backup_cron = format!(
        "#!/usr/bin/env bash\n# Webizen-Host Daily Integrity Verification & Encrypted Archive Cron ({domain})\nset -euo pipefail\n\
         DATA_DIR=\"${{WEBIZEN_HOST_DATA_DIR:-/var/lib/webizen-host}}\"\nBACKUP_DIR=\"$DATA_DIR/backups\"\nmkdir -p \"$BACKUP_DIR\"\n\
         /usr/local/bin/webizen-hostd --check-config \"$DATA_DIR\"\nSTAMP=\"$(date -u +%Y%m%dT%H%M%SZ)\"\n\
         tar -czf \"$BACKUP_DIR/webizen-state-$STAMP.tar.gz\" -C \"$DATA_DIR\" host_state.cbor-ld journal.q42j\n"
    );

    let cloud_init = format!(
        "#cloud-config\n# Webizen-Host Cloud-Init First-Boot Provisioning — {domain} ({did})\npackage_update: true\n\
         packages:\n  - nftables\n  - caddy\n  - ca-certificates\n  - curl\n\
         users:\n  - name: webizen\n    system: true\n    homedir: /var/lib/webizen-host\n    shell: /usr/sbin/nologin\n\
         runcmd:\n  - [ bash, -lc, \"/var/lib/webizen-host/deploy/install-vps.sh\" ]\n"
    );

    let build_deb = format!(
        "#!/usr/bin/env bash\n# Webizen-Host Debian Package Builder (dpkg-deb) — {domain}\nset -euo pipefail\n\
         PKG_ROOT=\"${{1:-./build/webizen-hostd_0.1.0_amd64}}\"\n\
         install -d -m 0755 \"$PKG_ROOT/DEBIAN\" \"$PKG_ROOT/usr/local/bin\" \"$PKG_ROOT/lib/systemd/system\" \"$PKG_ROOT/etc\"\n\
         cat > \"$PKG_ROOT/DEBIAN/control\" <<'EOF'\nPackage: webizen-hostd\nVersion: 0.1.0\nSection: net\nPriority: optional\nArchitecture: amd64\n\
         Maintainer: Webizen Human-Centric Stewardship <steward@{domain}>\nDescription: Webizen Human-Centric Personal & Family Host Daemon\nEOF\n\
         dpkg-deb --build \"$PKG_ROOT\"\n"
    );

    for (path, content) in [
        (&systemd_unit_path, &systemd_unit),
        (&nftables_conf_path, &nftables_conf),
        (&install_script_path, &install_script),
        (&caddyfile_path, &caddyfile),
        (&containerfile_path, &containerfile),
        (&backup_cron_path, &backup_cron),
        (&cloud_init_path, &cloud_init),
        (&build_deb_path, &build_deb),
    ] {
        validate_human_centric_nomenclature(content).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        fs::write(path, content)?;
    }

    Ok(VpsDeploymentPaths {
        deploy_dir,
        systemd_unit_path,
        nftables_conf_path,
        install_script_path,
        caddyfile_path,
        containerfile_path,
        backup_cron_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn host_persistent_state_cbor_ld_roundtrip_and_tamper_rejection() {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("qualia_vps_deploy_test_{}_{}", std::process::id(), id));
        let _ = fs::create_dir_all(&dir);
        let state_path = dir.join("host_state.cbor-ld");

        let mut state = HostPersistentState::default();
        state.custom_dns_records.push(CustomDnsRecord {
            name: "_dmarc.civics.au".to_string(),
            rr_type: "TXT".to_string(),
            ttl: 600,
            value: "v=DMARC1; p=reject".to_string(),
        });
        state.save_cbor_ld(&state_path).unwrap();

        let raw = fs::read(&state_path).unwrap();
        assert_eq!(&raw[0..3], &[0xD9, 0x05, 0x01]);
        assert_eq!(HostPersistentState::load_cbor_ld(&state_path).unwrap(), state);

        let mut tampered = raw.clone();
        tampered[10] ^= 0x01;
        fs::write(&state_path, &tampered).unwrap();
        assert_eq!(HostPersistentState::load_cbor_ld(&state_path).unwrap_err().kind(), ErrorKind::InvalidData);

        let paths = write_linux_vps_deployment_bundle(&dir, &state).unwrap();
        let unit = fs::read_to_string(&paths.systemd_unit_path).unwrap();
        let nft = fs::read_to_string(&paths.nftables_conf_path).unwrap();
        let sh = fs::read_to_string(&paths.install_script_path).unwrap();
        let caddy = fs::read_to_string(&paths.caddyfile_path).unwrap();
        let container = fs::read_to_string(&paths.containerfile_path).unwrap();
        let cron = fs::read_to_string(&paths.backup_cron_path).unwrap();
        let cloud_init = fs::read_to_string(paths.deploy_dir.join("cloud-init.yaml")).unwrap();
        let build_deb = fs::read_to_string(paths.deploy_dir.join("build-deb.sh")).unwrap();

        assert!(unit.contains("ExecStart=/usr/local/bin/webizen-hostd --serve /var/lib/webizen-host") && unit.contains("MemoryMax=512M"));
        assert!(nft.contains("tcp dport 8080 drop") && nft.contains("udp dport 53 accept"));
        assert!(sh.contains("systemctl enable --now webizen-hostd.service"));
        assert!(caddy.contains("reverse_proxy 127.0.0.1:4242") && caddy.contains("default-src 'self'; script-src 'none'"));
        assert!(container.contains("ENTRYPOINT [\"/usr/local/bin/webizen-hostd\""));
        assert!(cron.contains("webizen-hostd --check-config") && cron.contains("host_state.cbor-ld journal.q42j"));
        assert!(cloud_init.starts_with("#cloud-config") && build_deb.contains("dpkg-deb --build"));

        for doc in [&unit, &nft, &sh, &caddy, &container, &cron, &cloud_init, &build_deb] {
            assert!(validate_human_centric_nomenclature(doc).is_ok());
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
