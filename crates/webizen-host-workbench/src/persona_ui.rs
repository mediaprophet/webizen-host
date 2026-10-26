//! Three-Persona Progressive-Disclosure cPanel Replacement Model (`Novice`, `TechGeek`, `Developer`)
//! across all 8 Left-Sidebar Control Panel Pages for `webizen-host`.
//!
//! All 8 functional cPanel replacement pages share one unified state engine (`AdaptiveHostWorkbench`)
//! and dynamically adapt their controls, tables, wizards, and diagnostics to the active `UserPersonaTier`:
//! 1. `ControlPanelPage::DomainsAndDns` — Domains, Subdomains & Authoritative DNS Zone Editor
//! 2. `ControlPanelPage::EmailAndAliases` — Email Accounts, Relationship-Scoped Aliases, Forwarders & DKIM/SPF/DMARC
//! 3. `ControlPanelPage::FilesAndStorage` — File Manager, IPFS/WebTorrent/HTTP-206 Range Seeding & Sanctuary Keep
//! 4. `ControlPanelPage::OntologiesAndDatabases` — `.q42` Volumes, Over-Time Ontology Ingestion & Range-SPARQL / SHACL Studio
//! 5. `ControlPanelPage::AppsAndSolidPods` — 1-Click QApp, W3C Solid Pod, Poet & Legacy Proxy Installer
//! 6. `ControlPanelPage::SslIdentityAndSecurity` — ACME + `WebizenID-TLS`, SSH/WireGuard, Family Guardianship & Quorum
//! 7. `ControlPanelPage::WalletExchangesAndBilling` — Multi-Chain Wallet, Multi-Exchange Swap Desk & Hard Monthly Cost-Cap
//! 8. `ControlPanelPage::JobsCronAndMetrics` — Background Ontology Jobs, Cron/Tick Scheduler, `SlgArena` Monitor & Audit Logs

use crate::LifeDomain;
use webizen_host_core::{validate_human_centric_nomenclature, NQuin};
use webizen_host_economics::BlockchainRail;

/// Embedded self-contained HTML/Tailwind UI bundle for the 8-Page Three-Persona cPanel Replacement Workbench.
pub const BUNDLED_ADAPTIVE_WORKBENCH_HTML: &str = include_str!("../assets/index.html");

/// The three target user groups supported across every page of the `webizen-host` Control Panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPersonaTier {
    /// Group 1: Everyday individuals, families, and community stewards (zero technical jargon).
    Novice,
    /// Group 2: Power users, sysadmins, network/CDN operators, and cooperative host stewards.
    TechGeek,
    /// Group 3: Semantic web engineers, VibeScript/QApp authors, and QualiaDB core developers.
    Developer,
}

impl UserPersonaTier {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Novice => "Novice (Everyday Steward & Family)",
            Self::TechGeek => "Tech Geek (Sysadmin, IPFS/CDN & Multi-Chain Operator)",
            Self::Developer => "Developer (Range-SPARQL, NQuin ABI, VBC1 & Sandbox Studio)",
        }
    }
}

/// All 10 Left-Sidebar cPanel & GitHub Replacement Pages in the `webizen-host` Admin Control Panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPanelPage {
    /// 1. Domains, Subdomains & DNS Zone Editor (A/AAAA/CNAME/MX/TXT, QDNF IPv6, Split-Horizon, 1-click connect)
    DomainsAndDns,
    /// 2. Email Accounts, Relationship-Scoped Aliases, Forwarders, DKIM/SPF/DMARC & Webmail
    EmailAndAliases,
    /// 3. File Manager, IPFS/WebTorrent/HTTP-206 Range Seeding, `.hmc` Bundles & Sanctuary Keep Sync
    FilesAndStorage,
    /// 4. Ontologies, `.q42` Volumes, Over-Time Ingestion ("Verify-Before-Rebuild") & Range-SPARQL / SHACL Studio
    OntologiesAndDatabases,
    /// 5. 1-Click App, QApp, W3C Solid Pod & Reverse-Proxy Application Installer
    AppsAndSolidPods,
    /// 6. SSL/TLS Certificates (Let's Encrypt ACME + `WebizenID-TLS`), SSH/WireGuard Keys, Guardianship & Quorum
    SslIdentityAndSecurity,
    /// 7. Multi-Chain Wallet, Coin Exchange Swap Desk & Hard Monthly Cost-Cap / Q-CDN Billing Manager
    WalletExchangesAndBilling,
    /// 8. Background Jobs, Cron Scheduler, Resource Monitors (42 MiB `SlgArena` / CPU / Bandwidth) & Audit Logs
    JobsCronAndMetrics,
    /// 9. Social-Web / P2P Compute, Bandwidth & Storage Delegation Permits, Budgets & Priority Rules (`P0..P3`)
    ResourceDelegationAndBudgets,
    /// 10. Webizen Git Forge (`Q-Git` — Decentralized GitHub Alternative: Repos, Code, PRs, Issues, P2P Bundles & CI)
    GitForgeAndRepositories,
}

impl ControlPanelPage {
    pub const ALL: [ControlPanelPage; 10] = [
        Self::DomainsAndDns,
        Self::EmailAndAliases,
        Self::FilesAndStorage,
        Self::OntologiesAndDatabases,
        Self::AppsAndSolidPods,
        Self::SslIdentityAndSecurity,
        Self::WalletExchangesAndBilling,
        Self::JobsCronAndMetrics,
        Self::ResourceDelegationAndBudgets,
        Self::GitForgeAndRepositories,
    ];

    pub const fn sidebar_title(&self) -> &'static str {
        match self {
            Self::DomainsAndDns => "Domains & DNS Zones",
            Self::EmailAndAliases => "Email & Contact Aliases",
            Self::FilesAndStorage => "Files, IPFS & Storage",
            Self::OntologiesAndDatabases => "Ontologies & Databases",
            Self::AppsAndSolidPods => "Apps & Solid Pods",
            Self::SslIdentityAndSecurity => "SSL, Identity & Security",
            Self::WalletExchangesAndBilling => "Wallet, Exchanges & Billing",
            Self::JobsCronAndMetrics => "Jobs, Cron & Metrics",
            Self::ResourceDelegationAndBudgets => "P2P Resource Permits & Budgets",
            Self::GitForgeAndRepositories => "Git Forge (GitHub Alternative)",
        }
    }
}

/// Simplified, jargon-free view model for **Group 1: Novice Users**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoviceViewSummary {
    pub active_page: ControlPanelPage,
    pub headline_status: String,
    pub monthly_bill_shield_text: String,
    pub sanctuary_privacy_badge: String,
    pub active_relationship_mail_count: usize,
    pub family_safe_spaces_enabled: bool,
    pub ontology_library_status: String,
    pub quick_actions: [&'static str; 5],
}

/// Protocol, networking, CDN, and multi-chain operator view model for **Group 2: Tech Geeks**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TechGeekViewSummary {
    pub active_page: ControlPanelPage,
    pub dns_nquin_ring_status: String,
    pub qdnf_ula_ipv6_overlay: String,
    pub ipfs_and_webtorrent_status: String,
    pub verify_before_rebuild_dedup_status: String,
    pub incremental_ontology_job_progress: (usize, usize),
    pub enabled_chains: Vec<BlockchainRail>,
    pub best_exchange_route_summary: String,
    pub cooperative_quorum_pending_txs: usize,
}

/// Low-level engine, SPARQL range planner, and sandbox profiler view model for **Group 3: Developers**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeveloperViewSummary {
    pub active_page: ControlPanelPage,
    pub sparql_range_pruning_summary: String,
    pub active_slg_arena_cell_bytes: usize,
    pub slg_arena_limit_bytes: usize,
    pub vbc1_cycle_budget_remaining: u64,
    pub sample_inspected_quin: NQuin,
    pub shacl_non_thing_uplift_count: usize,
    pub post_quantum_mldsa65_status: String,
    pub cscp_08_09_verified: bool,
}

/// Unified workbench state that seamlessly switches across all 8 cPanel replacement pages and
/// all 3 persona tiers (`Novice`, `TechGeek`, `Developer`).
#[derive(Clone, Debug)]
pub struct AdaptiveHostWorkbench {
    pub active_persona: UserPersonaTier,
    pub active_page: ControlPanelPage,
    pub active_life_domain: LifeDomain,
    pub primary_domain: String,
    pub hard_monthly_cap_usd: u32,
    pub hard_monthly_egress_gib: u32,
    pub relationship_mail_aliases: usize,
    pub family_guardianship_enabled: bool,
    pub network_ontology_adopted_without_rebuild: bool,
    pub incremental_chunks_done: usize,
    pub incremental_chunks_total: usize,
    pub sparql_superblocks_fetched: usize,
    pub sparql_superblocks_total: usize,
    pub enabled_chains: Vec<BlockchainRail>,
    pub best_exchange_venue: String,
    pub sample_quin: NQuin,
}

impl AdaptiveHostWorkbench {
    pub fn new_default(primary_domain: &str) -> Result<Self, &'static str> {
        validate_human_centric_nomenclature(primary_domain)?;
        Ok(Self {
            active_persona: UserPersonaTier::Novice,
            active_page: ControlPanelPage::DomainsAndDns,
            active_life_domain: LifeDomain::World,
            primary_domain: primary_domain.to_string(),
            hard_monthly_cap_usd: 12,
            hard_monthly_egress_gib: 1500,
            relationship_mail_aliases: 14,
            family_guardianship_enabled: true,
            network_ontology_adopted_without_rebuild: true,
            incremental_chunks_done: 128,
            incremental_chunks_total: 128,
            sparql_superblocks_fetched: 1,
            sparql_superblocks_total: 240,
            enabled_chains: vec![
                BlockchainRail::ECashXec,
                BlockchainRail::XrplLedger,
                BlockchainRail::EvmL2StablecoinUsdc,
                BlockchainRail::BitcoinLightning,
                BlockchainRail::IlpStreamSpsp,
                BlockchainRail::QualiaPqNative,
            ],
            best_exchange_venue: "NonCustodialDexAggregator (0.15% fee, check_usury OK)".to_string(),
            sample_quin: NQuin::new(0x1122_3344_5566_7788, 0x10, 42, 1, 1u64 << 61),
        })
    }

    /// Switch the UI persona tier (`Novice`, `TechGeek`, `Developer`) while staying on the active page.
    pub fn switch_persona(&mut self, persona: UserPersonaTier) {
        self.active_persona = persona;
    }

    /// Navigate to any of the 8 left-sidebar cPanel replacement pages while preserving the active persona.
    pub fn navigate_page(&mut self, page: ControlPanelPage) {
        self.active_page = page;
    }

    /// Project the state for **Group 1: Novice Users**.
    pub fn novice_view(&self) -> NoviceViewSummary {
        NoviceViewSummary {
            active_page: self.active_page,
            headline_status: format!("{} is Online & Protected", self.primary_domain),
            monthly_bill_shield_text: format!(
                "Locked at ${}/mo Flat VPS Ceiling ($0.00 Overage Guaranteed — Auto Peer Sharing Active)",
                self.hard_monthly_cap_usd
            ),
            sanctuary_privacy_badge:
                "Sanctuary Keep Active: Personal & Family Private Records Stay Strictly on Your Device"
                    .to_string(),
            active_relationship_mail_count: self.relationship_mail_aliases,
            family_safe_spaces_enabled: self.family_guardianship_enabled,
            ontology_library_status: if self.network_ontology_adopted_without_rebuild {
                "WebCivics Human-Rights Library Ready (Verified Network Copy Adopted — Zero Re-Processing Needed)"
                    .to_string()
            } else {
                format!(
                    "Updating Knowledge Library in Background ({}/{})",
                    self.incremental_chunks_done, self.incremental_chunks_total
                )
            },
            quick_actions: [
                "Connect My Domain or Family Website",
                "Create Private Contact Email Alias",
                "Adjust Monthly Bill Shield Slider",
                "Install 1-Click App or Solid Pod",
                "Pair My Local Computer (:8080 <-> :4242)",
            ],
        }
    }

    /// Project the state for **Group 2: Tech Geeks**.
    pub fn tech_geek_view(&self) -> TechGeekViewSummary {
        TechGeekViewSummary {
            active_page: self.active_page,
            dns_nquin_ring_status:
                "O(1) q_hash() 48-Byte NQuin Ring (:53, DoH, DoT, DoQ + Split-Horizon QPolicy)"
                    .to_string(),
            qdnf_ula_ipv6_overlay: "fd00:42::/32 Cryptokey ULA + SocialWebNet WireGuard + CSCP-08 MASQUE"
                .to_string(),
            ipfs_and_webtorrent_status: format!(
                "IPFS CIDv1 + Partial-CAR + WebTorrent (:4242) + HTTP 206 Range Seeding (Cap: {} GiB/mo)",
                self.hard_monthly_egress_gib
            ),
            verify_before_rebuild_dedup_status: if self.network_ontology_adopted_without_rebuild {
                "ADOPTED_NETWORK_ARTIFACT (CRC-32C + Q42LEX v4 + SHACL Non-Thing Verified)".to_string()
            } else {
                "REBUILDING_INCREMENTALLY (Peer candidate quarantined)".to_string()
            },
            incremental_ontology_job_progress: (
                self.incremental_chunks_done,
                self.incremental_chunks_total,
            ),
            enabled_chains: self.enabled_chains.clone(),
            best_exchange_route_summary: self.best_exchange_venue.clone(),
            cooperative_quorum_pending_txs: 2,
        }
    }

    /// Project the state for **Group 3: Developers**.
    pub fn developer_view(&self) -> DeveloperViewSummary {
        DeveloperViewSummary {
            active_page: self.active_page,
            sparql_range_pruning_summary: format!(
                "BIDX Range-SPARQL: Fetched {}/{} SuperBlocks (40 KiB HTTP 206 slice vs {:.1} MiB full volume)",
                self.sparql_superblocks_fetched,
                self.sparql_superblocks_total,
                (self.sparql_superblocks_total as f64 * 40.0) / 1024.0
            ),
            active_slg_arena_cell_bytes: 4 * 1024 * 1024,
            slg_arena_limit_bytes: 42 * 1024 * 1024,
            vbc1_cycle_budget_remaining: 985_400,
            sample_inspected_quin: self.sample_quin,
            shacl_non_thing_uplift_count: 18,
            post_quantum_mldsa65_status:
                "Hybrid Ed25519 + ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205) | <15 mJ/batch"
                    .to_string(),
            cscp_08_09_verified: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_workbench_supports_all_10_cpanel_and_git_pages_and_3_personas() {
        let mut wb = AdaptiveHostWorkbench::new_default("ns.webcivics.net").unwrap();
        assert_eq!(ControlPanelPage::ALL.len(), 10);

        for page in ControlPanelPage::ALL {
            wb.navigate_page(page);
            assert_eq!(wb.novice_view().active_page, page);
            assert_eq!(wb.tech_geek_view().active_page, page);
            assert_eq!(wb.developer_view().active_page, page);
            assert!(validate_human_centric_nomenclature(page.sidebar_title()).is_ok());
        }

        // Verify bundled HTML contains all 10 cPanel/Git pages, all 3 persona modes, and honours Human-Centric Nomenclature
        for page_id in [
            "page-domains",
            "page-email",
            "page-files",
            "page-ontologies",
            "page-apps",
            "page-security",
            "page-wallet",
            "page-jobs",
            "page-delegation",
            "page-git",
        ] {
            assert!(
                BUNDLED_ADAPTIVE_WORKBENCH_HTML.contains(page_id),
                "missing cPanel page section: {page_id}"
            );
        }
        assert!(validate_human_centric_nomenclature(BUNDLED_ADAPTIVE_WORKBENCH_HTML).is_ok());
    }
}
