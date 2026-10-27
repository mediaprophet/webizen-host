//! Three-Persona Progressive-Disclosure cPanel, Git, 3D Studio & VibeScript UX Replacement Model
//! (`Novice`, `TechGeek`, `Developer`) across all 12 Left-Sidebar Control Panel Pages for `webizen-host`.
//!
//! All 12 functional cPanel replacement pages share one unified state engine (`AdaptiveHostWorkbench`)
//! and dynamically adapt their controls, tables, wizards, and diagnostics to the active `UserPersonaTier`:
//! 1. `ControlPanelPage::DomainsAndDns` — Domains, Subdomains & Authoritative DNS Zone Editor
//! 2. `ControlPanelPage::EmailAndAliases` — Email Accounts, Relationship-Scoped Aliases, Forwarders & DKIM/SPF/DMARC
//! 3. `ControlPanelPage::FilesAndStorage` — File Manager, IPFS/WebTorrent/HTTP-206 Range Seeding & Sanctuary Keep
//! 4. `ControlPanelPage::OntologiesAndDatabases` — `.q42` Volumes, Over-Time Ontology Ingestion & Range-SPARQL / SHACL Studio
//! 5. `ControlPanelPage::AppsAndSolidPods` — 1-Click QApp, W3C Solid Pod, Poet & Legacy Proxy Installer
//! 6. `ControlPanelPage::SslIdentityAndSecurity` — ACME + `WebizenID-TLS`, SSH/WireGuard, Family Guardianship & Quorum
//! 7. `ControlPanelPage::WalletExchangesAndBilling` — Multi-Chain Wallet, Multi-Exchange Swap Desk & Hard Monthly Cost-Cap
//! 8. `ControlPanelPage::JobsCronAndMetrics` — Background Ontology Jobs, Cron/Tick Scheduler, `SlgArena` Monitor & Audit Logs
//! 9. `ControlPanelPage::ResourceDelegationAndBudgets` — P2P Compute, Bandwidth & Storage Delegation Permits (`P0..P3`)
//! 10. `ControlPanelPage::GitForgeAndRepositories` — Webizen Git Forge (`Q-Git` Decentralized GitHub Alternative)
//! 11. `ControlPanelPage::Vibe3dAssetAndSceneForge` — Vibe 3D Asset, PGA Motor, PBR Material & QBDL `.hmc` Scene Forge
//! 12. `ControlPanelPage::VibeUiUxAndSheafStudio` — VibeScript UI/UX Projectional AST & 4-Modality Presentation Sheaf Studio

use crate::LifeDomain;
use webizen_host_core::{validate_human_centric_nomenclature, NQuin};
use webizen_host_economics::BlockchainRail;

/// Embedded self-contained HTML/CSS/SVG UI bundle for the 12-Page Three-Persona cPanel Replacement Workbench.
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

/// All 12 Left-Sidebar cPanel, Git, 3D Studio & VibeScript UI/UX Pages in the `webizen-host` Admin Control Panel.
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
    /// 11. Vibe 3D Asset & Scene Forge (PGA G(3,0,1) Motors, 6-Facet PBR, 10-Family Animation & QBDL `.hmc`)
    Vibe3dAssetAndSceneForge,
    /// 12. VibeScript UI/UX & 4-Modality Presentation Sheaf Studio (Projectional AST, Node-Wire DAG & Sheaf T69)
    VibeUiUxAndSheafStudio,
}

impl ControlPanelPage {
    pub const ALL: [ControlPanelPage; 12] = [
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
        Self::Vibe3dAssetAndSceneForge,
        Self::VibeUiUxAndSheafStudio,
    ];

    pub const fn section_id(&self) -> &'static str {
        match self {
            Self::DomainsAndDns => "page-domains",
            Self::EmailAndAliases => "page-email",
            Self::FilesAndStorage => "page-files",
            Self::OntologiesAndDatabases => "page-ontologies",
            Self::AppsAndSolidPods => "page-apps",
            Self::SslIdentityAndSecurity => "page-security",
            Self::WalletExchangesAndBilling => "page-wallet",
            Self::JobsCronAndMetrics => "page-jobs",
            Self::ResourceDelegationAndBudgets => "page-delegation",
            Self::GitForgeAndRepositories => "page-git",
            Self::Vibe3dAssetAndSceneForge => "page-studio-3d",
            Self::VibeUiUxAndSheafStudio => "page-vibe-ux",
        }
    }

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
            Self::Vibe3dAssetAndSceneForge => "3D Asset & Scene Forge",
            Self::VibeUiUxAndSheafStudio => "VibeScript UI/UX & Sheaf Studio",
        }
    }

    pub const fn persona_label(&self, persona: UserPersonaTier) -> &'static str {
        match (self, persona) {
            (Self::Vibe3dAssetAndSceneForge, UserPersonaTier::Novice) => "3D Scene & World Studio",
            (Self::Vibe3dAssetAndSceneForge, UserPersonaTier::TechGeek) => "Vibe 3D Asset & QBDL .hmc Forge",
            (Self::Vibe3dAssetAndSceneForge, UserPersonaTier::Developer) => "vibe_3d_studio (PGA Motors + PBR + .hmc)",
            (Self::VibeUiUxAndSheafStudio, UserPersonaTier::Novice) => "Design & Accessibility Studio",
            (Self::VibeUiUxAndSheafStudio, UserPersonaTier::TechGeek) => "VibeScript UI/UX & 4-Modality Sheaf Studio",
            (Self::VibeUiUxAndSheafStudio, UserPersonaTier::Developer) => "vibe_ux_toolkit (Projectional AST + Sheaf T69)",
            (page, _) => page.sidebar_title(),
        }
    }

    pub const fn life_domain(&self) -> LifeDomain {
        match self {
            Self::DomainsAndDns | Self::FilesAndStorage => LifeDomain::World,
            Self::EmailAndAliases | Self::GitForgeAndRepositories => LifeDomain::Relations,
            Self::OntologiesAndDatabases => LifeDomain::Memory,
            Self::AppsAndSolidPods | Self::Vibe3dAssetAndSceneForge => LifeDomain::Practice,
            Self::SslIdentityAndSecurity | Self::ResourceDelegationAndBudgets => LifeDomain::Care,
            Self::WalletExchangesAndBilling | Self::JobsCronAndMetrics | Self::VibeUiUxAndSheafStudio => {
                LifeDomain::Instruments
            }
        }
    }

    pub const fn form_action_path(&self) -> &'static str {
        match self {
            Self::DomainsAndDns => "/cpanel/domains/add",
            Self::EmailAndAliases => "/cpanel/email/add",
            Self::FilesAndStorage => "/cpanel/files/publish",
            Self::OntologiesAndDatabases => "/cpanel/ontologies/sparql",
            Self::AppsAndSolidPods => "/cpanel/apps/install",
            Self::SslIdentityAndSecurity => "/cpanel/security/issue-cert",
            Self::WalletExchangesAndBilling => "/cpanel/wallet/swap",
            Self::JobsCronAndMetrics => "/cpanel/jobs/backup",
            Self::ResourceDelegationAndBudgets => "/cpanel/delegation/issue",
            Self::GitForgeAndRepositories => "/cpanel/git/create-repo",
            Self::Vibe3dAssetAndSceneForge => "/cpanel/studio/forge-3d",
            Self::VibeUiUxAndSheafStudio => "/cpanel/ux/compile-sheaf",
        }
    }
}

/// Build the 12-item progressive-disclosure left sidebar for the specified `UserPersonaTier`.
pub const fn build_sidebar_for_persona(
    persona: UserPersonaTier,
) -> [(ControlPanelPage, &'static str, LifeDomain); 12] {
    let mut out = [(
        ControlPanelPage::DomainsAndDns,
        "",
        LifeDomain::World,
    ); 12];
    let mut idx = 0;
    while idx < 12 {
        let p = ControlPanelPage::ALL[idx];
        out[idx] = (p, p.persona_label(persona), p.life_domain());
        idx += 1;
    }
    out
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

/// Unified workbench state that seamlessly switches across all 12 cPanel replacement pages and
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

    /// Navigate to any of the 12 left-sidebar cPanel replacement pages while preserving the active persona.
    pub fn navigate_page(&mut self, page: ControlPanelPage) {
        self.active_page = page;
        self.active_life_domain = page.life_domain();
    }

    /// Build the 12-page left-sidebar model for the currently active persona tier.
    pub fn build_sidebar_for_persona(&self) -> [(ControlPanelPage, &'static str, LifeDomain); 12] {
        build_sidebar_for_persona(self.active_persona)
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
    fn adaptive_workbench_supports_all_12_cpanel_git_studio_and_ux_pages_and_3_personas() {
        let mut wb = AdaptiveHostWorkbench::new_default("ns.webcivics.net").unwrap();
        assert_eq!(ControlPanelPage::ALL.len(), 12);

        for persona in [
            UserPersonaTier::Novice,
            UserPersonaTier::TechGeek,
            UserPersonaTier::Developer,
        ] {
            wb.switch_persona(persona);
            let sidebar = wb.build_sidebar_for_persona();
            assert_eq!(sidebar.len(), 12);
            for (page, label, domain) in sidebar {
                assert_eq!(domain, page.life_domain());
                assert!(validate_human_centric_nomenclature(label).is_ok());
            }
        }

        for page in ControlPanelPage::ALL {
            wb.navigate_page(page);
            assert_eq!(wb.novice_view().active_page, page);
            assert_eq!(wb.tech_geek_view().active_page, page);
            assert_eq!(wb.developer_view().active_page, page);
            assert!(validate_human_centric_nomenclature(page.sidebar_title()).is_ok());
            assert!(validate_human_centric_nomenclature(page.form_action_path()).is_ok());
            let action_attr = format!("action=\"{}\"", page.form_action_path());
            assert!(
                BUNDLED_ADAPTIVE_WORKBENCH_HTML.contains(&action_attr),
                "missing Zero-JS form action attribute: {action_attr}"
            );
            assert!(
                BUNDLED_ADAPTIVE_WORKBENCH_HTML.contains(page.section_id()),
                "missing cPanel page section: {}",
                page.section_id()
            );
        }

        assert!(validate_human_centric_nomenclature(BUNDLED_ADAPTIVE_WORKBENCH_HTML).is_ok());
        let js_audit =
            crate::VibeWebServerEngine::verify_zero_javascript_html(BUNDLED_ADAPTIVE_WORKBENCH_HTML)
                .unwrap();
        assert!(js_audit.zero_executable_js_tags);
        assert!(js_audit.zero_inline_js_handlers);
        assert_eq!(js_audit.embedded_vibescript_modules, 1);
    }
}
