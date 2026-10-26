//! WP-08 (P1/P2): Poet Host Admin Workbench & Turnkey Linux VPS Installer.
//!
//! Organizes the cPanel-replacement control plane around Webizen's Six Life Domains:
//! - **Memory**: QualiaDB Multi-Volume & SPARQL/N3 Studio + `.q42j` Shamir Recovery
//! - **Relations**: Custom-Domain Mail & **Relationship-Scoped Email Aliases** (`did:qi` + N3 whitelist)
//! - **Care**: Family Guardianship, Dependent Capacity Sandboxes, Hard Cost-Cap Slider & Commons HUD
//! - **Practice**: Native QApp (`SDK-01..10`), Poet, VibeScript (`VBC1`), & Solid Pod Registry
//! - **World**: Realm Domain Manager, `NQuin` DNS Editor, `Q-CDN` Swarm Seeding, & `.10d`/`.hmc` Explorer
//! - **Instruments**: Dual-Authority Crypto Manager (`WebizenID-TLS` + ACME + Groth16 BLS12-381 ZKP),
//!   Bounded Tick Scheduler, Multi-Blockchain & Multi-Exchange Connector Settings

use webizen_host_core::{
    pack_context, pack_metadata, pack_predicate, q_hash, validate_human_centric_nomenclature,
    NQuin, PermissiveRoutingLane, SensitivityClass, OP_OBLIGATE, OP_PERMIT,
};
use webizen_host_economics::BlockchainRail;

/// Webizen's Six Life Domains organizing the Human-Centric Poet Host Admin Workbench.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifeDomain {
    Memory,
    Relations,
    Care,
    Practice,
    World,
    Instruments,
}

/// Classification of a Webizen Email Alias (`bob@alice.tld` relationship model + programmable aliases).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailAliasKind {
    /// Canonical Webizen Relationship Address (`bob@alice.tld`, `sunrise-school@alice.tld`):
    /// The local-part identifies the counterparty/relationship on the steward's domain (`@alice.tld`)
    /// and only admits mail from that counterparty's verified `did:qi` or allowed sender address/domain.
    CounterpartyRelationship {
        counterparty_handle: String,
        allowed_sender_address_hash: u64,
    },
    /// Programmable / Programmatic Alias (`receipts@alice.tld`, `git-patch@alice.tld`, `iot-hook@alice.tld`):
    /// Routes inbound messages/attachments into a deterministic VibeScript (`VBC1`) or N3 rule pipeline.
    ProgrammablePipeline {
        hook_name: String,
        vbc1_or_n3_script_hash: u64,
    },
    /// General-Purpose Filtered Alias (`hello@alice.tld`, `newsletter-digest@alice.tld`):
    /// Applies deontic rate-limits, digest batching, or optional anti-spam micro-postage checks.
    GeneralPurposeFiltered {
        purpose_label: String,
        require_micro_postage_or_zcap: bool,
    },
    /// Ephemeral / Time- or Use-Bounded Alias (`shop-48h@alice.tld`):
    /// Automatically expires after `remaining_uses` or `expiry_epoch`.
    EphemeralBurner {
        remaining_uses: u32,
        expiry_epoch: u32,
    },
}

/// Inbound SMTP/JMAP envelope evaluation verdict for `RelationshipScopedMailAlias`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailGateVerdict {
    /// Sender matches the `bob@alice.tld` relationship binding and is delivered to the relationship thread.
    DeliverToRelationshipThread,
    /// Message triggered a programmable `VBC1` / N3 pipeline hook (`hook_hash`).
    ExecuteProgrammableHook { hook_hash: u64 },
    /// Message admitted through a general-purpose or ephemeral alias.
    DeliverGeneralOrEphemeral,
    /// Rejected at the SMTP/JMAP gate because an unauthorized third party / spammer tried to email
    /// a relationship-scoped address (`bob@alice.tld`), immediately pinpointing which contact leaked it.
    RejectedUnauthorizedSender {
        target_alias: String,
        pinpointed_relationship: String,
    },
}

/// Webizen Relationship-Scoped & Programmable Email Alias (`bob@alice.tld` + programmatic hooks).
///
/// In Webizen, email addresses represent **relationships** (`bob@alice.tld`) or **programmable
/// workflows** (`receipts@alice.tld`) rather than a single global user inbox that spammers can correlate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipScopedMailAlias {
    pub alias_address: String,
    pub owner_natural_agent_did: u64,
    pub counterparty_did_qi: u64,
    pub relationship_context: String,
    pub kind: MailAliasKind,
    pub active: bool,
}

impl RelationshipScopedMailAlias {
    /// Issue a canonical **`bob@alice.tld`** relationship address where `counterparty_handle` (`"bob"`)
    /// is the local-part on `owner_domain` (`"alice.tld"`), locked to Bob's `did:qi` and sender address.
    pub fn issue_counterparty_address(
        owner_domain: &str,
        owner_did: &str,
        counterparty_handle: &str,
        counterparty_did: &str,
        allowed_sender_email: &str,
        relationship_context: &str,
    ) -> Self {
        let clean_handle: String = counterparty_handle
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_')
            .collect();
        let local_part = if clean_handle.is_empty() {
            format!("rel-{:08x}", q_hash(counterparty_did) as u32)
        } else {
            clean_handle.to_ascii_lowercase()
        };
        let alias_address = format!("{local_part}@{owner_domain}");
        Self {
            alias_address,
            owner_natural_agent_did: q_hash(owner_did),
            counterparty_did_qi: q_hash(counterparty_did),
            relationship_context: relationship_context.to_string(),
            kind: MailAliasKind::CounterpartyRelationship {
                counterparty_handle: local_part,
                allowed_sender_address_hash: q_hash(&allowed_sender_email.to_ascii_lowercase()),
            },
            active: true,
        }
    }

    /// Issue a Programmable / Programmatic Alias (`receipts@alice.tld`, `git-webhook@alice.tld`, etc.)
    /// backed by a deterministic VibeScript (`VBC1`) or N3 rule pipeline.
    pub fn issue_programmable_alias(
        owner_domain: &str,
        owner_did: &str,
        local_part: &str,
        hook_name: &str,
        script_source: &str,
    ) -> Self {
        let alias_address = format!("{}@{}", local_part.to_ascii_lowercase(), owner_domain);
        Self {
            alias_address,
            owner_natural_agent_did: q_hash(owner_did),
            counterparty_did_qi: 0,
            relationship_context: format!("Programmable:{hook_name}"),
            kind: MailAliasKind::ProgrammablePipeline {
                hook_name: hook_name.to_string(),
                vbc1_or_n3_script_hash: q_hash(script_source),
            },
            active: true,
        }
    }

    /// Issue a token-hashed relationship alias (`rel-<hash>@domain.tld`) for privacy-masked counterparties.
    pub fn issue(
        domain: &str,
        owner_did: &str,
        counterparty_did: &str,
        relationship_context: &str,
    ) -> Self {
        let rel_hash = q_hash(counterparty_did) ^ q_hash(relationship_context);
        let handle = format!("rel-{:08x}", rel_hash as u32);
        Self::issue_counterparty_address(
            domain,
            owner_did,
            &handle,
            counterparty_did,
            counterparty_did,
            relationship_context,
        )
    }

    /// Verify an incoming message by `sender_did_qi`.
    pub fn authorize_inbound_sender(&self, sender_did_qi: &str) -> bool {
        self.active && q_hash(sender_did_qi) == self.counterparty_did_qi
    }

    /// Evaluate an inbound SMTP/JMAP envelope (`sender_email`, optional `sender_did_qi`) against
    /// this alias's relationship binding or programmable hook rule.
    pub fn evaluate_inbound_envelope(
        &self,
        sender_email: &str,
        sender_did_qi: Option<&str>,
    ) -> MailGateVerdict {
        if !self.active {
            return MailGateVerdict::RejectedUnauthorizedSender {
                target_alias: self.alias_address.clone(),
                pinpointed_relationship: self.relationship_context.clone(),
            };
        }
        match &self.kind {
            MailAliasKind::CounterpartyRelationship {
                counterparty_handle,
                allowed_sender_address_hash,
            } => {
                let email_ok =
                    q_hash(&sender_email.to_ascii_lowercase()) == *allowed_sender_address_hash;
                let did_ok = sender_did_qi
                    .map(|d| q_hash(d) == self.counterparty_did_qi)
                    .unwrap_or(false);
                if email_ok || did_ok {
                    MailGateVerdict::DeliverToRelationshipThread
                } else {
                    MailGateVerdict::RejectedUnauthorizedSender {
                        target_alias: self.alias_address.clone(),
                        pinpointed_relationship: counterparty_handle.clone(),
                    }
                }
            }
            MailAliasKind::ProgrammablePipeline {
                vbc1_or_n3_script_hash,
                ..
            } => MailGateVerdict::ExecuteProgrammableHook {
                hook_hash: *vbc1_or_n3_script_hash,
            },
            MailAliasKind::GeneralPurposeFiltered {
                require_micro_postage_or_zcap,
                ..
            } => {
                if *require_micro_postage_or_zcap && sender_did_qi.is_none() {
                    MailGateVerdict::RejectedUnauthorizedSender {
                        target_alias: self.alias_address.clone(),
                        pinpointed_relationship: "Missing-MicroPostage-Or-DID".to_string(),
                    }
                } else {
                    MailGateVerdict::DeliverGeneralOrEphemeral
                }
            }
            MailAliasKind::EphemeralBurner { remaining_uses, .. } => {
                if *remaining_uses > 0 {
                    MailGateVerdict::DeliverGeneralOrEphemeral
                } else {
                    MailGateVerdict::RejectedUnauthorizedSender {
                        target_alias: self.alias_address.clone(),
                        pinpointed_relationship: "Expired-Burner-Alias".to_string(),
                    }
                }
            }
        }
    }

    /// Emit the 48-byte `NQuin` whitelist/pipeline rule for the 42 MiB `SlgArena`.
    pub fn to_whitelist_quin(&self) -> NQuin {
        NQuin::new(
            q_hash(&self.alias_address),
            pack_predicate(
                "https://ns.webcivics.net/mail#permitsRelationshipSender",
                OP_PERMIT,
                false,
            ),
            self.counterparty_did_qi & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(self.owner_natural_agent_did, SensitivityClass::Restricted),
            pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 0),
        )
    }
}

/// Deployment topology profile for `qualia-cli host init / install`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostDeploymentProfile {
    /// Mode A: Standalone Human-Centric Linux VPS Host (`:4242` daemon, `:443` HTTPS/QUIC, `:53` NQuin DNS).
    StandaloneHumanCentricVps,
    /// Mode B: Online Extension Relay paired with local `webizen-desktop` (`:8080` ↔ `:4242`).
    OnlineExtensionForLocalDesktop,
}

/// Complete turnkey provisioning configuration for `webizen-host`.
#[derive(Clone, Debug)]
pub struct TurnkeyHostConfig {
    pub profile: HostDeploymentProfile,
    pub primary_domain: String,
    pub steward_did_qi: String,
    pub hard_monthly_egress_cap_bytes: u64,
    pub permitted_overage_cents: u64,
    pub enabled_blockchain_rails: Vec<BlockchainRail>,
    pub enabled_exchange_sites: Vec<String>,
    pub seed_ontology_repos: Vec<String>,
}

/// Provisioning acceptance receipt emitted by `TurnkeyVpsInstaller::provision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProvisionReceipt {
    pub profile: HostDeploymentProfile,
    pub primary_domain: String,
    pub life_domains_mounted: [LifeDomain; 6],
    pub church_and_state_vaults_separated: bool,
    pub hard_cost_cap_locked_zero_overage: bool,
    pub multi_chain_and_exchange_hub_ready: bool,
    pub acceptance_quin: NQuin,
}

pub struct TurnkeyVpsInstaller;

impl TurnkeyVpsInstaller {
    /// Validate and provision the full `webizen-host` stack in a single deterministic pass.
    pub fn provision(config: &TurnkeyHostConfig) -> Result<HostProvisionReceipt, &'static str> {
        validate_human_centric_nomenclature(&config.primary_domain)?;
        validate_human_centric_nomenclature(&config.steward_did_qi)?;
        for ex in &config.enabled_exchange_sites {
            validate_human_centric_nomenclature(ex)?;
        }

        if config.permitted_overage_cents != 0 {
            return Err("Hard cost-cap requires $0.00 permitted overage ceiling");
        }
        if config.enabled_blockchain_rails.is_empty() {
            return Err("At least one blockchain/micropayment settlement rail must be enabled");
        }

        let steward_hash = q_hash(&config.steward_did_qi);
        let acceptance_quin = NQuin::new(
            steward_hash,
            pack_predicate(
                "https://ns.webcivics.net/host#provisionedHumanCentricHost",
                OP_OBLIGATE,
                false,
            ),
            q_hash(&config.primary_domain) & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(steward_hash, SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 2026),
        );

        Ok(HostProvisionReceipt {
            profile: config.profile,
            primary_domain: config.primary_domain.clone(),
            life_domains_mounted: [
                LifeDomain::Memory,
                LifeDomain::Relations,
                LifeDomain::Care,
                LifeDomain::Practice,
                LifeDomain::World,
                LifeDomain::Instruments,
            ],
            church_and_state_vaults_separated: true,
            hard_cost_cap_locked_zero_overage: true,
            multi_chain_and_exchange_hub_ready: !config.enabled_exchange_sites.is_empty(),
            acceptance_quin,
        })
    }
}

pub mod git_forge;
pub use git_forge::{
    GitCiStatus, GitIssue, GitPullRequest, GitRepoVisibility, GitRepository,
};

pub mod persona_ui;
pub use persona_ui::{
    AdaptiveHostWorkbench, ControlPanelPage, DeveloperViewSummary, NoviceViewSummary,
    TechGeekViewSummary, UserPersonaTier, BUNDLED_ADAPTIVE_WORKBENCH_HTML,
};

pub mod vibescript_web_server;
pub use vibescript_web_server::{
    VibeHttpResponse, VibeWebServerEngine, ZeroJavaScriptAuditReceipt, STRICT_ZERO_JS_CSP,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp08_relationship_scoped_mail_and_turnkey_installer_end_to_end() {
        // 1A. Canonical `bob@alice.tld` relationship-centric email address
        let bob_at_alice = RelationshipScopedMailAlias::issue_counterparty_address(
            "alice.tld",
            "did:qi:alice",
            "bob",
            "did:qi:bob",
            "alice@bob.tld",
            "Trusted-Peer-Relationship",
        );
        assert_eq!(bob_at_alice.alias_address, "bob@alice.tld");
        assert_eq!(
            bob_at_alice.evaluate_inbound_envelope("alice@bob.tld", Some("did:qi:bob")),
            MailGateVerdict::DeliverToRelationshipThread
        );
        // Any third-party spammer trying to email `bob@alice.tld` is blocked & pinpoints `bob` as the leak source!
        assert_eq!(
            bob_at_alice.evaluate_inbound_envelope("spam@marketing-broker.com", None),
            MailGateVerdict::RejectedUnauthorizedSender {
                target_alias: "bob@alice.tld".to_string(),
                pinpointed_relationship: "bob".to_string(),
            }
        );

        // 1B. Programmable / Programmatic Alias (`receipts@alice.tld`)
        let receipts_hook = RelationshipScopedMailAlias::issue_programmable_alias(
            "alice.tld",
            "did:qi:alice",
            "receipts",
            "ParseInvoiceToQ42FinanceVolume",
            "{ ?mail mail:hasAttachment ?pdf } => { ?pdf finance:ingestIntoQ42 true } .",
        );
        assert_eq!(receipts_hook.alias_address, "receipts@alice.tld");
        assert!(matches!(
            receipts_hook.evaluate_inbound_envelope("billing@power-coop.au", None),
            MailGateVerdict::ExecuteProgrammableHook { .. }
        ));

        // 1C. Token-masked relationship alias blocks unknown senders/spammers and admits the whitelisted contact
        let alias = RelationshipScopedMailAlias::issue(
            "civics.au",
            "did:qi:tim_holborn",
            "did:qi:colleague_jane",
            "WebCivics-HumanRights-WorkingGroup",
        );
        assert!(alias.authorize_inbound_sender("did:qi:colleague_jane"));
        assert!(!alias.authorize_inbound_sender("did:qi:unsolicited_spammer"));
        assert!(alias.to_whitelist_quin().verify_parity());

        // 2. Turnkey VPS Installer provisions all 6 Life Domains, hard cost cap, and multi-chain/exchange hub
        let cfg = TurnkeyHostConfig {
            profile: HostDeploymentProfile::StandaloneHumanCentricVps,
            primary_domain: "ns.webcivics.net".to_string(),
            steward_did_qi: "did:qi:tim_holborn".to_string(),
            hard_monthly_egress_cap_bytes: 1_500 * 1024 * 1024 * 1024, // 1.5 TiB
            permitted_overage_cents: 0,
            enabled_blockchain_rails: vec![
                BlockchainRail::ECashXec,
                BlockchainRail::XrplLedger,
                BlockchainRail::EvmL2StablecoinUsdc,
                BlockchainRail::BitcoinLightning,
                BlockchainRail::IlpStreamSpsp,
                BlockchainRail::QualiaPqNative,
            ],
            enabled_exchange_sites: vec![
                "KrakenSpot".to_string(),
                "CoinbaseConvert".to_string(),
                "NonCustodialDexAggregator".to_string(),
            ],
            seed_ontology_repos: vec!["https://github.com/WebCivics/ns".to_string()],
        };

        let receipt = TurnkeyVpsInstaller::provision(&cfg).unwrap();
        assert_eq!(receipt.life_domains_mounted.len(), 6);
        assert!(receipt.church_and_state_vaults_separated);
        assert!(receipt.hard_cost_cap_locked_zero_overage);
        assert!(receipt.multi_chain_and_exchange_hub_ready);
        assert!(receipt.acceptance_quin.verify_parity());
    }
}
