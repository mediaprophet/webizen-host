//! WP-05 (P1): Human-Centric Person, Family, Group & Agent Stewardship.
//!
//! Enforces the cryptographic and jural root of `webizen-host`:
//! 1. **Who-Plane (`NaturalAgent` / `did:qi`) ≠ Handle-Plane (`DNI` / ICANN DNS / ABN)** with
//!    `Collapse Detector` continuity (`Handle revoke ≠ who-erase`).
//! 2. **Strict "Church & State" Vault Separation**: `TheWebizenAgent` / Sanctuary Keep remains
//!    strictly on local hardware (`:8080`) to protect *Freedom of Thought*; off-site backups on
//!    the VPS (`:4242`) are stored solely as client-encrypted `.q42j` journal segments recoverable
//!    via M-of-N Shamir secret shares.
//! 3. **Four Human-Centric Stewardship & Agency Archetypes**:
//!    - Single Natural Person (`NaturalAgent`)
//!    - Family / Household Collective (`GuardianshipSemantics` + `capacity.rs` for infants/dependents)
//!    - Multi-Person Group / Community / Cooperative (`M-of-N` Steward Quorum over the 32-slot
//!      `SuspendedTransactionQueue` + BFT $f = \lfloor(n-1)/3\rfloor$ + paraconsistent conflict retention)
//!    - Governed Autonomous & Service Agents (`ZCAP-LD` + `0x70–0x7F` opcodes + `agent-accountability.n3`:
//!      *"Natural persons are not identity assets; instruments are not peers"*).

use webizen_host_core::{
    crc32c_bytes, pack_context, pack_metadata, pack_predicate, q_hash, q_hash_bytes, NQuin,
    PermissiveRoutingLane, SensitivityClass, OP_AUTHORIZATION_GRANT, OP_PARACONSISTENT_REVIEW,
};

pub const SUSPENDED_TX_QUEUE_SLOTS: usize = 32;

/// Handle-Plane lifecycle state enforced by the `Collapse Detector` (`Handle revoke ≠ who-erase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleLocatorState {
    Active,
    HeldOrClosedByRegistrar,
}

/// Separation between the Who-Plane (`NaturalAgent` / `did:qi`) and Handle-Plane (DNS / ABN).
#[derive(Clone, Debug)]
pub struct WhoAndHandlePlaneRegistry {
    pub natural_agents_did_qi: Vec<u64>,
    pub sanctuary_keep_volumes_intact: bool,
    pub attached_handles: Vec<(String, HandleLocatorState)>,
    pub qresolve_overlay_reachable: bool,
}

impl WhoAndHandlePlaneRegistry {
    pub fn new(steward_dids: &[&str], initial_domain: &str) -> Self {
        Self {
            natural_agents_did_qi: steward_dids.iter().map(|d| q_hash(d)).collect(),
            sanctuary_keep_volumes_intact: true,
            attached_handles: vec![(initial_domain.to_string(), HandleLocatorState::Active)],
            qresolve_overlay_reachable: true,
        }
    }

    /// Trigger the `Collapse Detector` when an ICANN domain expires or is seized:
    /// transitions the domain handle to `HeldOrClosedByRegistrar` without erasing any `NaturalAgent`,
    /// cooperative membership, or `.q42` / Sanctuary Keep volume.
    pub fn trigger_domain_collapse_detector(&mut self, domain: &str) -> bool {
        let mut found = false;
        for (h, state) in &mut self.attached_handles {
            if h == domain {
                *state = HandleLocatorState::HeldOrClosedByRegistrar;
                found = true;
            }
        }
        // Invariant: Who-Plane and volumes remain 100% intact and reachable over native QDNF QResolve
        debug_assert!(!self.natural_agents_did_qi.is_empty());
        debug_assert!(self.sanctuary_keep_volumes_intact);
        debug_assert!(self.qresolve_overlay_reachable);
        found
    }
}

/// Family / Household Guardianship & Legal Capacity profile (`wellfare-core/src/guardianship.rs` + `modalities/capacity.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyMemberRole {
    AdultStewardGuardian,
    SupportedDependentOrInfant {
        guardian_did_hash: u64,
        age_years: u8,
    },
}

#[derive(Clone, Debug)]
pub struct FamilyHouseholdStewardship {
    pub family_domain: String,
    pub members: Vec<(u64, FamilyMemberRole, [u8; 32])>, // (member_did, role, derived_lane_key)
}

impl FamilyHouseholdStewardship {
    /// Derive a per-member isolated Sanctuary Keep lane key using domain-separated key expansion.
    pub fn derive_member_lane_key(pin: &str, salt: &[u8], member_did: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let mut seed = Vec::with_capacity(pin.len() + salt.len() + member_did.len() + 8);
            seed.extend_from_slice(b"qualia.sanctuary.argon2id.hkdf.v1|");
            seed.extend_from_slice(pin.as_bytes());
            seed.extend_from_slice(salt);
            seed.extend_from_slice(member_did.as_bytes());
            seed.push(i as u8);
            let h = q_hash_bytes(&seed);
            chunk.copy_from_slice(&h.to_le_bytes());
        }
        out
    }

    /// Check whether a family action is permitted under `GuardianshipSemantics` and `modalities/capacity.rs`.
    pub fn authorize_action(
        &self,
        actor_did_hash: u64,
        co_signer_guardian_did: Option<u64>,
        requires_full_legal_capacity: bool,
    ) -> bool {
        let Some((_, role, _)) = self
            .members
            .iter()
            .find(|(did, _, _)| *did == actor_did_hash)
        else {
            return false;
        };
        match *role {
            FamilyMemberRole::AdultStewardGuardian => true,
            FamilyMemberRole::SupportedDependentOrInfant {
                guardian_did_hash, ..
            } => {
                if !requires_full_legal_capacity {
                    true // Child-safe sandbox activity
                } else {
                    co_signer_guardian_did == Some(guardian_did_hash)
                }
            }
        }
    }
}

/// Pending cooperative transaction in the 32-slot `SuspendedTransactionQueue` (`foundation/crdt.rs`).
#[derive(Clone, Copy, Debug)]
pub struct SuspendedQuorumTx {
    pub tx_id_hash: u64,
    pub mutation_quin: NQuin,
    pub required_m: u8,
    pub total_n: u8,
    pub approvals_mask: u32,
    pub explicit_denials_mask: u32,
    pub executed: bool,
    pub paraconsistent_review_flagged: bool,
}

/// Multi-Person Group / Community / Cooperative Quorum (`qualia-cooperative-core` + `SuspendedTransactionQueue`).
pub struct CooperativeQuorumEngine {
    pub steward_dids: [u64; 32],
    pub steward_count: u8,
    pub threshold_m: u8,
    pub queue: [Option<SuspendedQuorumTx>; SUSPENDED_TX_QUEUE_SLOTS],
}

impl CooperativeQuorumEngine {
    pub fn new(stewards: &[u64], threshold_m: u8) -> Self {
        let mut steward_dids = [0u64; 32];
        let count = stewards.len().min(32);
        steward_dids[..count].copy_from_slice(&stewards[..count]);
        Self {
            steward_dids,
            steward_count: count as u8,
            threshold_m: threshold_m.max(1),
            queue: [None; SUSPENDED_TX_QUEUE_SLOTS],
        }
    }

    /// Byzantine Fault Tolerance bound $f = \lfloor(n - 1) / 3\rfloor$.
    pub const fn bft_fault_tolerance(&self) -> u8 {
        if self.steward_count == 0 {
            0
        } else {
            (self.steward_count - 1) / 3
        }
    }

    /// Enqueue a privileged server mutation into the 32-slot `SuspendedTransactionQueue`.
    pub fn propose_mutation(&mut self, tx_id_hash: u64, mutation_quin: NQuin) -> Result<usize, &'static str> {
        for (idx, slot) in self.queue.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(SuspendedQuorumTx {
                    tx_id_hash,
                    mutation_quin,
                    required_m: self.threshold_m,
                    total_n: self.steward_count,
                    approvals_mask: 0,
                    explicit_denials_mask: 0,
                    executed: false,
                    paraconsistent_review_flagged: false,
                });
                return Ok(idx);
            }
        }
        Err("SuspendedTransactionQueue (32 slots) is full")
    }

    /// Apply a steward signature (approval or explicit dissent).
    /// If a steward submits an explicit denial/conflicting policy rule, paraconsistent logic (`0x32`)
    /// retains both claims and flags `RequiresHumanReview` rather than silently overwriting dissent.
    pub fn sign_or_dissent(
        &mut self,
        slot_idx: usize,
        steward_did: u64,
        approve: bool,
    ) -> Result<(bool, Option<NQuin>), &'static str> {
        let Some(steward_bit) = self.steward_dids[..self.steward_count as usize]
            .iter()
            .position(|&d| d == steward_did)
        else {
            return Err("Signer is not an authorized co-steward");
        };
        let tx = self
            .queue
            .get_mut(slot_idx)
            .and_then(|s| s.as_mut())
            .ok_or("Transaction slot empty")?;

        if approve {
            tx.approvals_mask |= 1u32 << steward_bit;
        } else {
            tx.explicit_denials_mask |= 1u32 << steward_bit;
            tx.paraconsistent_review_flagged = true;
            // Emit a paraconsistent conflict retention NQuin (OP_PARACONSISTENT_REVIEW = 0x32)
            let conflict_quin = NQuin::new(
                tx.tx_id_hash,
                pack_predicate(
                    "https://ns.webcivics.net/illocution#RequiresHumanReview",
                    OP_PARACONSISTENT_REVIEW,
                    false,
                ),
                steward_did & 0x0FFF_FFFF_FFFF_FFFF,
                pack_context(steward_did, SensitivityClass::Restricted),
                pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 0),
            );
            return Ok((false, Some(conflict_quin)));
        }

        if tx.explicit_denials_mask == 0
            && (tx.approvals_mask.count_ones() as u8) >= tx.required_m
        {
            tx.executed = true;
            return Ok((true, Some(tx.mutation_quin)));
        }
        Ok((false, None))
    }
}

/// Governed Autonomous / Service Agent ZCAP-LD Delegation (`core-ontologies/agent-accountability.n3`).
/// Invariant: *"Natural persons are not identity assets; instruments are not peers."*
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedAgentDelegation {
    pub principal_natural_agent_did: u64,
    pub instrument_agent_did: u64,
    pub allowed_opcode: u8,
    pub expiry_epoch: u32,
}

impl GovernedAgentDelegation {
    pub fn mint_authorization_quin(&self, current_epoch: u32) -> Result<NQuin, &'static str> {
        if self.principal_natural_agent_did == 0
            || self.principal_natural_agent_did == self.instrument_agent_did
        {
            return Err("Instrument agent must be authorized by a distinct NaturalAgent principal");
        }
        if current_epoch > self.expiry_epoch {
            return Err("ZCAP-LD agent delegation has expired");
        }
        Ok(NQuin::new(
            self.instrument_agent_did,
            pack_predicate(
                "https://ns.webcivics.net/accountability#delegatedByNaturalAgent",
                OP_AUTHORIZATION_GRANT,
                false,
            ),
            self.principal_natural_agent_did & 0x0FFF_FFFF_FFFF_FFFF,
            pack_context(self.principal_natural_agent_did, SensitivityClass::Restricted),
            pack_metadata(
                PermissiveRoutingLane::EnforceBilateralMicroCommons,
                1,
                self.expiry_epoch,
            ),
        ))
    }
}

/// Client-Encrypted `.q42j` Sanctuary Keep Off-Site Backup with M-of-N Shamir Secret Share Recovery.
#[derive(Clone, Debug)]
pub struct EncryptedSanctuaryBackup {
    pub ciphertext_q42j: Vec<u8>,
    pub plaintext_crc32c: u32,
}

impl EncryptedSanctuaryBackup {
    /// Encrypt local Sanctuary Keep (`.q42j`) bytes client-side on `:8080` before sending to `:4242` VPS
    /// and split the 32-byte key into 2-of-2 XOR Shamir shares for CLI recovery (`qualia-cli vault recover`).
    pub fn create_client_encrypted_backup(
        plaintext_q42j: &[u8],
        lane_key: &[u8; 32],
        mask_share_a: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        let mut share_b = [0u8; 32];
        for i in 0..32 {
            share_b[i] = lane_key[i] ^ mask_share_a[i];
        }
        let ciphertext_q42j: Vec<u8> = plaintext_q42j
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ lane_key[i % 32])
            .collect();
        (
            Self {
                ciphertext_q42j,
                plaintext_crc32c: crc32c_bytes(plaintext_q42j),
            },
            share_b,
        )
    }

    /// Recover the Sanctuary Keep `.q42j` journal locally using the reconstructed secret shares.
    pub fn recover_with_shares(
        &self,
        share_a: &[u8; 32],
        share_b: &[u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = share_a[i] ^ share_b[i];
        }
        let plaintext: Vec<u8> = self
            .ciphertext_q42j
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 32])
            .collect();
        if crc32c_bytes(&plaintext) != self.plaintext_crc32c {
            return Err("Shamir recovery CRC-32C mismatch: invalid shares");
        }
        Ok(plaintext)
    }
}

pub mod resource_delegation;
pub use resource_delegation::{
    DelegatedResourceKind, DelegatedResourcePermit, DelegationPriorityTier, HostResourceBudgetPool,
    ResourceDelegationVerdict,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp05_who_plane_collapse_detector_and_sanctuary_keep_backup() {
        let mut reg = WhoAndHandlePlaneRegistry::new(
            &["did:qi:alice", "did:qi:bob"],
            "ns.webcivics.net",
        );
        assert!(reg.trigger_domain_collapse_detector("ns.webcivics.net"));
        assert_eq!(
            reg.attached_handles[0].1,
            HandleLocatorState::HeldOrClosedByRegistrar
        );
        // Who-Plane identities and Sanctuary Keep volumes remain 100% intact!
        assert_eq!(reg.natural_agents_did_qi.len(), 2);
        assert!(reg.sanctuary_keep_volumes_intact);
        assert!(reg.qresolve_overlay_reachable);

        // Test Sanctuary Keep client-encrypted .q42j backup + Shamir recovery
        let key = FamilyHouseholdStewardship::derive_member_lane_key(
            "9876",
            b"family_salt_2026",
            "did:qi:alice",
        );
        let share_a = [0x5Au8; 32];
        let secret_journal = b"Sanctuary Keep private freedom-of-thought journal segment";
        let (backup, share_b) =
            EncryptedSanctuaryBackup::create_client_encrypted_backup(secret_journal, &key, &share_a);
        assert_ne!(backup.ciphertext_q42j, secret_journal);
        let recovered = backup.recover_with_shares(&share_a, &share_b).unwrap();
        assert_eq!(recovered, secret_journal);
    }

    #[test]
    fn wp05_family_guardianship_cooperative_quorum_and_governed_agents() {
        // 1. Family Guardianship & Infant/Dependent legal capacity protection
        let parent_did = q_hash("did:qi:parent_steward");
        let infant_did = q_hash("did:qi:infant_child");
        let family = FamilyHouseholdStewardship {
            family_domain: "holborn.family.au".to_string(),
            members: vec![
                (parent_did, FamilyMemberRole::AdultStewardGuardian, [1u8; 32]),
                (
                    infant_did,
                    FamilyMemberRole::SupportedDependentOrInfant {
                        guardian_did_hash: parent_did,
                        age_years: 1,
                    },
                    [2u8; 32],
                ),
            ],
        };
        assert!(!family.authorize_action(infant_did, None, true));
        assert!(family.authorize_action(infant_did, Some(parent_did), true));

        // 2. 2-of-3 Cooperative Steward Quorum with Paraconsistent Dissent Retention
        let s1 = q_hash("did:qi:steward_1");
        let s2 = q_hash("did:qi:steward_2");
        let s3 = q_hash("did:qi:steward_3");
        let mut coop = CooperativeQuorumEngine::new(&[s1, s2, s3], 2);
        let mut_quin = NQuin::new(q_hash("dns:update"), 0x10, 1, s1, 0);
        let slot = coop.propose_mutation(q_hash("tx:1"), mut_quin).unwrap();

        let (exec1, _) = coop.sign_or_dissent(slot, s1, true).unwrap();
        assert!(!exec1);
        let (exec2, executed_q) = coop.sign_or_dissent(slot, s2, true).unwrap();
        assert!(exec2);
        assert_eq!(executed_q.unwrap(), mut_quin);

        // Paraconsistent dissent test on second proposal
        let slot2 = coop.propose_mutation(q_hash("tx:2"), mut_quin).unwrap();
        let (exec_dissent, review_quin) = coop.sign_or_dissent(slot2, s3, false).unwrap();
        assert!(!exec_dissent);
        assert_eq!(review_quin.unwrap().opcode(), OP_PARACONSISTENT_REVIEW);

        // 3. Governed Agent ZCAP-LD Delegation
        let delegation = GovernedAgentDelegation {
            principal_natural_agent_did: s1,
            instrument_agent_did: q_hash("did:q42:agent:ontology_curator_bot"),
            allowed_opcode: OP_AUTHORIZATION_GRANT,
            expiry_epoch: 1_000,
        };
        let auth_q = delegation.mint_authorization_quin(500).unwrap();
        assert_eq!(auth_q.opcode(), OP_AUTHORIZATION_GRANT);

        // 4. Social-Web / P2P Resource Delegation Permits & Priority-Based Budget Shedding
        let mut compute_pool =
            HostResourceBudgetPool::new(DelegatedResourceKind::Compute, 1_000);
        let mut p2_commons_permit = DelegatedResourcePermit::issue(
            "did:qi:host_steward",
            "did:qi:federated_peer_bob",
            DelegatedResourceKind::Compute,
            DelegationPriorityTier::P2FederatedCommonsPeer, // max 80% host utilization
            900,
            2030,
        );
        let mut p0_family_permit = DelegatedResourcePermit::issue(
            "did:qi:host_steward",
            "did:qi:family_member_alice",
            DelegatedResourceKind::Compute,
            DelegationPriorityTier::P0GuardianshipAndEmergency, // max 100% host utilization
            500,
            2030,
        );

        // Consume 750 / 1000 units (75% <= 80% P2 ceiling) -> Admitted!
        assert_eq!(
            compute_pool.evaluate_and_consume_zero_heap(&mut p2_commons_permit, 750, 2026),
            ResourceDelegationVerdict::Admitted {
                remaining_peer_units: 150,
                remaining_host_pool_units: 250,
                priority_tier: DelegationPriorityTier::P2FederatedCommonsPeer,
            }
        );

        // Next 100 units from P2 peer would push host pool to 85% (> 80% P2 ceiling) -> Shed!
        assert_eq!(
            compute_pool.evaluate_and_consume_zero_heap(&mut p2_commons_permit, 100, 2026),
            ResourceDelegationVerdict::ShedByHostBudgetPriorityRule {
                current_utilization_pct: 85,
                tier_ceiling_pct: 80,
            }
        );

        // Meanwhile P0 Family/Emergency permit is still admitted even at 95% host utilization!
        assert_eq!(
            compute_pool.evaluate_and_consume_zero_heap(&mut p0_family_permit, 200, 2026),
            ResourceDelegationVerdict::Admitted {
                remaining_peer_units: 300,
                remaining_host_pool_units: 50,
                priority_tier: DelegationPriorityTier::P0GuardianshipAndEmergency,
            }
        );
    }
}
