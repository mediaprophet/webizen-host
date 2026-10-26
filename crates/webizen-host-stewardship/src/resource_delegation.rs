//! Social-Web & P2P Resource Delegation Permits, Budgets & Priority Rules (`Compute`, `Bandwidth`, `Storage`).
//!
//! Enables a `webizen-host` steward or cooperative to delegate bounded **Compute**, **Bandwidth**,
//! and **Storage** permits to social-graph peers, family members, cooperative partners, or federations,
//! with priority-based budget shedding (`P0`..`P3`) and 48-byte `NQuin` deontic encoding (`OP_PERMIT = 0x11`,
//! `OP_FORBID = 0x12`, `DEFEATER_BIT`).

use webizen_host_core::{
    pack_context, pack_metadata, pack_predicate, q_hash, NQuin, PermissiveRoutingLane,
    SensitivityClass, DEFEATER_BIT, OP_FORBID, OP_PERMIT,
};

/// The three delegatable host/P2P resource classes (`net/qdnf/economics/meters.rs` alignment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DelegatedResourceKind {
    /// CPU/GPU sandbox cycles (`VBC1` ops, swarm compute jobs, incremental ontology build chunks).
    Compute = 1,
    /// Origin and relay network transfer (GiB egress, TURN/MASQUE relay, Q-CDN seeding bandwidth).
    Bandwidth = 2,
    /// Persistent volume custody (`.q42` SuperBlock pinning, W3C Solid Pod quota, Git LFS / `.hmc` storage).
    Storage = 3,
}

/// Social-graph and relationship priority tier governing how delegated permits behave as the host's
/// overall budget approaches saturation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DelegationPriorityTier {
    /// Tier 0 (Highest): Family Guardianship, Dependents & Humanitarian Emergency (`<= 100%` budget saturation).
    P0GuardianshipAndEmergency = 0,
    /// Tier 1 (High): Trusted Social-Web Friends, Co-Stewards & Reciprocal Co-op Peers (`<= 95%` budget saturation).
    P1TrustedSocialAndCoopPeer = 1,
    /// Tier 2 (Standard): Federated Social-Web / ForgeFed Contributors & Commons Seeders (`<= 80%` budget saturation).
    P2FederatedCommonsPeer = 2,
    /// Tier 3 (Best-Effort): Anonymous / Public Guest Queries (`<= 50%` budget saturation before P2P offload).
    P3PublicBestEffort = 3,
}

impl DelegationPriorityTier {
    /// Maximum host budget utilization percentage (`0..=100`) at which this priority tier is still admitted
    /// on the host before automatic throttling or P2P swarm redirection kicks in.
    pub const fn max_host_budget_utilization_pct(&self) -> u8 {
        match self {
            Self::P0GuardianshipAndEmergency => 100,
            Self::P1TrustedSocialAndCoopPeer => 95,
            Self::P2FederatedCommonsPeer => 80,
            Self::P3PublicBestEffort => 50,
        }
    }
}

/// A cryptographically auditable permit delegating Compute, Bandwidth, or Storage to a peer or group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatedResourcePermit {
    pub grantor_did_hash: u64,
    pub grantee_did_hash: u64,
    pub resource_kind: DelegatedResourceKind,
    pub priority_tier: DelegationPriorityTier,
    pub max_units_per_epoch: u64,
    pub used_units_in_epoch: u64,
    pub expiry_epoch: u32,
    pub revoked_by_defeater: bool,
}

/// Verdict returned by the zero-heap `HostResourceBudgetController::evaluate_permit_zero_heap`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceDelegationVerdict {
    /// Request is admitted under the peer's delegated permit and priority tier.
    Admitted {
        remaining_peer_units: u64,
        remaining_host_pool_units: u64,
        priority_tier: DelegationPriorityTier,
    },
    /// Denied because an explicit `DEFEATER_BIT` revocation rule overrides the permit.
    DeniedRevokedByDefeater,
    /// Denied because the permit's temporal epoch has expired.
    DeniedPermitExpired,
    /// Denied because the peer exhausted their individual delegated quota (`max_units_per_epoch`).
    DeniedPeerQuotaExhausted,
    /// Shed/throttled because the host's overall resource budget utilization exceeded the threshold
    /// allowed for this peer's `DelegationPriorityTier` (e.g., P2 shed at >80% so P0/P1 stay protected).
    ShedByHostBudgetPriorityRule {
        current_utilization_pct: u8,
        tier_ceiling_pct: u8,
    },
}

impl DelegatedResourcePermit {
    pub fn issue(
        grantor_did: &str,
        grantee_did: &str,
        resource_kind: DelegatedResourceKind,
        priority_tier: DelegationPriorityTier,
        max_units_per_epoch: u64,
        expiry_epoch: u32,
    ) -> Self {
        Self {
            grantor_did_hash: q_hash(grantor_did),
            grantee_did_hash: q_hash(grantee_did),
            resource_kind,
            priority_tier,
            max_units_per_epoch,
            used_units_in_epoch: 0,
            expiry_epoch,
            revoked_by_defeater: false,
        }
    }

    /// Compile this resource delegation permit (or defeater revocation) into a 48-byte `NQuin`.
    pub fn to_deontic_quin(&self) -> NQuin {
        let pred_uri = match self.resource_kind {
            DelegatedResourceKind::Compute => "https://ns.webcivics.net/delegation#permitCompute",
            DelegatedResourceKind::Bandwidth => "https://ns.webcivics.net/delegation#permitBandwidth",
            DelegatedResourceKind::Storage => "https://ns.webcivics.net/delegation#permitStorage",
        };
        let opcode = if self.revoked_by_defeater {
            OP_FORBID
        } else {
            OP_PERMIT
        };
        let pred = pack_predicate(pred_uri, opcode, self.revoked_by_defeater);
        // Pack priority tier in bits 56..58 and quota in bits 0..55 of the 60-bit object payload
        let obj = ((self.priority_tier as u64) << 56)
            | (self.max_units_per_epoch & 0x00FF_FFFF_FFFF_FFFF);
        NQuin::new(
            self.grantee_did_hash,
            pred,
            obj,
            pack_context(self.grantor_did_hash, SensitivityClass::Restricted),
            pack_metadata(
                PermissiveRoutingLane::EnforceBilateralMicroCommons,
                1,
                self.expiry_epoch,
            ),
        )
    }
}

/// Host-wide budget controller for Compute, Bandwidth, and Storage that enforces both per-peer
/// delegated permits and priority-based load shedding (`P0`..`P3`) in zero heap memory.
#[derive(Clone, Copy, Debug)]
pub struct HostResourceBudgetPool {
    pub resource_kind: DelegatedResourceKind,
    pub total_epoch_budget_units: u64,
    pub consumed_epoch_units: u64,
}

impl HostResourceBudgetPool {
    pub const fn new(resource_kind: DelegatedResourceKind, total_epoch_budget_units: u64) -> Self {
        Self {
            resource_kind,
            total_epoch_budget_units,
            consumed_epoch_units: 0,
        }
    }

    /// Current utilization percentage (`0..=100`).
    #[inline]
    pub const fn utilization_pct(&self) -> u8 {
        if self.total_epoch_budget_units == 0 {
            return 100;
        }
        let pct = (self.consumed_epoch_units.saturating_mul(100)) / self.total_epoch_budget_units;
        if pct > 100 {
            100
        } else {
            pct as u8
        }
    }

    /// Zero-heap (`HotZeroHeap`) evaluation of a peer's resource request against both their
    /// `DelegatedResourcePermit` and the host's priority-tiered budget pool.
    #[inline]
    pub fn evaluate_and_consume_zero_heap(
        &mut self,
        permit: &mut DelegatedResourcePermit,
        requested_units: u64,
        current_epoch: u32,
    ) -> ResourceDelegationVerdict {
        if permit.revoked_by_defeater || (permit.to_deontic_quin().predicate & DEFEATER_BIT) != 0 {
            return ResourceDelegationVerdict::DeniedRevokedByDefeater;
        }
        if current_epoch > permit.expiry_epoch {
            return ResourceDelegationVerdict::DeniedPermitExpired;
        }
        if permit.used_units_in_epoch.saturating_add(requested_units) > permit.max_units_per_epoch {
            return ResourceDelegationVerdict::DeniedPeerQuotaExhausted;
        }

        let projected_host = self.consumed_epoch_units.saturating_add(requested_units);
        let projected_pct = if self.total_epoch_budget_units == 0 {
            100
        } else {
            ((projected_host.saturating_mul(100)) / self.total_epoch_budget_units).min(100) as u8
        };

        let tier_ceiling = permit.priority_tier.max_host_budget_utilization_pct();
        if projected_pct > tier_ceiling || projected_host > self.total_epoch_budget_units {
            return ResourceDelegationVerdict::ShedByHostBudgetPriorityRule {
                current_utilization_pct: projected_pct,
                tier_ceiling_pct: tier_ceiling,
            };
        }

        permit.used_units_in_epoch += requested_units;
        self.consumed_epoch_units = projected_host;

        ResourceDelegationVerdict::Admitted {
            remaining_peer_units: permit.max_units_per_epoch - permit.used_units_in_epoch,
            remaining_host_pool_units: self.total_epoch_budget_units - self.consumed_epoch_units,
            priority_tier: permit.priority_tier,
        }
    }
}
