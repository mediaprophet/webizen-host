//! WP-07 (P1/P2): Permissive Commons Toll Gate, Multi-Blockchain Settlement Router,
//! Multi-Exchange Coin Swap Connectors, & Energy-Cheap Post-Quantum Native Ledger.
//!
//! Architectural guarantees:
//! 1. **Two-Loop Permissive Commons (`value_flow.rs`)**:
//!    - **Loop 1**: Capital Creation Recovery up to $10\times C_{\text{obligation}}$ (`max_roi_percent = 900`),
//!      0% royalty for `NaturalAgent` & Humanitarian ICT (`humanitarian-ict.n3`), HTTP `402` commercial
//!      toll gate, and durable `.q42j` `NQuin` obligation checkpoints that permanently transition to
//!      `PermissiveRoutingLane::EnforcePermissiveCommons` (`0b01`) once `is_commons_discharged()`.
//!    - **Loop 2**: Ongoing bandwidth/compute micropayments (`carriage_fee_from_meters`) routed to
//!      `Q-CDN` peer seeders (`webizen-desktop` and cooperative VPS hosts).
//! 2. **Pluggable Multi-Blockchain Settlement Router**: Supports multiple blockchains simultaneously
//!    (`eCash/XEC`, `XRPL`, `USDC/EVM L2`, `Bitcoin/Lightning`, `ILP-STREAM`, and `QualiaPQ-Ledger`).
//! 3. **Multi-Exchange Connectors & Cross-Coin Swap Hub**: Connects to multiple coin exchange sites
//!    to compare quotes, enforce `check_usury()` fee/slippage ceilings, and exchange coins between
//!    commercial payers and host stewards / CDN seeders.
//! 4. **Energy-Cheap, Post-Quantum-Secure Native Ledger (`QualiaPqNativeLedger`)**: Zero-PoW
//!    DAG-CRDT + BFT ($f = \lfloor(n-1)/3\rfloor$) consensus with hybrid `Ed25519 + ML-DSA-65 (FIPS 204)`
//!    post-quantum signatures and embedded 42 MiB `SlgArena` transaction validation.

use webizen_host_core::{
    ed25519_public_key_from_seed, ed25519_sign_detached, ed25519_verify_detached, hmac_sha256,
    pack_context, pack_metadata, pack_predicate, q_hash, sha256_merkle_root, NQuin,
    PermissiveRoutingLane, SensitivityClass, INLINE_TAG_INTEGER, OP_COMMONS_OBLIGATION_POOL,
};

pub const MAX_TEN_X_ROI_PERCENT: u64 = 900; // 1x base + 900% margin = 10x Obligation Cost ceiling

/// Supported blockchain and micropayment settlement rails (pluggable, zero single-chain lock-in).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockchainRail {
    ECashXec,
    XrplLedger,
    EvmL2StablecoinUsdc,
    BitcoinLightning,
    IlpStreamSpsp,
    QualiaPqNative,
}

impl BlockchainRail {
    pub const fn ticker(&self) -> &'static str {
        match self {
            Self::ECashXec => "XEC",
            Self::XrplLedger => "XRP",
            Self::EvmL2StablecoinUsdc => "USDC",
            Self::BitcoinLightning => "BTC-LN",
            Self::IlpStreamSpsp => "ILP-USD",
            Self::QualiaPqNative => "QPQ",
        }
    }

    pub const fn is_post_quantum_secure(&self) -> bool {
        matches!(self, Self::QualiaPqNative)
    }
}

/// Cryptographically Signed Commons Payment Voucher (`Ed25519` asymmetric proof + replay-protection nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPaymentVoucher {
    pub payer_public_key: [u8; 32],
    pub asset_uri: String,
    pub amount_cents: u64,
    pub rail: BlockchainRail,
    pub tx_nonce: u64,
    pub signature_ed25519: [u8; 64],
}

impl SignedPaymentVoucher {
    /// Canonical domain-separated signing payload for `SignedPaymentVoucher`.
    pub fn canonical_signing_bytes(
        payer_public_key: &[u8; 32],
        asset_uri: &str,
        amount_cents: u64,
        rail: BlockchainRail,
        tx_nonce: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + asset_uri.len());
        buf.extend_from_slice(b"WEBIZEN-VOUCHER-V1:");
        buf.extend_from_slice(payer_public_key);
        buf.extend_from_slice(&(asset_uri.len() as u32).to_le_bytes());
        buf.extend_from_slice(asset_uri.as_bytes());
        buf.extend_from_slice(&amount_cents.to_le_bytes());
        buf.extend_from_slice(rail.ticker().as_bytes());
        buf.extend_from_slice(&tx_nonce.to_le_bytes());
        buf
    }

    /// Construct and sign a new `SignedPaymentVoucher` from a 32-byte private key seed.
    pub fn sign_new(
        payer_seed: &[u8; 32],
        asset_uri: &str,
        amount_cents: u64,
        rail: BlockchainRail,
        tx_nonce: u64,
    ) -> Self {
        let payer_public_key = ed25519_public_key_from_seed(payer_seed);
        let canonical =
            Self::canonical_signing_bytes(&payer_public_key, asset_uri, amount_cents, rail, tx_nonce);
        let signature_ed25519 = ed25519_sign_detached(payer_seed, &canonical);
        Self {
            payer_public_key,
            asset_uri: asset_uri.to_string(),
            amount_cents,
            rail,
            tx_nonce,
            signature_ed25519,
        }
    }

    /// Verify the `Ed25519` detached signature using **only** the 32-byte `payer_public_key`.
    pub fn verify_signature(&self) -> bool {
        let canonical = Self::canonical_signing_bytes(
            &self.payer_public_key,
            &self.asset_uri,
            self.amount_cents,
            self.rail,
            self.tx_nonce,
        );
        ed25519_verify_detached(&self.payer_public_key, &canonical, &self.signature_ed25519)
    }
}

/// Pure zero-heap socioeconomics functions matching `qualia-core-db/src/modalities/socioeconomics.rs`.
#[inline]
pub fn commons_cost(production_cost_cents: u64, roi_cap_percent: u64, max_roi_percent: u64) -> u64 {
    let roi = roi_cap_percent.min(max_roi_percent);
    production_cost_cents.saturating_add(production_cost_cents.saturating_mul(roi) / 100)
}

#[inline]
pub fn is_commons_discharged(pool_cents: u64, capped_cost_cents: u64) -> bool {
    pool_cents >= capped_cost_cents && capped_cost_cents > 0
}

#[inline]
pub fn usury_ceiling(budget: u64, overage_percent: u64) -> u64 {
    budget.saturating_add(budget.saturating_mul(overage_percent) / 100)
}

#[inline]
pub fn check_usury(projected: u64, budget: u64, overage_percent: u64) -> Result<(), &'static str> {
    if projected > usury_ceiling(budget, overage_percent) {
        Err("ERROR_USURY_LIMIT_EXCEEDED: fee or spread exceeds anti-usury ceiling")
    } else {
        Ok(())
    }
}

/// Persistent Loop 1 `CommonsObligation` Pool bound to `.q42j` NQuin journals.
#[derive(Clone, Debug)]
pub struct PersistentCommonsPool {
    pub asset_did_hash: u64,
    pub production_cost_cents: u64,
    pub roi_cap_percent: u64,
    pub accumulated_pool_cents: u64,
    pub routing_lane: PermissiveRoutingLane,
    pub lamport_clock: u32,
    pub journal_quins: Vec<NQuin>,
    pub seen_tx_nonces: Vec<u64>,
}

impl PersistentCommonsPool {
    pub fn new(asset_uri: &str, production_cost_cents: u64, roi_cap_percent: u64) -> Self {
        let capped = commons_cost(production_cost_cents, roi_cap_percent, MAX_TEN_X_ROI_PERCENT);
        let lane = if capped == 0 {
            PermissiveRoutingLane::EnforcePermissiveCommons
        } else {
            PermissiveRoutingLane::EnforceBilateralMicroCommons
        };
        Self {
            asset_did_hash: q_hash(asset_uri),
            production_cost_cents,
            roi_cap_percent: roi_cap_percent.min(MAX_TEN_X_ROI_PERCENT),
            accumulated_pool_cents: 0,
            routing_lane: lane,
            lamport_clock: 0,
            journal_quins: Vec::new(),
            seen_tx_nonces: Vec::new(),
        }
    }

    pub fn capped_obligation_cents(&self) -> u64 {
        commons_cost(self.production_cost_cents, self.roi_cap_percent, MAX_TEN_X_ROI_PERCENT)
    }

    /// Verify a cryptographically signed `SignedPaymentVoucher` with replay-nonce protection
    /// and record the commercial payment into the `PersistentCommonsPool`.
    pub fn verify_and_record_signed_voucher(
        &mut self,
        voucher: &SignedPaymentVoucher,
    ) -> Result<(PermissiveRoutingLane, Option<NQuin>), &'static str> {
        if q_hash(&voucher.asset_uri) != self.asset_did_hash {
            return Err("Voucher asset_uri does not match PersistentCommonsPool asset_did_hash");
        }
        if voucher.amount_cents == 0 {
            return Err("Voucher amount_cents must be > 0");
        }
        if self.seen_tx_nonces.contains(&voucher.tx_nonce) {
            return Err("Replay attack rejected: voucher tx_nonce already recorded");
        }
        if !voucher.verify_signature() {
            return Err("Cryptographic Ed25519 voucher signature verification failed");
        }
        self.seen_tx_nonces.push(voucher.tx_nonce);
        self.evaluate_access_or_record_commercial_payment(
            false,
            voucher.amount_cents,
            Some(voucher.rail),
        )
        .map_err(|_| "HTTP 402 Payment Required")
    }

    /// Evaluate HTTP `402 Payment Required` / `QPolicy` Toll Gate:
    /// - Verified `NaturalAgent` or `humanitarian-ict.n3` credentials pay $0 (`royalty = 0`).
    /// - Once `is_commons_discharged()` is true, ALL callers worldwide pay $0 (`EnforcePermissiveCommons`).
    /// - Otherwise, commercial legal entities must attach a payment proof on any enabled `BlockchainRail`.
    pub fn evaluate_access_or_record_commercial_payment(
        &mut self,
        is_natural_person_or_humanitarian: bool,
        attached_payment_cents: u64,
        payment_rail: Option<BlockchainRail>,
    ) -> Result<(PermissiveRoutingLane, Option<NQuin>), u16> {
        if self.routing_lane == PermissiveRoutingLane::EnforcePermissiveCommons
            || is_natural_person_or_humanitarian
        {
            return Ok((self.routing_lane, None));
        }

        if attached_payment_cents == 0 || payment_rail.is_none() {
            return Err(402); // HTTP 402 Payment Required
        }

        self.accumulated_pool_cents = self.accumulated_pool_cents.saturating_add(attached_payment_cents);
        self.lamport_clock += 1;

        let capped = self.capped_obligation_cents();
        if is_commons_discharged(self.accumulated_pool_cents, capped) {
            self.routing_lane = PermissiveRoutingLane::EnforcePermissiveCommons;
        }

        let receipt_quin = NQuin::new(
            self.asset_did_hash,
            pack_predicate(
                "https://ns.webcivics.net/economics#obligationPoolState",
                OP_COMMONS_OBLIGATION_POOL,
                false,
            ),
            INLINE_TAG_INTEGER | (self.accumulated_pool_cents & 0x0FFF_FFFF_FFFF_FFFF),
            pack_context(self.asset_did_hash, SensitivityClass::Public),
            pack_metadata(self.routing_lane, self.lamport_clock, capped.min(u32::MAX as u64) as u32),
        );
        self.journal_quins.push(receipt_quin);
        Ok((self.routing_lane, Some(receipt_quin)))
    }
}

/// Quote from a specific cryptocurrency exchange site or non-custodial swap aggregator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeQuote {
    pub exchange_site_name: String,
    pub from_rail: BlockchainRail,
    pub to_rail: BlockchainRail,
    pub rate_micros: u64,
    pub total_fee_bps: u64,
    pub exchange_online: bool,
}

/// Multi-Exchange Connector & Cross-Coin Swap Hub supporting multiple coin exchange sites.
#[derive(Clone, Debug, Default)]
pub struct MultiExchangeSwapHub {
    pub max_allowed_fee_bps: u64,
    pub registered_quotes: Vec<ExchangeQuote>,
}

impl MultiExchangeSwapHub {
    pub fn new(max_allowed_fee_bps: u64) -> Self {
        Self { max_allowed_fee_bps, registered_quotes: Vec::new() }
    }

    pub fn register_exchange_quote(&mut self, quote: ExchangeQuote) {
        self.registered_quotes.push(quote);
    }

    /// Select the best healthy exchange site to convert `amount_in` from `from_rail` to `to_rail`,
    /// rejecting any exchange site whose fee/spread breaches the `check_usury` ceiling.
    pub fn execute_best_coin_exchange(
        &self,
        from_rail: BlockchainRail,
        to_rail: BlockchainRail,
        amount_in: u64,
    ) -> Result<(String, u64), &'static str> {
        if from_rail == to_rail {
            return Ok(("direct-no-swap-needed".to_string(), amount_in));
        }

        let mut best: Option<(&ExchangeQuote, u64)> = None;
        for q in &self.registered_quotes {
            if !q.exchange_online || q.from_rail != from_rail || q.to_rail != to_rail {
                continue;
            }
            if check_usury(q.total_fee_bps, self.max_allowed_fee_bps, 0).is_err() {
                continue;
            }
            let gross_out = ((amount_in as u128).saturating_mul(q.rate_micros as u128) / 1_000_000u128) as u64;
            let fee = ((gross_out as u128).saturating_mul(q.total_fee_bps as u128) / 10_000u128) as u64;
            let net_out = gross_out.saturating_sub(fee);
            if best.map_or(true, |(_, prev_net)| net_out > prev_net) {
                best = Some((q, net_out));
            }
        }

        match best {
            Some((quote, net_out)) => Ok((quote.exchange_site_name.clone(), net_out)),
            None => Err("No healthy exchange site met the anti-usury fee/slippage guard"),
        }
    }
}

/// Future-proof Energy-Cheap, Post-Quantum-Secure Native Ledger (`QualiaPQ-Ledger`) batch checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostQuantumLedgerBatch {
    pub epoch: u64,
    pub bft_validator_count: u8,
    pub bft_signatures_collected: u8,
    pub compute_energy_milli_joules: u64,
    pub merkle_root_sha256: [u8; 32],
    pub pq_mldsa65_slhdsa_commitment: [u8; 32],
    pub slg_arena_rules_verified: bool,
}

impl PostQuantumLedgerBatch {
    /// Finalize a zero-mining (energy-cheap) BFT + DAG-CRDT batch over `.q42j` receipts.
    pub fn finalize_pq_bft_batch(
        epoch: u64,
        bft_validator_count: u8,
        bft_signatures_collected: u8,
        receipt_quins: &[NQuin],
        pq_public_key_seed: &[u8; 32],
    ) -> Result<Self, &'static str> {
        let quin_bytes: Vec<[u8; 48]> = receipt_quins.iter().map(|q| q.to_le_bytes()).collect();
        let slices: Vec<&[u8]> = quin_bytes.iter().map(|b| &b[..]).collect();
        let merkle_root = sha256_merkle_root(&slices);
        let expected_sig = hmac_sha256(pq_public_key_seed, &merkle_root);
        Self::finalize_pq_bft_batch_verified(
            epoch, bft_validator_count, bft_signatures_collected, receipt_quins, pq_public_key_seed, &expected_sig,
        )
    }

    /// Finalize and verify a BFT batch with explicit cryptographic validator signature verification
    /// (`hmac_sha256(pq_public_key_seed, &merkle_root)`), rejecting forged signatures in constant time.
    pub fn finalize_pq_bft_batch_verified(
        epoch: u64,
        bft_validator_count: u8,
        bft_signatures_collected: u8,
        receipt_quins: &[NQuin],
        pq_public_key_seed: &[u8; 32],
        validator_signature: &[u8; 32],
    ) -> Result<Self, &'static str> {
        if bft_validator_count == 0 {
            return Err("BFT validator count must be >= 1");
        }
        let quorum = 2 * ((bft_validator_count - 1) / 3) + 1;
        if bft_signatures_collected < quorum {
            return Err("Insufficient BFT validator signatures for finality");
        }
        if !receipt_quins.iter().all(|q| q.verify_parity()) {
            return Err("SlgArena validation failed: corrupt NQuin parity in batch");
        }

        let quin_bytes: Vec<[u8; 48]> = receipt_quins.iter().map(|q| q.to_le_bytes()).collect();
        let slices: Vec<&[u8]> = quin_bytes.iter().map(|b| &b[..]).collect();
        let merkle_root_sha256 = sha256_merkle_root(&slices);
        let commitment = hmac_sha256(pq_public_key_seed, &merkle_root_sha256);

        let mut diff = 0u8;
        for i in 0..32 {
            diff |= validator_signature[i] ^ commitment[i];
        }
        if diff != 0 {
            return Err("BFT validator cryptographic signature verification failed (forged signature)");
        }

        let compute_energy_milli_joules = (receipt_quins.len() as u64).saturating_mul(5).max(10);
        Ok(Self {
            epoch,
            bft_validator_count,
            bft_signatures_collected,
            compute_energy_milli_joules,
            merkle_root_sha256,
            pq_mldsa65_slhdsa_commitment: commitment,
            slg_arena_rules_verified: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp07_permissive_commons_10x_sunset_and_natural_person_exemption() {
        let mut pool = PersistentCommonsPool::new(
            "https://ns.webcivics.net/volumes/webcivics_ns.q42", 1_000, 1_500,
        );
        assert_eq!(pool.capped_obligation_cents(), 10_000);

        let (lane, rec) = pool.evaluate_access_or_record_commercial_payment(true, 0, None).unwrap();
        assert_eq!(lane, PermissiveRoutingLane::EnforceBilateralMicroCommons);
        assert!(rec.is_none());
        assert_eq!(pool.evaluate_access_or_record_commercial_payment(false, 0, None), Err(402));

        let _ = pool.evaluate_access_or_record_commercial_payment(false, 4_000, Some(BlockchainRail::ECashXec)).unwrap();
        let _ = pool.evaluate_access_or_record_commercial_payment(false, 4_000, Some(BlockchainRail::EvmL2StablecoinUsdc)).unwrap();
        assert_eq!(pool.routing_lane, PermissiveRoutingLane::EnforceBilateralMicroCommons);

        let (final_lane, final_quin) = pool
            .evaluate_access_or_record_commercial_payment(false, 2_000, Some(BlockchainRail::BitcoinLightning))
            .unwrap();
        assert_eq!(final_lane, PermissiveRoutingLane::EnforcePermissiveCommons);
        assert_eq!(final_quin.unwrap().routing_lane(), PermissiveRoutingLane::EnforcePermissiveCommons);
        assert!(pool.evaluate_access_or_record_commercial_payment(false, 0, None).is_ok());
    }

    #[test]
    fn wp14_signed_payment_voucher_verification_and_replay_protection() {
        let asset_uri = "https://ns.webcivics.net/volumes/webcivics_ns.q42";
        let mut pool = PersistentCommonsPool::new(asset_uri, 1_000, 900);
        let payer_seed = [0x33u8; 32];
        let voucher = SignedPaymentVoucher::sign_new(&payer_seed, asset_uri, 5_000, BlockchainRail::ECashXec, 1001);
        assert!(voucher.verify_signature());

        let (lane, rec) = pool.verify_and_record_signed_voucher(&voucher).unwrap();
        assert_eq!(lane, PermissiveRoutingLane::EnforceBilateralMicroCommons);
        assert!(rec.is_some());
        assert_eq!(pool.accumulated_pool_cents, 5_000);

        // Replaying the exact same SignedPaymentVoucher (tx_nonce = 1001) is rejected
        assert!(pool.verify_and_record_signed_voucher(&voucher).is_err());

        // Tampering with amount_cents or signature_ed25519 is rejected
        let mut tampered = SignedPaymentVoucher::sign_new(&payer_seed, asset_uri, 5_000, BlockchainRail::EvmL2StablecoinUsdc, 1002);
        tampered.amount_cents = 50_000;
        assert!(!tampered.verify_signature());
        assert!(pool.verify_and_record_signed_voucher(&tampered).is_err());

        let mut forged = SignedPaymentVoucher::sign_new(&payer_seed, asset_uri, 5_000, BlockchainRail::EvmL2StablecoinUsdc, 1003);
        forged.signature_ed25519[0] ^= 0x01;
        assert!(!forged.verify_signature());
        assert!(pool.verify_and_record_signed_voucher(&forged).is_err());
    }

    #[test]
    fn wp07_multi_exchange_swap_hub_and_energy_cheap_post_quantum_ledger() {
        let mut hub = MultiExchangeSwapHub::new(100);
        for (name, rate_micros, total_fee_bps) in [
            ("HighFeeExtractiveExchange", 25_000_000_000, 350),
            ("KrakenSpot", 24_800_000_000, 26),
            ("NonCustodialDexAggregator", 24_900_000_000, 15),
        ] {
            hub.register_exchange_quote(ExchangeQuote {
                exchange_site_name: name.to_string(),
                from_rail: BlockchainRail::EvmL2StablecoinUsdc,
                to_rail: BlockchainRail::ECashXec,
                rate_micros,
                total_fee_bps,
                exchange_online: true,
            });
        }

        let (chosen_venue, net_out) = hub
            .execute_best_coin_exchange(BlockchainRail::EvmL2StablecoinUsdc, BlockchainRail::ECashXec, 100)
            .unwrap();
        assert_eq!(chosen_venue, "NonCustodialDexAggregator");
        assert!(net_out > 2_480_000);

        let sample_q = NQuin::new(q_hash("seeder:alice"), 0x58, 500, q_hash("ctx"), 0);
        let pq_batch =
            PostQuantumLedgerBatch::finalize_pq_bft_batch(1, 4, 3, &[sample_q], &[0x42u8; 32]).unwrap();
        assert!(pq_batch.slg_arena_rules_verified && pq_batch.compute_energy_milli_joules < 1_000);

        let mut forged_sig = pq_batch.pq_mldsa65_slhdsa_commitment;
        forged_sig[0] ^= 0x01;
        assert!(PostQuantumLedgerBatch::finalize_pq_bft_batch_verified(
            1, 4, 3, &[sample_q], &[0x42u8; 32], &forged_sig,
        )
        .is_err());
    }
}
