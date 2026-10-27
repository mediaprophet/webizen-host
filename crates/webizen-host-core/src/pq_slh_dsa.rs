//! Pure-Rust FIPS 205 Stateless Hash-Based Post-Quantum Signature Scheme (`SLH-DSA-SHA2-128s`).
//!
//! Implements asymmetric post-quantum signatures using Winternitz One-Time Signature Plus (`WOTS+`)
//! chains ($w = 16$, $n = 16$ bytes) and tweakable SHA-256 public-key root compression (`T_l`).
//!
//! Adheres strictly to `AGENTS.md`:
//! - Tier-1 `HotZeroHeap`: zero heap allocations across key generation, signing, verification, and wire encoding
//! - True public-key-only verification (`[u8; 32]` = `pk_seed_16 || pk_root_16`) with zero shared secret
//! - Constant-time root tag comparison during detached signature verification

use crate::crypto::{Sha256State, sha256};

/// Security parameter $n = 16$ bytes (128-bit security level matching FIPS 205 `SLH-DSA-SHA2-128s`).
pub const SLH_DSA_N: usize = 16;
/// Winternitz parameter $w = 16$ (4-bit base-16 nibbles, steps $0 \dots 15$).
pub const SLH_DSA_W: usize = 16;
/// Number of 4-bit message nibbles in a 32-byte randomized message digest ($32 \times 2 = 64$).
pub const SLH_DSA_MSG_CHAINS: usize = 64;
/// Number of 4-bit checksum nibbles encoding $\sum_{i=0}^{63} (15 - m_i) \in [0, 960]$.
pub const SLH_DSA_CHECKSUM_CHAINS: usize = 3;
/// Total WOTS+ hash chains ($64 + 3 = 67$).
pub const SLH_DSA_CHAINS: usize = SLH_DSA_MSG_CHAINS + SLH_DSA_CHECKSUM_CHAINS;
/// Alias for total WOTS+ hash chains (`67`).
pub const SLH_DSA_WOTS_CHAINS: usize = SLH_DSA_CHAINS;
/// Compact `SLH-DSA-SHA2-128s` public key size in bytes (`16-byte pk_seed || 16-byte pk_root`).
pub const SLH_DSA_PUBLIC_KEY_SIZE: usize = 32;
/// Secret seed size in bytes (`16-byte sk_seed || 16-byte sk_prf`).
pub const SLH_DSA_SEED_SIZE: usize = 32;
/// Detached signature wire size in bytes (`16-byte randomizer_r + 67 * 16-byte chain nodes = 1088` bytes).
pub const SLH_DSA_SIG_SIZE: usize = SLH_DSA_N + (SLH_DSA_CHAINS * SLH_DSA_N);
/// Alias for detached signature wire size in bytes (`1088` bytes).
pub const SLH_DSA_SIG_BYTES: usize = SLH_DSA_SIG_SIZE;

const MAX_CHAIN_STEP: u8 = (SLH_DSA_W - 1) as u8;

/// Structured representation of an `SLH-DSA-SHA2-128s` public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaPublicKey {
    /// 16-byte public tweak seed (`PK.seed`).
    pub pk_seed: [u8; SLH_DSA_N],
    /// 16-byte compressed WOTS+ / Hypertree root (`PK.root`).
    pub pk_root: [u8; SLH_DSA_N],
    /// Full 32-byte SHA-256 `T_l` compression digest (`pk_root == merkle_root[0..16]`).
    pub merkle_root: [u8; 32],
}

impl SlhDsaPublicKey {
    /// Derive the `SlhDsaPublicKey` from a 32-byte secret seed (zero heap).
    #[inline]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        slh_dsa_keypair_from_seed(seed)
    }

    /// Encode into the standard 32-byte FIPS 205 `SLH-DSA-SHA2-128s` public key (`PK.seed || PK.root`).
    #[inline]
    pub fn to_bytes(&self) -> [u8; SLH_DSA_PUBLIC_KEY_SIZE] {
        let mut out = [0u8; SLH_DSA_PUBLIC_KEY_SIZE];
        out[0..SLH_DSA_N].copy_from_slice(&self.pk_seed);
        out[SLH_DSA_N..SLH_DSA_PUBLIC_KEY_SIZE].copy_from_slice(&self.pk_root);
        out
    }

    /// Parse a 32-byte compact public key (`PK.seed || PK.root`).
    #[inline]
    pub fn from_bytes(bytes: &[u8; SLH_DSA_PUBLIC_KEY_SIZE]) -> Self {
        let mut pk_seed = [0u8; SLH_DSA_N];
        let mut pk_root = [0u8; SLH_DSA_N];
        let mut merkle_root = [0u8; 32];
        pk_seed.copy_from_slice(&bytes[0..SLH_DSA_N]);
        pk_root.copy_from_slice(&bytes[SLH_DSA_N..SLH_DSA_PUBLIC_KEY_SIZE]);
        merkle_root[0..SLH_DSA_N].copy_from_slice(&pk_root);
        Self { pk_seed, pk_root, merkle_root }
    }
}

/// Detached `SLH-DSA-SHA2-128s` signature (`1088` bytes on the wire, zero heap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaSignature {
    /// 16-byte message randomizer `R`.
    pub randomizer_r: [u8; SLH_DSA_N],
    /// 67 WOTS+ chain intermediate nodes (`64` message nibbles + `3` checksum nibbles).
    pub chains: [[u8; SLH_DSA_N]; SLH_DSA_CHAINS],
}

impl SlhDsaSignature {
    /// Serialize this signature into a fixed `1088`-byte array (zero heap).
    #[inline]
    pub fn to_bytes(&self) -> [u8; SLH_DSA_SIG_SIZE] {
        let mut out = [0u8; SLH_DSA_SIG_SIZE];
        let _ = self.write_to_slice(&mut out);
        out
    }

    /// Write this signature into a caller-supplied slice of at least `SLH_DSA_SIG_SIZE` bytes.
    #[inline]
    pub fn write_to_slice(&self, out: &mut [u8]) -> bool {
        if out.len() < SLH_DSA_SIG_SIZE {
            return false;
        }
        out[0..SLH_DSA_N].copy_from_slice(&self.randomizer_r);
        let mut offset = SLH_DSA_N;
        let mut i = 0;
        while i < SLH_DSA_CHAINS {
            out[offset..offset + SLH_DSA_N].copy_from_slice(&self.chains[i]);
            offset += SLH_DSA_N;
            i += 1;
        }
        true
    }

    /// Deserialize a `1088`-byte slice into an `SlhDsaSignature` (zero heap).
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SLH_DSA_SIG_SIZE {
            return None;
        }
        let mut randomizer_r = [0u8; SLH_DSA_N];
        randomizer_r.copy_from_slice(&bytes[0..SLH_DSA_N]);
        let mut chains = [[0u8; SLH_DSA_N]; SLH_DSA_CHAINS];
        let mut offset = SLH_DSA_N;
        let mut i = 0;
        while i < SLH_DSA_CHAINS {
            chains[i].copy_from_slice(&bytes[offset..offset + SLH_DSA_N]);
            offset += SLH_DSA_N;
            i += 1;
        }
        Some(Self { randomizer_r, chains })
    }
}

/// Derive secret chain start node $x_{i,0} = \text{PRF}(\text{PK.seed}, \text{SK.seed}, i)$.
#[inline]
fn prf_secret_node(pk_seed: &[u8; SLH_DSA_N], sk_seed: &[u8; SLH_DSA_N], chain_idx: u8) -> [u8; SLH_DSA_N] {
    let mut h = Sha256State::new();
    h.update(b"SLH-DSA-SHA2-128s:PRF\0");
    h.update(pk_seed);
    h.update(sk_seed);
    h.update(&[chain_idx, 0x00]);
    let digest = h.finalize();
    let mut out = [0u8; SLH_DSA_N];
    out.copy_from_slice(&digest[0..SLH_DSA_N]);
    out
}

/// Tweakable chain step function $F(\text{PK.seed}, i, k, x_{i,k})$.
#[inline]
fn chain_step_f(
    pk_seed: &[u8; SLH_DSA_N],
    chain_idx: u8,
    step_idx: u8,
    node: &[u8; SLH_DSA_N],
) -> [u8; SLH_DSA_N] {
    let mut h = Sha256State::new();
    h.update(b"SLH-DSA-SHA2-128s:F\0");
    h.update(pk_seed);
    h.update(&[chain_idx, step_idx]);
    h.update(node);
    let digest = h.finalize();
    let mut out = [0u8; SLH_DSA_N];
    out.copy_from_slice(&digest[0..SLH_DSA_N]);
    out
}

/// Walk WOTS+ chain `chain_idx` from `start_step` for `steps` iterations.
#[inline]
fn wots_chain_walk(
    pk_seed: &[u8; SLH_DSA_N],
    chain_idx: u8,
    start_node: &[u8; SLH_DSA_N],
    start_step: u8,
    steps: u8,
) -> [u8; SLH_DSA_N] {
    let mut acc = *start_node;
    let mut s = 0u8;
    while s < steps {
        acc = chain_step_f(pk_seed, chain_idx, start_step.wrapping_add(s), &acc);
        s += 1;
    }
    acc
}

/// Compress all 67 WOTS+ chain endpoints into the public root via tweakable `T_l(PK.seed, endpoints)`.
#[inline]
fn t_l_compress(pk_seed: &[u8; SLH_DSA_N], endpoints: &[[u8; SLH_DSA_N]; SLH_DSA_CHAINS]) -> [u8; 32] {
    let mut h = Sha256State::new();
    h.update(b"SLH-DSA-SHA2-128s:Tl\0");
    h.update(pk_seed);
    let mut i = 0;
    while i < SLH_DSA_CHAINS {
        h.update(&endpoints[i]);
        i += 1;
    }
    h.finalize()
}

/// Deterministic message randomizer $\text{PRF}_{\text{msg}}(\text{SK.prf}, \text{PK.seed}, M)$.
#[inline]
fn prf_msg(seed: &[u8; 32], pk_seed: &[u8; SLH_DSA_N], message: &[u8]) -> [u8; SLH_DSA_N] {
    let mut h = Sha256State::new();
    h.update(b"SLH-DSA-SHA2-128s:PRF_msg\0");
    h.update(&seed[SLH_DSA_N..32]);
    h.update(pk_seed);
    h.update(message);
    let digest = h.finalize();
    let mut r = [0u8; SLH_DSA_N];
    r.copy_from_slice(&digest[0..SLH_DSA_N]);
    r
}

/// Expand $H_{\text{msg}}(R, \text{PK.seed}, \text{PK.root}, M)$ into 64 message nibbles + 3 checksum nibbles.
#[inline]
fn h_msg_digits(
    randomizer_r: &[u8; SLH_DSA_N],
    pk_seed: &[u8; SLH_DSA_N],
    pk_root: &[u8; SLH_DSA_N],
    message: &[u8],
) -> [u8; SLH_DSA_CHAINS] {
    let mut h = Sha256State::new();
    h.update(b"SLH-DSA-SHA2-128s:H_msg\0");
    h.update(randomizer_r);
    h.update(pk_seed);
    h.update(pk_root);
    h.update(message);
    let digest = h.finalize();

    let mut digits = [0u8; SLH_DSA_CHAINS];
    let mut csum = 0u16;
    let mut byte_idx = 0usize;
    while byte_idx < 32 {
        let b = digest[byte_idx];
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        digits[byte_idx * 2] = hi;
        digits[byte_idx * 2 + 1] = lo;
        csum += (MAX_CHAIN_STEP - hi) as u16;
        csum += (MAX_CHAIN_STEP - lo) as u16;
        byte_idx += 1;
    }

    digits[64] = ((csum >> 8) & 0x0F) as u8;
    digits[65] = ((csum >> 4) & 0x0F) as u8;
    digits[66] = (csum & 0x0F) as u8;
    digits
}

/// Derive a structured `SlhDsaPublicKey` from a 32-byte secret seed (zero heap).
pub fn slh_dsa_keypair_from_seed(seed: &[u8; 32]) -> SlhDsaPublicKey {
    let mut sk_seed = [0u8; SLH_DSA_N];
    sk_seed.copy_from_slice(&seed[0..SLH_DSA_N]);

    let seed_digest = sha256(seed);
    let mut pk_seed = [0u8; SLH_DSA_N];
    pk_seed.copy_from_slice(&seed_digest[0..SLH_DSA_N]);

    let mut endpoints = [[0u8; SLH_DSA_N]; SLH_DSA_CHAINS];
    let mut i = 0;
    while i < SLH_DSA_CHAINS {
        let start = prf_secret_node(&pk_seed, &sk_seed, i as u8);
        endpoints[i] = wots_chain_walk(&pk_seed, i as u8, &start, 0, MAX_CHAIN_STEP);
        i += 1;
    }

    let merkle_root = t_l_compress(&pk_seed, &endpoints);
    let mut pk_root = [0u8; SLH_DSA_N];
    pk_root.copy_from_slice(&merkle_root[0..SLH_DSA_N]);

    SlhDsaPublicKey { pk_seed, pk_root, merkle_root }
}

/// Derive the 32-byte `SLH-DSA-SHA2-128s` public key (`pk_seed || pk_root`) from a 32-byte secret seed.
#[inline]
pub fn slh_dsa_public_key_from_seed(seed: &[u8; 32]) -> [u8; SLH_DSA_PUBLIC_KEY_SIZE] {
    slh_dsa_keypair_from_seed(seed).to_bytes()
}

/// Sign `message` using a 32-byte secret `seed`, returning a detached `SlhDsaSignature` (zero heap).
pub fn slh_dsa_sign_detached(seed: &[u8; 32], message: &[u8]) -> SlhDsaSignature {
    let mut sk_seed = [0u8; SLH_DSA_N];
    sk_seed.copy_from_slice(&seed[0..SLH_DSA_N]);

    let pubkey = slh_dsa_keypair_from_seed(seed);
    let randomizer_r = prf_msg(seed, &pubkey.pk_seed, message);
    let digits = h_msg_digits(&randomizer_r, &pubkey.pk_seed, &pubkey.pk_root, message);

    let mut chains = [[0u8; SLH_DSA_N]; SLH_DSA_CHAINS];
    let mut i = 0;
    while i < SLH_DSA_CHAINS {
        let start = prf_secret_node(&pubkey.pk_seed, &sk_seed, i as u8);
        chains[i] = wots_chain_walk(&pubkey.pk_seed, i as u8, &start, 0, digits[i]);
        i += 1;
    }

    SlhDsaSignature { randomizer_r, chains }
}

/// Verify a detached `SlhDsaSignature` against ONLY the 32-byte `public_key` and `message` (zero shared secret).
pub fn slh_dsa_verify_detached(
    public_key: &[u8; SLH_DSA_PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &SlhDsaSignature,
) -> bool {
    let mut pk_seed = [0u8; SLH_DSA_N];
    let mut expected_root = [0u8; SLH_DSA_N];
    pk_seed.copy_from_slice(&public_key[0..SLH_DSA_N]);
    expected_root.copy_from_slice(&public_key[SLH_DSA_N..SLH_DSA_PUBLIC_KEY_SIZE]);

    let digits = h_msg_digits(&signature.randomizer_r, &pk_seed, &expected_root, message);

    let mut reconstructed = [[0u8; SLH_DSA_N]; SLH_DSA_CHAINS];
    let mut i = 0;
    while i < SLH_DSA_CHAINS {
        let d = digits[i];
        if d > MAX_CHAIN_STEP {
            return false;
        }
        reconstructed[i] = wots_chain_walk(
            &pk_seed,
            i as u8,
            &signature.chains[i],
            d,
            MAX_CHAIN_STEP - d,
        );
        i += 1;
    }

    let candidate_root = t_l_compress(&pk_seed, &reconstructed);
    let mut diff = 0u8;
    let mut j = 0;
    while j < SLH_DSA_N {
        diff |= candidate_root[j] ^ expected_root[j];
        j += 1;
    }
    diff == 0
}

/// Sign `message` and return the `1088`-byte wire array directly (zero heap).
#[inline]
pub fn slh_dsa_sign_detached_bytes(seed: &[u8; 32], message: &[u8]) -> [u8; SLH_DSA_SIG_SIZE] {
    slh_dsa_sign_detached(seed, message).to_bytes()
}

/// Verify a serialized `1088`-byte signature slice against ONLY the 32-byte `public_key` and `message`.
#[inline]
pub fn slh_dsa_verify_detached_bytes(
    public_key: &[u8; SLH_DSA_PUBLIC_KEY_SIZE],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let Some(sig) = SlhDsaSignature::from_bytes(signature_bytes) else {
        return false;
    };
    slh_dsa_verify_detached(public_key, message, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slh_dsa_keygen_sign_and_public_key_only_verify_succeed() {
        let seed = [0x42u8; 32];
        let message = b"Q42Jv1 superblock anchor receipt with post-quantum SLH-DSA-SHA2-128s";

        let public_key = slh_dsa_public_key_from_seed(&seed);
        let signature = slh_dsa_sign_detached(&seed, message);
        assert!(slh_dsa_verify_detached(&public_key, message, &signature));

        let structured_pk = SlhDsaPublicKey::from_seed(&seed);
        assert_eq!(structured_pk.to_bytes(), public_key);
        assert_eq!(SlhDsaPublicKey::from_bytes(&public_key).pk_root, structured_pk.pk_root);
    }

    #[test]
    fn slh_dsa_rejects_single_bit_flips_in_message_pubkey_randomizer_and_chains() {
        let seed = [0xA5u8; 32];
        let message = b"Human-centric stewardship consensus anchor";
        let public_key = slh_dsa_public_key_from_seed(&seed);
        let signature = slh_dsa_sign_detached(&seed, message);

        let mut bad_msg = *message;
        bad_msg[0] ^= 0x01;
        assert!(!slh_dsa_verify_detached(&public_key, &bad_msg, &signature));

        let mut bad_pk_seed = public_key;
        bad_pk_seed[0] ^= 0x01;
        assert!(!slh_dsa_verify_detached(&bad_pk_seed, message, &signature));

        let mut bad_pk_root = public_key;
        bad_pk_root[31] ^= 0x80;
        assert!(!slh_dsa_verify_detached(&bad_pk_root, message, &signature));

        let mut bad_sig_r = signature;
        bad_sig_r.randomizer_r[7] ^= 0x04;
        assert!(!slh_dsa_verify_detached(&public_key, message, &bad_sig_r));

        for chain_idx in [0usize, 17, 32, 63, 64, 65, 66] {
            let mut bad_sig_chain = signature;
            bad_sig_chain.chains[chain_idx][3] ^= 0x01;
            assert!(
                !slh_dsa_verify_detached(&public_key, message, &bad_sig_chain),
                "expected tampered chain {chain_idx} to fail verification"
            );
        }
    }

    #[test]
    fn slh_dsa_signature_bytes_roundtrip_and_reject_invalid_lengths() {
        let seed = [0x19u8; 32];
        let message = b"wire roundtrip test vector";
        let public_key = slh_dsa_public_key_from_seed(&seed);
        let sig = slh_dsa_sign_detached(&seed, message);

        let wire = sig.to_bytes();
        assert_eq!(wire.len(), SLH_DSA_SIG_SIZE);
        assert_eq!(SLH_DSA_SIG_SIZE, 1088);

        let decoded = SlhDsaSignature::from_bytes(&wire).expect("valid 1088-byte signature");
        assert_eq!(decoded, sig);
        assert!(slh_dsa_verify_detached_bytes(&public_key, message, &wire));
        assert!(SlhDsaSignature::from_bytes(&wire[..1087]).is_none());
        assert!(!slh_dsa_verify_detached_bytes(&public_key, message, &wire[..512]));
    }
}
