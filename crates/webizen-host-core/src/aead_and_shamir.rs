//! RFC 8439 `ChaCha20-Poly1305` Authenticated Encryption with Associated Data (AEAD)
//! and Shamir's Secret Sharing over $\text{GF}(2^8)$ (`x^8 + x^4 + x^3 + x + 1 = 0x11B`).

use crate::crypto::hmac_sha256;

#[inline]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// RFC 8439 ChaCha20 64-byte keystream block generator (`expand 32-byte k`, 20 rounds).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;
    for i in 0..8 {
        let j = i * 4;
        initial[4 + i] = u32::from_le_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
    }
    initial[12] = counter;
    for i in 0..3 {
        let j = i * 4;
        initial[13 + i] = u32::from_le_bytes([nonce[j], nonce[j + 1], nonce[j + 2], nonce[j + 3]]);
    }

    let mut working = initial;
    for _ in 0..10 {
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);

        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut counter = initial_counter;
    for (chunk_idx, src) in data.chunks(64).enumerate() {
        let block = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        let dst = &mut out[chunk_idx * 64..chunk_idx * 64 + src.len()];
        for i in 0..src.len() {
            dst[i] = src[i] ^ block[i];
        }
    }
    out
}

/// RFC 8439 Poly1305 one-time authenticator over `(aad, ciphertext, aad.len(), ciphertext.len())`.
fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r.copy_from_slice(&otk[0..16]);
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;

    let t0 = u32::from_le_bytes(r[0..4].try_into().unwrap()) as u64;
    let t1 = u32::from_le_bytes(r[4..8].try_into().unwrap()) as u64;
    let t2 = u32::from_le_bytes(r[8..12].try_into().unwrap()) as u64;
    let t3 = u32::from_le_bytes(r[12..16].try_into().unwrap()) as u64;

    let r0 = t0 & 0x3ffffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    let r4 = (t3 >> 8) & 0x00fffff;

    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let mut h = [0u64; 5];
    let mut feed_block = |blk: &[u8; 16]| {
        let b0 = u32::from_le_bytes(blk[0..4].try_into().unwrap()) as u64;
        let b1 = u32::from_le_bytes(blk[4..8].try_into().unwrap()) as u64;
        let b2 = u32::from_le_bytes(blk[8..12].try_into().unwrap()) as u64;
        let b3 = u32::from_le_bytes(blk[12..16].try_into().unwrap()) as u64;

        h[0] += b0 & 0x3ffffff;
        h[1] += ((b0 >> 26) | (b1 << 6)) & 0x3ffffff;
        h[2] += ((b1 >> 20) | (b2 << 12)) & 0x3ffffff;
        h[3] += ((b2 >> 14) | (b3 << 18)) & 0x3ffffff;
        h[4] += (b3 >> 8) | (1u64 << 24);

        let d0 = h[0] * r0 + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
        let mut d1 = h[0] * r1 + h[1] * r0 + h[2] * s4 + h[3] * s3 + h[4] * s2;
        let mut d2 = h[0] * r2 + h[1] * r1 + h[2] * r0 + h[3] * s4 + h[4] * s3;
        let mut d3 = h[0] * r3 + h[1] * r2 + h[2] * r1 + h[3] * r0 + h[4] * s4;
        let mut d4 = h[0] * r4 + h[1] * r3 + h[2] * r2 + h[3] * r1 + h[4] * r0;

        let mut c = d0 >> 26;
        h[0] = d0 & 0x3ffffff;
        d1 += c;
        c = d1 >> 26;
        h[1] = d1 & 0x3ffffff;
        d2 += c;
        c = d2 >> 26;
        h[2] = d2 & 0x3ffffff;
        d3 += c;
        c = d3 >> 26;
        h[3] = d3 & 0x3ffffff;
        d4 += c;
        c = d4 >> 26;
        h[4] = d4 & 0x3ffffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;
    };

    for chunk in aad.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        feed_block(&blk);
    }
    for chunk in ciphertext.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        feed_block(&blk);
    }
    let mut len_blk = [0u8; 16];
    len_blk[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_blk[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    feed_block(&len_blk);

    let mut c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    let mut g0 = h[0].wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h[1].wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h[2].wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h[3].wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    h[0] = (h[0] & !mask) | (g0 & mask);
    h[1] = (h[1] & !mask) | (g1 & mask);
    h[2] = (h[2] & !mask) | (g2 & mask);
    h[3] = (h[3] & !mask) | (g3 & mask);
    h[4] = (h[4] & !mask) | (g4 & mask);

    let w0 = (h[0] | (h[1] << 26)) & 0xffffffff;
    let w1 = ((h[1] >> 6) | (h[2] << 20)) & 0xffffffff;
    let w2 = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffff;
    let w3 = ((h[3] >> 18) | (h[4] << 8)) & 0xffffffff;

    let s0_pad = u32::from_le_bytes(otk[16..20].try_into().unwrap()) as u64;
    let s1_pad = u32::from_le_bytes(otk[20..24].try_into().unwrap()) as u64;
    let s2_pad = u32::from_le_bytes(otk[24..28].try_into().unwrap()) as u64;
    let s3_pad = u32::from_le_bytes(otk[28..32].try_into().unwrap()) as u64;

    let mut acc = w0 + s0_pad;
    let out0 = acc as u32;
    acc = w1 + s1_pad + (acc >> 32);
    let out1 = acc as u32;
    acc = w2 + s2_pad + (acc >> 32);
    let out2 = acc as u32;
    acc = w3 + s3_pad + (acc >> 32);
    let out3 = acc as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&out0.to_le_bytes());
    tag[4..8].copy_from_slice(&out1.to_le_bytes());
    tag[8..12].copy_from_slice(&out2.to_le_bytes());
    tag[12..16].copy_from_slice(&out3.to_le_bytes());
    tag
}

/// RFC 8439 ChaCha20-Poly1305 AEAD Seal (counter=0 for Poly1305 OTK, counter=1 for ChaCha20 stream).
pub fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    let ciphertext = chacha20_xor(key, 1, nonce, plaintext);
    let tag = poly1305_aead_tag(&otk, aad, &ciphertext);
    (ciphertext, tag)
}

/// RFC 8439 ChaCha20-Poly1305 AEAD Open with constant-time 128-bit tag verification (`diff != 0`).
pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    let expected_tag = poly1305_aead_tag(&otk, aad, ciphertext);

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err("ChaCha20-Poly1305 AEAD authentication tag verification failed");
    }
    Ok(chacha20_xor(key, 1, nonce, ciphertext))
}

#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    p
}

#[inline]
fn gf256_inv(a: u8) -> u8 {
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Split a 32-byte secret into `(x_coord, share_bytes)` using Shamir's Secret Sharing over $\text{GF}(2^8)$.
pub fn shamir_split_gf256(
    secret: &[u8; 32],
    threshold_m: u8,
    total_n: u8,
    seed: &[u8; 32],
) -> Result<Vec<(u8, [u8; 32])>, &'static str> {
    if threshold_m == 0 || total_n < threshold_m {
        return Err("Invalid Shamir threshold parameters: require 1 <= threshold_m <= total_n");
    }
    let mut coeffs = vec![[0u8; 32]; threshold_m as usize];
    coeffs[0] = *secret;
    for deg in 1..(threshold_m as usize) {
        let stream = hmac_sha256(seed, &[deg as u8, threshold_m, total_n]);
        for b in 0..32 {
            coeffs[deg][b] = if stream[b] == 0 { 1 } else { stream[b] };
        }
    }

    let mut shares = Vec::with_capacity(total_n as usize);
    for idx in 1..=total_n {
        let x = idx;
        let mut y = [0u8; 32];
        for b in 0..32 {
            let mut val = 0u8;
            for deg in (0..(threshold_m as usize)).rev() {
                val = gf256_mul(val, x) ^ coeffs[deg][b];
            }
            y[b] = val;
        }
        shares.push((x, y));
    }
    Ok(shares)
}

/// Reconstruct a 32-byte secret from at least `threshold_m` Shamir shares via Lagrange interpolation at $x = 0$ over $\text{GF}(2^8)$.
pub fn shamir_reconstruct_gf256(
    shares: &[(u8, [u8; 32])],
    threshold_m: u8,
) -> Result<[u8; 32], &'static str> {
    if threshold_m == 0 || shares.len() < threshold_m as usize {
        return Err("Insufficient Shamir shares to meet threshold_m");
    }
    let active = &shares[..threshold_m as usize];
    for i in 0..active.len() {
        if active[i].0 == 0 {
            return Err("Shamir share x-coordinate cannot be 0");
        }
        for j in (i + 1)..active.len() {
            if active[i].0 == active[j].0 {
                return Err("Duplicate Shamir share x-coordinate");
            }
        }
    }

    let mut out = [0u8; 32];
    for i in 0..active.len() {
        let xi = active[i].0;
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &(xj, _)) in active.iter().enumerate() {
            if i != j {
                num = gf256_mul(num, xj);
                den = gf256_mul(den, xj ^ xi);
            }
        }
        let basis_at_zero = gf256_mul(num, gf256_inv(den));
        for b in 0..32 {
            out[b] ^= gf256_mul(active[i].1[b], basis_at_zero);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn fips_180_4_sha256_nist_vector_abc_and_crypto_primitives() {
        let expected_abc =
            hex_to_32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256(b"abc"), expected_abc);

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"webizen-host-sanctuary-aead-header";
        let msg = b"Confidential Freedom of Thought journal entry";
        let (mut ct, mut tag) = chacha20_poly1305_seal(&key, &nonce, aad, msg);
        assert_eq!(
            chacha20_poly1305_open(&key, &nonce, aad, &ct, &tag).unwrap(),
            msg
        );

        ct[0] ^= 0x01;
        assert!(chacha20_poly1305_open(&key, &nonce, aad, &ct, &tag).is_err());
        ct[0] ^= 0x01;
        tag[15] ^= 0x01;
        assert!(chacha20_poly1305_open(&key, &nonce, aad, &ct, &tag).is_err());

        let secret = sha256(b"master-sanctuary-key");
        let shares = shamir_split_gf256(&secret, 2, 3, &[0x99u8; 32]).unwrap();
        assert_eq!(
            shamir_reconstruct_gf256(&[shares[0], shares[2]], 2).unwrap(),
            secret
        );
        assert_eq!(
            shamir_reconstruct_gf256(&[shares[1], shares[2]], 2).unwrap(),
            secret
        );
        assert!(shamir_reconstruct_gf256(&[shares[0]], 2).is_err());
    }
}
