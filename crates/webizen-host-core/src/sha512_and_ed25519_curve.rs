//! Standards-Exact FIPS 180-4 SHA-512 & RFC 8032 Twisted-Edwards Ed25519 (`WP-14`).
//!
//! Zero-heap (`HotZeroHeap`) implementation of FIPS 180-4 SHA-512 (`Sha512State`, `sha512`)
//! and RFC 8032 Ed25519 over $-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2 \pmod{2^{255}-19}$.

use core::cmp::Ordering;

const H512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Streaming FIPS 180-4 SHA-512 state (zero heap allocation).
#[derive(Clone, Copy)]
pub struct Sha512State {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Default for Sha512State {
    fn default() -> Self { Self::new() }
}

impl Sha512State {
    #[inline]
    pub const fn new() -> Self {
        Self { h: H512_INIT, buf: [0u8; 128], buf_len: 0, total_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u128;
        if self.buf_len > 0 {
            let take = core::cmp::min(128 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let block = self.buf;
                self.compress_block(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 128 {
            let (block_slice, rest) = data.split_at(128);
            let mut block = [0u8; 128];
            block.copy_from_slice(block_slice);
            self.compress_block(&block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            self.buf[self.buf_len..128].fill(0);
            let block = self.buf;
            self.compress_block(&block);
            self.buf.fill(0);
        } else {
            self.buf[self.buf_len..112].fill(0);
        }
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let last_block = self.buf;
        self.compress_block(&last_block);

        let mut out = [0u8; 64];
        for (i, &word) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..80 {
            let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(sum1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (st, val) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *st = st.wrapping_add(val);
        }
    }
}

/// Compute the 64-byte FIPS 180-4 SHA-512 digest of `data` (zero heap).
#[inline]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut st = Sha512State::new();
    st.update(data);
    st.finalize()
}

type Fe = [u64; 4];

const FE_ZERO: Fe = [0, 0, 0, 0];
const FE_ONE: Fe = [1, 0, 0, 0];
const P_25519: Fe = [0xFFFF_FFFF_FFFF_FFED, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF];
const P_MINUS_2: Fe = [0xFFFF_FFFF_FFFF_FFEB, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF];
const P_MINUS_5_OVER_8: Fe = [0xFFFF_FFFF_FFFF_FFFD, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x0FFF_FFFF_FFFF_FFFF];
const ED25519_D: Fe = [0x75eb_4dca_1359_78a3, 0x0070_0a4d_4141_d8ab, 0x8cc7_4079_7779_e898, 0x5203_6cee_2b6f_fe73];
const SQRT_M1: Fe = [0xc4ee_1b27_4a0e_a0b0, 0x2f43_1806_ad2f_e478, 0x2b4d_0099_3dfb_d7a7, 0x2b83_2480_4fc1_df0b];
const BASE_X: Fe = [0xc956_2d60_8f25_d51a, 0x692c_c760_9525_a7b2, 0xc0a4_e231_fdd6_dc5c, 0x2169_36d3_cd6e_53fe];
const BASE_Y: Fe = [0x6666_6666_6666_6658, 0x6666_6666_6666_6666, 0x6666_6666_6666_6666, 0x6666_6666_6666_6666];
const ED25519_L: [u64; 4] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0x0000_0000_0000_0000, 0x1000_0000_0000_0000];

/// Extended Twisted-Edwards point $(X : Y : Z : T)$ with $X \cdot Y = Z \cdot T \pmod p$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtPoint {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

#[inline]
fn u256_cmp(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    for i in (0..4).rev() {
        if a[i] != b[i] { return a[i].cmp(&b[i]); }
    }
    Ordering::Equal
}

#[inline]
fn u256_sub_raw(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (mut out, mut borrow) = ([0u64; 4], 0u64);
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1 || b2);
    }
    out
}

#[inline]
fn u256_from_le_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

#[inline]
fn u256_to_le_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 { out[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes()); }
    out
}

#[inline]
fn fe_add(a: Fe, b: Fe) -> Fe {
    let (mut out, mut carry) = ([0u64; 4], 0u128);
    for i in 0..4 {
        let s = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    if u256_cmp(&out, &P_25519) != Ordering::Less { out = u256_sub_raw(out, P_25519); }
    out
}

#[inline]
fn fe_sub(a: Fe, b: Fe) -> Fe {
    if u256_cmp(&a, &b) != Ordering::Less {
        u256_sub_raw(a, b)
    } else {
        u256_sub_raw(P_25519, u256_sub_raw(b, a))
    }
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let mut c = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (a[i] as u128) * (b[j] as u128) + (c[i + j] as u128) + carry;
            c[i + j] = prod as u64;
            carry = prod >> 64;
        }
        c[i + 4] = carry as u64;
    }
    let (mut r, mut carry) = ([0u64; 4], 0u128);
    for i in 0..4 {
        let v = (c[i] as u128) + (c[i + 4] as u128) * 38 + carry;
        r[i] = v as u64;
        carry = v >> 64;
    }
    let q = (carry << 1) | ((r[3] >> 63) as u128);
    r[3] &= 0x7FFF_FFFF_FFFF_FFFF;
    let mut c2 = q * 19;
    for i in 0..4 {
        let v = (r[i] as u128) + c2;
        r[i] = v as u64;
        c2 = v >> 64;
    }
    while u256_cmp(&r, &P_25519) != Ordering::Less { r = u256_sub_raw(r, P_25519); }
    r
}

fn fe_pow(mut base: Fe, exp: Fe) -> Fe {
    let mut res = FE_ONE;
    for bit in 0..255 {
        if ((exp[bit / 64] >> (bit % 64)) & 1) == 1 { res = fe_mul(res, base); }
        base = fe_mul(base, base);
    }
    res
}

#[inline]
fn fe_inv(a: Fe) -> Fe { fe_pow(a, P_MINUS_2) }

#[inline]
fn basepoint() -> ExtPoint {
    ExtPoint { x: BASE_X, y: BASE_Y, z: FE_ONE, t: fe_mul(BASE_X, BASE_Y) }
}

/// Unified Extended Twisted-Edwards point addition (RFC 8032 §5.1.4).
pub fn point_add(p1: &ExtPoint, p2: &ExtPoint) -> ExtPoint {
    let d2 = fe_add(ED25519_D, ED25519_D);
    let a = fe_mul(fe_sub(p1.y, p1.x), fe_sub(p2.y, p2.x));
    let b = fe_mul(fe_add(p1.y, p1.x), fe_add(p2.y, p2.x));
    let c = fe_mul(fe_mul(p1.t, d2), p2.t);
    let z1z2 = fe_mul(p1.z, p2.z);
    let d = fe_add(z1z2, z1z2);
    let (e, f, g, h) = (fe_sub(b, a), fe_sub(d, c), fe_add(d, c), fe_add(b, a));
    ExtPoint { x: fe_mul(e, f), y: fe_mul(g, h), t: fe_mul(e, h), z: fe_mul(f, g) }
}

/// Scalar multiplication $s \cdot P$ on Twisted-Edwards Ed25519.
pub fn point_mul(p: &ExtPoint, scalar: &[u64; 4]) -> ExtPoint {
    let mut res = ExtPoint { x: FE_ZERO, y: FE_ONE, z: FE_ONE, t: FE_ZERO };
    let mut temp = *p;
    for bit in 0..256 {
        if ((scalar[bit / 64] >> (bit % 64)) & 1) == 1 { res = point_add(&res, &temp); }
        temp = point_add(&temp, &temp);
    }
    res
}

/// Compress an `ExtPoint` into 32-byte RFC 8032 §5.1.2 encoding.
pub fn point_compress(p: &ExtPoint) -> [u8; 32] {
    let z_inv = fe_inv(p.z);
    let (x, y) = (fe_mul(p.x, z_inv), fe_mul(p.y, z_inv));
    let mut s = u256_to_le_bytes(&y);
    s[31] |= ((x[0] & 1) as u8) << 7;
    s
}

/// Decompress a 32-byte RFC 8032 §5.1.3 point encoding into an `ExtPoint`.
pub fn point_decompress(s: &[u8; 32]) -> Option<ExtPoint> {
    let x_0 = (s[31] >> 7) & 1;
    let mut y_bytes = *s;
    y_bytes[31] &= 0x7F;
    let y = u256_from_le_bytes(&y_bytes);
    if u256_cmp(&y, &P_25519) != Ordering::Less { return None; }
    let y2 = fe_mul(y, y);
    let (u, v) = (fe_sub(y2, FE_ONE), fe_add(fe_mul(ED25519_D, y2), FE_ONE));
    let v2 = fe_mul(v, v);
    let v3 = fe_mul(v2, v);
    let v7 = fe_mul(fe_mul(v2, v2), v3);
    let mut x = fe_mul(fe_mul(u, v3), fe_pow(fe_mul(u, v7), P_MINUS_5_OVER_8));

    let vxx = fe_mul(v, fe_mul(x, x));
    if vxx != u {
        if vxx == fe_sub(FE_ZERO, u) { x = fe_mul(x, SQRT_M1); } else { return None; }
    }
    if x == FE_ZERO && x_0 == 1 { return None; }
    if ((x[0] & 1) as u8) != x_0 { x = fe_sub(FE_ZERO, x); }
    Some(ExtPoint { x, y, z: FE_ONE, t: fe_mul(x, y) })
}

#[inline]
fn scalar_add_mod_l(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (mut out, mut carry) = ([0u64; 4], 0u128);
    for i in 0..4 {
        let s = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    while u256_cmp(&out, &ED25519_L) != Ordering::Less { out = u256_sub_raw(out, ED25519_L); }
    out
}

fn scalar_reduce_512(bytes_64: &[u8; 64]) -> [u64; 4] {
    let mut acc = [0u64; 4];
    for &byte in bytes_64.iter().rev() {
        for bit in (0..8).rev() {
            acc = scalar_add_mod_l(acc, acc);
            if ((byte >> bit) & 1) == 1 { acc = scalar_add_mod_l(acc, [1, 0, 0, 0]); }
        }
    }
    acc
}

fn scalar_mul_mod_l(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut a_red = a;
    while u256_cmp(&a_red, &ED25519_L) != Ordering::Less { a_red = u256_sub_raw(a_red, ED25519_L); }
    let mut res = [0u64; 4];
    for bit in (0..256).rev() {
        res = scalar_add_mod_l(res, res);
        if ((b[bit / 64] >> (bit % 64)) & 1) == 1 { res = scalar_add_mod_l(res, a_red); }
    }
    res
}

#[inline]
fn expand_secret_seed(seed: &[u8; 32]) -> ([u64; 4], [u8; 32]) {
    let h = sha512(seed);
    let (mut s_bytes, mut prefix) = ([0u8; 32], [0u8; 32]);
    s_bytes.copy_from_slice(&h[0..32]);
    s_bytes[0] &= 248;
    s_bytes[31] &= 127;
    s_bytes[31] |= 64;
    prefix.copy_from_slice(&h[32..64]);
    (u256_from_le_bytes(&s_bytes), prefix)
}

/// Derive the 32-byte RFC 8032 §5.1.5 Ed25519 public key from a 32-byte private seed.
pub fn rfc8032_ed25519_pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let (s, _) = expand_secret_seed(seed);
    point_compress(&point_mul(&basepoint(), &s))
}

/// Produce a 64-byte RFC 8032 §5.1.6 Ed25519 signature over `msg`.
pub fn rfc8032_ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let (s, prefix) = expand_secret_seed(seed);
    let a_bytes = point_compress(&point_mul(&basepoint(), &s));

    let mut r_hasher = Sha512State::new();
    r_hasher.update(&prefix);
    r_hasher.update(msg);
    let r = scalar_reduce_512(&r_hasher.finalize());
    let r_bytes = point_compress(&point_mul(&basepoint(), &r));

    let mut k_hasher = Sha512State::new();
    k_hasher.update(&r_bytes);
    k_hasher.update(&a_bytes);
    k_hasher.update(msg);
    let k = scalar_reduce_512(&k_hasher.finalize());

    let s_bytes = u256_to_le_bytes(&scalar_add_mod_l(r, scalar_mul_mod_l(k, s)));
    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_bytes);
    sig[32..64].copy_from_slice(&s_bytes);
    sig
}

/// Verify a 64-byte RFC 8032 §5.1.7 Ed25519 signature using `pubkey` and `msg`.
pub fn rfc8032_ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let r_bytes: [u8; 32] = sig[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[32..64].try_into().unwrap();
    if (s_bytes[31] & 0xE0) != 0 { return false; }
    let s_scalar = u256_from_le_bytes(&s_bytes);
    if u256_cmp(&s_scalar, &ED25519_L) != Ordering::Less { return false; }
    let (Some(a_point), Some(r_point)) = (point_decompress(pubkey), point_decompress(&r_bytes)) else {
        return false;
    };

    let mut k_hasher = Sha512State::new();
    k_hasher.update(&r_bytes);
    k_hasher.update(pubkey);
    k_hasher.update(msg);
    let k = scalar_reduce_512(&k_hasher.finalize());

    let lhs = point_mul(&basepoint(), &s_scalar);
    let rhs = point_add(&r_point, &point_mul(&a_point, &k));
    fe_mul(lhs.x, rhs.z) == fe_mul(rhs.x, lhs.z) && fe_mul(lhs.y, rhs.z) == fe_mul(rhs.y, lhs.z)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for i in 0..N { out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap(); }
        out
    }

    #[test]
    fn fips_180_4_sha512_abc_test_vector() {
        let expected: [u8; 64] = hex_to_bytes(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(sha512(b"abc"), expected);
    }

    #[test]
    fn rfc8032_section_7_1_test_vectors_1_and_2() {
        let seed1: [u8; 32] = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pub1: [u8; 32] = hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig1: [u8; 64] = hex_to_bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(rfc8032_ed25519_pubkey_from_seed(&seed1), pub1);
        assert_eq!(rfc8032_ed25519_sign(&seed1, b""), sig1);
        assert!(rfc8032_ed25519_verify(&pub1, b"", &sig1));

        let seed2: [u8; 32] = hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let pub2: [u8; 32] = hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig2: [u8; 64] = hex_to_bytes(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        assert_eq!(rfc8032_ed25519_pubkey_from_seed(&seed2), pub2);
        assert_eq!(rfc8032_ed25519_sign(&seed2, &[0x72]), sig2);
        assert!(rfc8032_ed25519_verify(&pub2, &[0x72], &sig2));
    }
}
