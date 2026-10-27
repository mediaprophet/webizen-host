//! Pure-Rust, dependency-free cryptographic primitives for `webizen-host`:
//! - FIPS 180-4 `SHA-256` & RFC 2104 `HMAC-SHA256`
//! - RFC 5869 `HKDF-SHA256` & RFC 8018 `PBKDF2-HMAC-SHA256`
//! - Domain-separated binary `SHA-256` Merkle Tree (`0x00` leaf / `0x01` internal node)
//! - Re-exports RFC 8439 `ChaCha20-Poly1305` AEAD and $\text{GF}(2^8)$ Shamir Secret Sharing from `aead_and_shamir`.

pub use crate::aead_and_shamir::{
    chacha20_block, chacha20_poly1305_open, chacha20_poly1305_seal, shamir_reconstruct_gf256,
    shamir_split_gf256,
};

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let j = i * 4;
        w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Zero-heap incremental FIPS 180-4 SHA-256 state machine.
#[derive(Clone, Copy)]
pub struct Sha256State {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    pub const fn new() -> Self {
        Self {
            state: SHA256_H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                sha256_compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            sha256_compress(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            sha256_compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut self.state, &self.buf);

        let mut out = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Full FIPS 180-4 SHA-256 digest (zero heap).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256State::new();
    hasher.update(data);
    hasher.finalize()
}

/// Full RFC 2104 HMAC-SHA256 (`ipad = 0x36`, `opad = 0x5c`, 64-byte block size, zero heap).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256State::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256State::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize()
}

/// Full RFC 5869 HKDF-Extract + HKDF-Expand using `hmac_sha256` (zero heap).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let zero_salt = [0u8; 32];
    let actual_salt = if salt.is_empty() { &zero_salt[..] } else { salt };
    let prk = hmac_sha256(actual_salt, ikm);

    let mut t_prev = [0u8; 32];
    let mut t_len = 0usize;
    let mut counter = 1u8;
    let mut offset = 0usize;

    while offset < out.len() {
        let mut k_block = [0u8; 64];
        k_block[..32].copy_from_slice(&prk);
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k_block[i];
            opad[i] ^= k_block[i];
        }

        let mut inner = Sha256State::new();
        inner.update(&ipad);
        if t_len > 0 {
            inner.update(&t_prev[..t_len]);
        }
        inner.update(info);
        inner.update(&[counter]);
        let inner_digest = inner.finalize();

        let mut outer = Sha256State::new();
        outer.update(&opad);
        outer.update(&inner_digest);
        t_prev = outer.finalize();
        t_len = 32;

        let take = (out.len() - offset).min(32);
        out[offset..offset + take].copy_from_slice(&t_prev[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// Full RFC 8018 PBKDF2-HMAC-SHA256 (zero heap).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    let iters = iterations.max(1);
    let mut k_block = [0u8; 64];
    if password.len() > 64 {
        let hashed = sha256(password);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..password.len()].copy_from_slice(password);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256State::new();
    inner.update(&ipad);
    inner.update(salt);
    inner.update(&1u32.to_be_bytes());
    let inner_digest = inner.finalize();

    let mut outer = Sha256State::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let mut u = outer.finalize();
    let mut t = u;

    for _ in 1..iters {
        let mut inner_i = Sha256State::new();
        inner_i.update(&ipad);
        inner_i.update(&u);
        let d_in = inner_i.finalize();

        let mut outer_i = Sha256State::new();
        outer_i.update(&opad);
        outer_i.update(&d_in);
        u = outer_i.finalize();

        for j in 0..32 {
            t[j] ^= u[j];
        }
    }
    *out = t;
}

/// Domain-separated binary SHA-256 Merkle root (`0x00 || chunk` leaves, `0x01 || left || right` internal nodes).
pub fn sha256_merkle_root(chunks: &[&[u8]]) -> [u8; 32] {
    if chunks.is_empty() {
        return sha256(&[0x00]);
    }
    let mut level: Vec<[u8; 32]> = chunks
        .iter()
        .map(|chunk| {
            let mut h = Sha256State::new();
            h.update(&[0x00]);
            h.update(chunk);
            h.finalize()
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            let mut h = Sha256State::new();
            h.update(&[0x01]);
            h.update(left);
            h.update(right);
            next.push(h.finalize());
        }
        level = next;
    }
    level[0]
}
