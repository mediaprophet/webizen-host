//! Pure-Rust RFC 1950 / RFC 1951 `zlib` DEFLATE/INFLATE & Adler-32 Codec (`WP-14` Swarm 1C).
//!
//! Provides dependency-free RFC 1950 `zlib` framing, Adler-32 checksumming, and RFC 1951
//! DEFLATE compression (Fixed Huffman + LZ77 sliding window) and INFLATE decompression
//! (Stored `BTYPE=00`, Fixed Huffman `BTYPE=01`, and Dynamic Huffman `BTYPE=10`),
//! including stream-prefix consumption (`zlib_decompress_prefix`) for Git `PACK` v2 objects.

const ADLER_MOD: u32 = 65_521;
const MAX_BITS: usize = 15;
const MAX_WINDOW: usize = 32_768;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Compute RFC 1950 §8.2 Adler-32 checksum (`((s2 << 16) | s1)` modulo `65521`).
pub fn adler32(data: &[u8]) -> u32 {
    let (mut s1, mut s2) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= ADLER_MOD;
        s2 %= ADLER_MOD;
    }
    (s2 << 16) | s1
}

struct BitWriter { buf: Vec<u8>, bit_buf: u32, bit_count: u8 }

impl BitWriter {
    fn with_capacity(cap: usize) -> Self { Self { buf: Vec::with_capacity(cap), bit_buf: 0, bit_count: 0 } }
    #[inline]
    fn write_bits(&mut self, val: u32, nbits: u8) {
        self.bit_buf |= (val & ((1u32 << nbits) - 1)) << self.bit_count;
        self.bit_count += nbits;
        while self.bit_count >= 8 {
            self.buf.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bit_count -= 8;
        }
    }
    #[inline]
    fn write_huffman(&mut self, code: u16, len: u8) {
        for i in (0..len).rev() { self.write_bits(((code >> i) & 1) as u32, 1); }
    }
    #[inline]
    fn write_fixed_sym(&mut self, sym: u16) {
        match sym {
            0..=143 => self.write_huffman(0x0030 + sym, 8),
            144..=255 => self.write_huffman(0x0190 + (sym - 144), 9),
            256..=279 => self.write_huffman(sym - 256, 7),
            280..=287 => self.write_huffman(0x00C0 + (sym - 280), 8),
            _ => unreachable!(),
        }
    }
    fn flush_align(&mut self) {
        if self.bit_count > 0 {
            self.buf.push((self.bit_buf & 0xFF) as u8);
            (self.bit_buf, self.bit_count) = (0, 0);
        }
    }
}

#[inline]
fn hash3(data: &[u8], pos: usize) -> usize {
    let v = (data[pos] as usize) | ((data[pos + 1] as usize) << 8) | ((data[pos + 2] as usize) << 16);
    (v.wrapping_mul(0x1E35_A7BD) >> 20) & 0x0FFF
}

/// Compress `input` into a raw RFC 1951 DEFLATE bitstream using Fixed Huffman (`BTYPE=01`) and LZ77.
pub fn deflate_compress_fixed(input: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::with_capacity(input.len() / 2 + 16);
    w.write_bits(1, 1);
    w.write_bits(0b01, 2);
    let (mut head, mut prev, mut pos) = ([-1i32; 4096], [0i32; MAX_WINDOW], 0usize);

    while pos < input.len() {
        let (mut best_len, mut best_dist) = (0usize, 0usize);
        if pos + MIN_MATCH <= input.len() {
            let h = hash3(input, pos);
            let mut cand = head[h];
            head[h] = pos as i32;
            prev[pos & (MAX_WINDOW - 1)] = cand;
            let max_len = (input.len() - pos).min(MAX_MATCH);
            let mut chain = 0usize;
            while cand >= 0 && chain < 64 {
                let cpos = cand as usize;
                let dist = pos - cpos;
                if dist == 0 || dist > MAX_WINDOW { break; }
                if input[cpos + best_len] == input[pos + best_len] {
                    let mut l = 0usize;
                    while l < max_len && input[cpos + l] == input[pos + l] { l += 1; }
                    if l >= MIN_MATCH && l > best_len {
                        (best_len, best_dist) = (l, dist);
                        if l == max_len { break; }
                    }
                }
                cand = prev[cpos & (MAX_WINDOW - 1)];
                chain += 1;
            }
        }
        if best_len >= MIN_MATCH {
            let l_idx = (0..29).rev().find(|&i| (LENGTH_BASE[i] as usize) <= best_len).unwrap_or(0);
            w.write_fixed_sym(257 + l_idx as u16);
            if LENGTH_EXTRA[l_idx] > 0 {
                w.write_bits((best_len - LENGTH_BASE[l_idx] as usize) as u32, LENGTH_EXTRA[l_idx]);
            }
            let d_idx = (0..30).rev().find(|&i| (DIST_BASE[i] as usize) <= best_dist).unwrap_or(0);
            w.write_huffman(d_idx as u16, 5);
            if DIST_EXTRA[d_idx] > 0 {
                w.write_bits((best_dist - DIST_BASE[d_idx] as usize) as u32, DIST_EXTRA[d_idx]);
            }
            for step in 1..best_len {
                if pos + step + MIN_MATCH <= input.len() {
                    let h = hash3(input, pos + step);
                    prev[(pos + step) & (MAX_WINDOW - 1)] = head[h];
                    head[h] = (pos + step) as i32;
                }
            }
            pos += best_len;
        } else {
            w.write_fixed_sym(input[pos] as u16);
            pos += 1;
        }
    }
    w.write_fixed_sym(256);
    w.flush_align();
    w.buf
}

/// Compress `input` into an RFC 1950 `zlib` stream (`[0x78, 0x9C]` header + DEFLATE + big-endian Adler-32).
pub fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let deflate = deflate_compress_fixed(input);
    let mut out = Vec::with_capacity(2 + deflate.len() + 4);
    out.extend_from_slice(&[0x78, 0x9C]);
    out.extend_from_slice(&deflate);
    out.extend_from_slice(&adler32(input).to_be_bytes());
    out
}

struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    #[inline]
    fn read_bits(&mut self, nbits: u8) -> Result<u32, &'static str> {
        let mut val = 0u32;
        for i in 0..nbits {
            let byte_idx = self.bit_pos >> 3;
            if byte_idx >= self.data.len() {
                return Err("Unexpected EOF in DEFLATE bitstream");
            }
            val |= (((self.data[byte_idx] >> (self.bit_pos & 7)) & 1) as u32) << i;
            self.bit_pos += 1;
        }
        Ok(val)
    }
    #[inline]
    fn align_byte(&mut self) {
        self.bit_pos = (self.bit_pos + 7) & !7;
    }
    #[inline]
    fn consumed_bytes(&self) -> usize {
        (self.bit_pos + 7) >> 3
    }
}

struct HuffmanDecoder {
    count: [u16; MAX_BITS + 1],
    symbols: [u16; 288],
}

impl HuffmanDecoder {
    fn from_lengths(lengths: &[u8]) -> Result<Self, &'static str> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            if (l as usize) > MAX_BITS {
                return Err("Huffman code length exceeds 15 bits");
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut left = 1i32;
        for bits in 1..=MAX_BITS {
            left = (left << 1) - (count[bits] as i32);
            if left < 0 {
                return Err("Over-subscribed Huffman code lengths table");
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for bits in 1..MAX_BITS {
            offs[bits + 1] = offs[bits] + count[bits];
        }
        let mut symbols = [0u16; 288];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let idx = offs[l as usize] as usize;
                if idx >= symbols.len() {
                    return Err("Huffman symbol table overflow");
                }
                symbols[idx] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Self { count, symbols })
    }
    fn fixed_lit_len() -> Self {
        let mut lengths = [0u8; 288];
        lengths[0..=143].fill(8);
        lengths[144..=255].fill(9);
        lengths[256..=279].fill(7);
        lengths[280..=287].fill(8);
        Self::from_lengths(&lengths).expect("valid RFC 1951 fixed lit/len table")
    }
    fn fixed_dist() -> Self {
        Self::from_lengths(&[5u8; 32]).expect("valid RFC 1951 fixed dist table")
    }
    #[inline]
    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, &'static str> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= reader.read_bits(1)? as i32;
            let c = self.count[len] as i32;
            if code - c < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += c;
            first = (first + c) << 1;
            code <<= 1;
        }
        Err("Invalid Huffman code in DEFLATE stream")
    }
}

fn decode_huffman_block(
    reader: &mut BitReader<'_>,
    lit_dec: &HuffmanDecoder,
    dist_dec: &HuffmanDecoder,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    loop {
        let sym = lit_dec.decode(reader)?;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else if sym <= 285 {
            let l_idx = (sym - 257) as usize;
            let len = (LENGTH_BASE[l_idx] as usize) + (reader.read_bits(LENGTH_EXTRA[l_idx])? as usize);
            let d_sym = dist_dec.decode(reader)? as usize;
            if d_sym >= 30 {
                return Err("Reserved distance symbol in DEFLATE stream");
            }
            let dist = (DIST_BASE[d_sym] as usize) + (reader.read_bits(DIST_EXTRA[d_sym])? as usize);
            if dist == 0 || dist > out.len() {
                return Err("DEFLATE back-reference distance out of bounds");
            }
            let start = out.len() - dist;
            for i in 0..len {
                out.push(out[start + i]);
            }
        } else {
            return Err("Reserved literal/length symbol in DEFLATE stream");
        }
    }
}

/// Decompress a raw RFC 1951 DEFLATE stream, returning `(decompressed_bytes, consumed_compressed_bytes)`.
pub fn inflate_raw(deflate_bytes: &[u8]) -> Result<(Vec<u8>, usize), &'static str> {
    let mut reader = BitReader { data: deflate_bytes, bit_pos: 0 };
    let mut out = Vec::new();
    loop {
        let bfinal = reader.read_bits(1)?;
        match reader.read_bits(2)? {
            0b00 => {
                reader.align_byte();
                let p = reader.bit_pos >> 3;
                if p + 4 > deflate_bytes.len() {
                    return Err("Truncated DEFLATE stored block header");
                }
                let len = u16::from_le_bytes([deflate_bytes[p], deflate_bytes[p + 1]]);
                let nlen = u16::from_le_bytes([deflate_bytes[p + 2], deflate_bytes[p + 3]]);
                if len != !nlen {
                    return Err("DEFLATE stored block LEN/NLEN complement mismatch");
                }
                let (data_start, data_end) = (p + 4, p + 4 + (len as usize));
                if data_end > deflate_bytes.len() {
                    return Err("Truncated DEFLATE stored block payload");
                }
                out.extend_from_slice(&deflate_bytes[data_start..data_end]);
                reader.bit_pos = data_end << 3;
            }
            0b01 => decode_huffman_block(
                &mut reader,
                &HuffmanDecoder::fixed_lit_len(),
                &HuffmanDecoder::fixed_dist(),
                &mut out,
            )?,
            0b10 => {
                let hlit = (reader.read_bits(5)? as usize) + 257;
                let hdist = (reader.read_bits(5)? as usize) + 1;
                let hclen = (reader.read_bits(4)? as usize) + 4;
                if hlit > 286 || hdist > 32 {
                    return Err("Invalid HLIT/HDIST count in dynamic DEFLATE block");
                }
                let mut cl_lengths = [0u8; 19];
                for i in 0..hclen {
                    cl_lengths[CL_ORDER[i]] = reader.read_bits(3)? as u8;
                }
                let cl_dec = HuffmanDecoder::from_lengths(&cl_lengths)?;
                let total_codes = hlit + hdist;
                let mut lengths = [0u8; 320];
                let mut idx = 0usize;
                while idx < total_codes {
                    let sym = cl_dec.decode(&mut reader)?;
                    match sym {
                        0..=15 => {
                            lengths[idx] = sym as u8;
                            idx += 1;
                        }
                        16 => {
                            if idx == 0 {
                                return Err("Dynamic Huffman repeat code 16 with no previous length");
                            }
                            let (prev_len, repeat) = (lengths[idx - 1], (reader.read_bits(2)? as usize) + 3);
                            if idx + repeat > total_codes {
                                return Err("Dynamic Huffman repeat code 16 overflow");
                            }
                            lengths[idx..idx + repeat].fill(prev_len);
                            idx += repeat;
                        }
                        17 | 18 => {
                            let repeat = if sym == 17 {
                                (reader.read_bits(3)? as usize) + 3
                            } else {
                                (reader.read_bits(7)? as usize) + 11
                            };
                            if idx + repeat > total_codes {
                                return Err("Dynamic Huffman zero-repeat overflow");
                            }
                            idx += repeat;
                        }
                        _ => return Err("Invalid code-length symbol in dynamic DEFLATE block"),
                    }
                }
                let lit_dec = HuffmanDecoder::from_lengths(&lengths[..hlit])?;
                let dist_dec = HuffmanDecoder::from_lengths(&lengths[hlit..total_codes])?;
                decode_huffman_block(&mut reader, &lit_dec, &dist_dec, &mut out)?;
            }
            _ => return Err("Reserved DEFLATE block type BTYPE=11"),
        }
        if bfinal == 1 {
            break;
        }
    }
    Ok((out, reader.consumed_bytes()))
}

/// Decompress a single RFC 1950 `zlib` stream from the prefix of `zlib_stream`,
/// returning `(decompressed_bytes, consumed_zlib_bytes)`.
pub fn zlib_decompress_prefix(zlib_stream: &[u8]) -> Result<(Vec<u8>, usize), &'static str> {
    if zlib_stream.len() < 6 {
        return Err("Truncated zlib stream");
    }
    let (cmf, flg) = (zlib_stream[0], zlib_stream[1]);
    if (cmf & 0x0F) != 8 || (cmf >> 4) > 7 {
        return Err("Invalid RFC 1950 zlib CMF header");
    }
    if (((cmf as u16) << 8) | (flg as u16)) % 31 != 0 || (flg & 0x20) != 0 {
        return Err("Invalid RFC 1950 zlib FLG/FCHECK header");
    }
    let (out, deflate_consumed) = inflate_raw(&zlib_stream[2..])?;
    let t = 2 + deflate_consumed;
    if t + 4 > zlib_stream.len() {
        return Err("Truncated zlib Adler-32 trailer");
    }
    let expected = u32::from_be_bytes([zlib_stream[t], zlib_stream[t + 1], zlib_stream[t + 2], zlib_stream[t + 3]]);
    if adler32(&out) != expected {
        return Err("zlib Adler-32 checksum mismatch");
    }
    Ok((out, t + 4))
}

/// Decompress an RFC 1950 `zlib` byte slice and verify its Adler-32 trailer.
pub fn zlib_decompress(zlib_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    zlib_decompress_prefix(zlib_bytes).map(|(out, _)| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_rfc1950_wikipedia_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn zlib_roundtrip_empty_short_and_repetitive_4k_payload() {
        let empty = zlib_compress(b"");
        assert_eq!(&empty[0..2], &[0x78, 0x9C]);
        assert_eq!(zlib_decompress(&empty).unwrap(), b"");
        let short = b"Webizen human-centric Git object storage and RFC 1950/1951 codec";
        assert_eq!(zlib_decompress(&zlib_compress(short)).unwrap(), short);
        let line = b"@prefix wc: <https://ns.webcivics.net/core#> .\nwc:Agent1 a wc:NaturalAgent ; wc:steward <did:qi:alice> .\n";
        let mut repetitive = Vec::with_capacity(4096);
        while repetitive.len() < 4096 {
            repetitive.extend_from_slice(line);
        }
        let compressed = zlib_compress(&repetitive);
        assert!(compressed.len() * 2 < repetitive.len());
        assert_eq!(zlib_decompress(&compressed).unwrap(), repetitive);
    }

    #[test]
    fn zlib_decompress_prefix_stored_block_and_tamper_detection() {
        let s1 = zlib_compress(b"commit 120\0tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
        let s2 = zlib_compress(b"blob 14\0Hello Webizen\n");
        let mut pack = [s1.as_slice(), s2.as_slice()].concat();
        let (d1, c1) = zlib_decompress_prefix(&pack).unwrap();
        assert_eq!((c1, d1.as_slice()), (s1.len(), &b"commit 120\0tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"[..]));
        let (d2, c2) = zlib_decompress_prefix(&pack[c1..]).unwrap();
        assert_eq!((c2, d2.as_slice()), (s2.len(), &b"blob 14\0Hello Webizen\n"[..]));
        let raw_stored = [0x01, 0x03, 0x00, 0xFC, 0xFF, b'G', b'i', b't'];
        assert_eq!(inflate_raw(&raw_stored).unwrap(), (b"Git".to_vec(), 8));
        let mut tampered_trailer = s2.clone();
        *tampered_trailer.last_mut().unwrap() ^= 0x01;
        assert_eq!(zlib_decompress(&tampered_trailer), Err("zlib Adler-32 checksum mismatch"));
        pack[3] ^= 0x04;
        assert!(zlib_decompress_prefix(&pack).is_err());
    }
}
