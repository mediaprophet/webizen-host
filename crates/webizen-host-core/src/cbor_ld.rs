//! Native W3C CBOR-LD (`application/cbor-ld`) Zero-Heap & Graph Codec for `webizen-host`.
//!
//! Replaces JSON / JSON-LD as the native structured wire, API, and SPARQL result format across
//! `webizen-host` and VibeScript (`VBC1`).
//!
//! ## Wire Layout (Compressed CBOR-LD Tag `0x0501` = 1281, Header `[0xD9, 0x05, 0x01]`)
//! - `0xD9, 0x05, 0x01` — 2-byte CBOR Tag `1281` (Compressed CBOR-LD document)
//! - Single-`NQuin` zero-heap record (`HotZeroHeap`, fixed 68 bytes):
//!   - `0xA7` — CBOR map of 7 integer-compressed term keys:
//!     - Key `1` (`@context` token): `u64` (`0x1B` + 8-byte BE)
//!     - Key `2` (`@id` / `subject`): `u64` (`0x1B` + 8-byte BE)
//!     - Key `3` (`predicate` + opcode): `u64` (`0x1B` + 8-byte BE)
//!     - Key `4` (`object` token/inline): `u64` (`0x1B` + 8-byte BE)
//!     - Key `5` (`context` + sensitivity): `u64` (`0x1B` + 8-byte BE)
//!     - Key `6` (`metadata` + routing lane): `u64` (`0x1B` + 8-byte BE)
//!     - Key `7` (`parity` XOR fold): `u64` (`0x1B` + 8-byte BE)

use crate::{q_hash, NQuin};

/// Canonical MIME media type for native CBOR-LD payloads.
pub const CBOR_LD_MEDIA_TYPE: &str = "application/cbor-ld";

/// W3C CBOR-LD Uncompressed Tag (`0x0500` = 1280).
pub const CBOR_LD_TAG_UNCOMPRESSED: u16 = 0x0500;

/// W3C CBOR-LD Compressed Tag (`0x0501` = 1281).
pub const CBOR_LD_TAG_COMPRESSED: u16 = 0x0501;

/// Exact byte length of a single zero-heap CBOR-LD encoded `NQuin` (`3` tag bytes + `1` map header + `7 * 10` key/val bytes = 74 bytes).
pub const CBOR_LD_QUIN_WIRE_SIZE: usize = 74;

/// Default WebCivics Human-Centric CBOR-LD `@context` registry token.
pub const WEBCIVICS_CBOR_LD_CONTEXT_TOKEN: u64 = 0x5745_4243_4956_4C44; // "WEBCIVLD"

/// Encode a single 48-byte `NQuin` into a caller-supplied `&mut [u8]` slice as a compressed
/// W3C CBOR-LD document (`0xD9 0x05 0x01`) with **zero heap allocation (`HotZeroHeap`)**.
#[inline]
pub fn encode_quin_cbor_ld_zero_heap(
    quin: &NQuin,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    if out.len() < CBOR_LD_QUIN_WIRE_SIZE {
        return Err("Caller output buffer too small for CBOR-LD NQuin (requires 74 bytes)");
    }
    // CBOR Tag 1281 (0x0501): Major type 6 (0xC0 | 25 = 0xD9), followed by 0x05, 0x01
    out[0] = 0xD9;
    out[1] = 0x05;
    out[2] = 0x01;
    // CBOR Map of 7 pairs: Major type 5 (0xA0 | 7 = 0xA7)
    out[3] = 0xA7;

    let fields: [(u8, u64); 7] = [
        (1, WEBCIVICS_CBOR_LD_CONTEXT_TOKEN),
        (2, quin.subject),
        (3, quin.predicate),
        (4, quin.object),
        (5, quin.context),
        (6, quin.metadata),
        (7, quin.parity),
    ];

    let mut pos = 4usize;
    let mut i = 0usize;
    while i < 7 {
        let (key_id, val) = fields[i];
        out[pos] = key_id; // CBOR unsigned int 1..7 (Major type 0, inline < 24)
        out[pos + 1] = 0x1B; // CBOR uint64 (Major type 0, additional info 27)
        out[pos + 2..pos + 10].copy_from_slice(&val.to_be_bytes());
        pos += 10;
        i += 1;
    }

    Ok(CBOR_LD_QUIN_WIRE_SIZE)
}

/// Decode a compressed W3C CBOR-LD (`0xD9 0x05 0x01`) byte slice back into a parity-verified
/// 48-byte `NQuin` with **zero heap allocation (`HotZeroHeap`)**.
#[inline]
pub fn decode_quin_cbor_ld_zero_heap(bytes: &[u8]) -> Result<NQuin, &'static str> {
    if bytes.len() < CBOR_LD_QUIN_WIRE_SIZE {
        return Err("CBOR-LD input slice shorter than 74 bytes");
    }
    if bytes[0] != 0xD9 || bytes[1] != 0x05 || (bytes[2] != 0x01 && bytes[2] != 0x00) {
        return Err("Missing W3C CBOR-LD tag header (0xD9 0x05 0x01)");
    }
    if bytes[3] != 0xA7 {
        return Err("Expected 7-entry CBOR-LD NQuin map header (0xA7)");
    }

    let mut vals = [0u64; 7];
    let mut pos = 4usize;
    let mut i = 0usize;
    while i < 7 {
        let expected_key = (i + 1) as u8;
        if bytes[pos] != expected_key || bytes[pos + 1] != 0x1B {
            return Err("Invalid CBOR-LD NQuin map key or uint64 marker");
        }
        let raw: [u8; 8] = bytes[pos + 2..pos + 10]
            .try_into()
            .map_err(|_| "Invalid CBOR-LD uint64 slice")?;
        vals[i] = u64::from_be_bytes(raw);
        pos += 10;
        i += 1;
    }

    let quin = NQuin {
        subject: vals[1],
        predicate: vals[2],
        object: vals[3],
        context: vals[4],
        metadata: vals[5],
        parity: vals[6],
    };
    if !quin.verify_parity() {
        return Err("Decoded CBOR-LD NQuin failed XOR parity verification");
    }
    Ok(quin)
}

/// Encode a slice of `NQuin`s into a single W3C CBOR-LD (`0xD9 0x05 0x01`) `@graph` document.
pub fn encode_quins_graph_cbor_ld(quins: &[NQuin], context_iri: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + quins.len() * CBOR_LD_QUIN_WIRE_SIZE);
    // Tag 1281 (0xD9 0x05 0x01)
    buf.extend_from_slice(&[0xD9, 0x05, 0x01]);
    // Top-level map with 2 entries: 1 = @context hash, 8 = @graph array
    buf.push(0xA2);
    // Key 1 (@context): uint64 q_hash(context_iri)
    buf.push(0x01);
    buf.push(0x1B);
    buf.extend_from_slice(&q_hash(context_iri).to_be_bytes());
    // Key 8 (@graph): CBOR array of length `quins.len()`
    buf.push(0x08);
    write_cbor_major_len(&mut buf, 4, quins.len() as u64);

    let mut scratch = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
    for q in quins {
        let n = encode_quin_cbor_ld_zero_heap(q, &mut scratch).unwrap();
        // Push the inner 70-byte CBOR map (`scratch[3..n]`) inside the @graph array
        buf.extend_from_slice(&scratch[3..n]);
    }
    buf
}

/// Write a CBOR major type (`0..=7`) and length header.
#[inline]
pub fn write_cbor_major_len(buf: &mut Vec<u8>, major: u8, len: u64) {
    if len < 24 {
        buf.push((major << 5) | (len as u8));
    } else if len <= 0xFF {
        buf.push((major << 5) | 24);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFF_FFFF {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&len.to_be_bytes());
    }
}

/// Write a CBOR text string (Major type 3).
#[inline]
pub fn write_cbor_text(buf: &mut Vec<u8>, text: &str) {
    write_cbor_major_len(buf, 3, text.len() as u64);
    buf.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pack_context, pack_metadata, pack_predicate, PermissiveRoutingLane, SensitivityClass,
        INLINE_TAG_INTEGER, OP_OBLIGATE,
    };

    #[test]
    fn cbor_ld_zero_heap_quin_roundtrips_and_verifies_tag_0501() {
        let q = NQuin::new(
            q_hash("did:qi:alice"),
            pack_predicate("https://ns.webcivics.net/deontic#obligates", OP_OBLIGATE, false),
            INLINE_TAG_INTEGER | 108,
            pack_context(q_hash("https://ns.webcivics.net/graph/commons"), SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 12, 2026),
        );

        let mut wire = [0u8; CBOR_LD_QUIN_WIRE_SIZE];
        let written = encode_quin_cbor_ld_zero_heap(&q, &mut wire).unwrap();
        assert_eq!(written, CBOR_LD_QUIN_WIRE_SIZE);
        assert_eq!(&wire[0..3], &[0xD9, 0x05, 0x01]);

        let decoded = decode_quin_cbor_ld_zero_heap(&wire).unwrap();
        assert_eq!(decoded, q);
        assert!(decoded.verify_parity());

        let graph_bytes = encode_quins_graph_cbor_ld(&[q], "https://ns.webcivics.net/context");
        assert_eq!(&graph_bytes[0..3], &[0xD9, 0x05, 0x01]);
    }
}
