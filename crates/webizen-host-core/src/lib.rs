//! Foundational 48-byte `NQuin` ABI, compile-time FNV-1a `q_hash()`, 60-bit masked tokens,
//! and Human-Centric / International Human-Rights invariants for `webizen-host`.
//!
//! Adheres strictly to `AGENTS.md`:
//! - Zero heap in hot paths (`HotZeroHeap`)
//! - 48-byte `NQuin` universal layout
//! - Human-Centric nomenclature (never using "sovereign" or "self-sovereign")
//! - SHACL-First Non-`owl:Thing` invariant for natural persons, kinship, human relations, and living entities

pub const QUIN_SIZE: usize = 48;
pub const SUPERBLOCK_SIZE: usize = 40_960;
pub const SUPERBLOCK_HEADER_BYTES: usize = 160;
pub const QUINS_PER_SUPERBLOCK: usize = 850;
pub const DEFAULT_COLD_ARENA_BUDGET_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
pub const SLG_ARENA_CELL_BYTES: usize = 42 * 1024 * 1024; // 42 MiB Sentinel cell

// Modality opcodes (AGENTS.md §0 & §1)
pub const OP_OBLIGATE: u8 = 0x10;
pub const OP_PERMIT: u8 = 0x11;
pub const OP_FORBID: u8 = 0x12;
pub const OP_KNOWS: u8 = 0x20;
pub const OP_BELIEVES: u8 = 0x21;
pub const OP_COMMON_KNOWLEDGE: u8 = 0x22;
pub const OP_PARACONSISTENT_BOTH: u8 = 0x30;
pub const OP_PARACONSISTENT_ISOLATE: u8 = 0x31;
pub const OP_PARACONSISTENT_REVIEW: u8 = 0x32;
pub const OP_LTL_GLOBALLY: u8 = 0x40;
pub const OP_LTL_FINALLY: u8 = 0x41;
pub const OP_LTL_NEXT: u8 = 0x42;
pub const OP_LTL_UNTIL: u8 = 0x43;
pub const OP_LTL_RELEASE: u8 = 0x44;
pub const OP_COMMONS_OBLIGATION_POOL: u8 = 0x58;
pub const OP_AUTHORIZATION_GRANT: u8 = 0x70;
pub const OP_RESOURCE_DECLARATION: u8 = 0x71;
pub const OP_PERFORMANCE_RATING: u8 = 0x72;

// Object inline type tags when MSB=0 (resolver.rs authoritative layout)
pub const INLINE_TAG_IRI: u64 = 0b000 << 60;
pub const INLINE_TAG_INTEGER: u64 = 0b001 << 60;
pub const INLINE_TAG_DECIMAL: u64 = 0b010 << 60;
pub const INLINE_TAG_BOOLEAN: u64 = 0b011 << 60;
pub const DID_Q42_MSB: u64 = 1u64 << 63;
pub const DEFEATER_BIT: u64 = 1u64 << 63;
pub const TOKEN_60BIT_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

/// Sensitivity class in `context[56..63]`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensitivityClass {
    Public = 0,
    Restricted = 1,
    Classified = 2,
}

/// Permissive routing lane in `metadata[61..62]`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissiveRoutingLane {
    Passthrough = 0b00,
    EnforcePermissiveCommons = 0b01,
    EnforceBilateralMicroCommons = 0b10,
    Spatial = 0b11,
}

/// Universal 48-byte `NQuin` semantic quad (`repr(C)`, 6 × `u64` = 48 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NQuin {
    pub subject: u64,
    pub predicate: u64,
    pub object: u64,
    pub context: u64,
    pub metadata: u64,
    pub parity: u64,
}

const _: () = assert!(
    core::mem::size_of::<NQuin>() == QUIN_SIZE,
    "NQuin must be exactly 48 bytes"
);

impl NQuin {
    /// Construct a parity-sealed 48-byte `NQuin`.
    #[inline]
    pub const fn new(
        subject: u64,
        predicate: u64,
        object: u64,
        context: u64,
        metadata: u64,
    ) -> Self {
        let parity = subject ^ predicate ^ object ^ context ^ metadata;
        Self {
            subject,
            predicate,
            object,
            context,
            metadata,
            parity,
        }
    }

    /// Verify the XOR parity field (`subject ^ predicate ^ object ^ context ^ metadata`).
    #[inline]
    pub const fn verify_parity(&self) -> bool {
        self.parity == (self.subject ^ self.predicate ^ self.object ^ self.context ^ self.metadata)
    }

    /// Extract the modality opcode from `predicate[0..7]`.
    #[inline]
    pub const fn opcode(&self) -> u8 {
        (self.predicate & 0xFF) as u8
    }

    /// Extract the `PermissiveRoutingLane` from `metadata[61..62]`.
    #[inline]
    pub const fn routing_lane(&self) -> PermissiveRoutingLane {
        match ((self.metadata >> 61) & 0b11) as u8 {
            0b00 => PermissiveRoutingLane::Passthrough,
            0b01 => PermissiveRoutingLane::EnforcePermissiveCommons,
            0b10 => PermissiveRoutingLane::EnforceBilateralMicroCommons,
            _ => PermissiveRoutingLane::Spatial,
        }
    }

    /// Extract the `SensitivityClass` from `context[56..63]`.
    #[inline]
    pub const fn sensitivity(&self) -> SensitivityClass {
        match ((self.context >> 56) & 0xFF) as u8 {
            0 => SensitivityClass::Public,
            1 => SensitivityClass::Restricted,
            _ => SensitivityClass::Classified,
        }
    }

    /// Encode this `NQuin` into a caller-supplied 48-byte little-endian array (zero heap).
    #[inline]
    pub fn to_le_bytes(&self) -> [u8; QUIN_SIZE] {
        let mut out = [0u8; QUIN_SIZE];
        out[0..8].copy_from_slice(&self.subject.to_le_bytes());
        out[8..16].copy_from_slice(&self.predicate.to_le_bytes());
        out[16..24].copy_from_slice(&self.object.to_le_bytes());
        out[24..32].copy_from_slice(&self.context.to_le_bytes());
        out[32..40].copy_from_slice(&self.metadata.to_le_bytes());
        out[40..48].copy_from_slice(&self.parity.to_le_bytes());
        out
    }

    /// Decode a 48-byte little-endian slice into an `NQuin` (zero heap).
    #[inline]
    pub fn from_le_bytes(bytes: &[u8; QUIN_SIZE]) -> Self {
        Self {
            subject: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            predicate: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            object: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            context: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            metadata: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            parity: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
        }
    }
}

/// Compile-time and runtime 64-bit FNV-1a hash (`q_hash`) for IRIs and domain labels.
#[inline]
pub const fn q_hash(text: &str) -> u64 {
    q_hash_bytes(text.as_bytes())
}

/// Compile-time and runtime 64-bit FNV-1a hash over raw bytes.
#[inline]
pub const fn q_hash_bytes(bytes: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Generate a 60-bit masked lexicon token (`lexicon.rs` contract, reserving bits 60..63 for tags).
#[inline]
pub const fn generate_60bit_token(text: &str) -> u64 {
    q_hash(text) & TOKEN_60BIT_MASK
}

/// Parse a `did:q42:` topological pointer with MSB bit 63 always set (`identifier.rs` contract).
#[inline]
pub fn parse_did_q42(uri: &str) -> Option<u64> {
    let payload = uri.strip_prefix("did:q42:")?;
    if payload.is_empty() {
        return None;
    }
    Some(q_hash(payload) | DID_Q42_MSB)
}

/// Pack a property IRI hash (`bits [8..62]`), a `u8` modality opcode (`bits [0..7]`),
/// and `DEFEATER_BIT` (`bit 63`) into the `predicate` field (`AGENTS.md` §1).
#[inline]
pub const fn pack_predicate(property_iri: &str, opcode: u8, is_defeater: bool) -> u64 {
    let base = ((q_hash(property_iri) << 8) & !DEFEATER_BIT) | (opcode as u64);
    if is_defeater {
        base | DEFEATER_BIT
    } else {
        base
    }
}

/// Pack `SensitivityClass` and a context/graph DID hash into `context`.
#[inline]
pub const fn pack_context(graph_did_hash: u64, sensitivity: SensitivityClass) -> u64 {
    (graph_did_hash & 0x00FF_FFFF_FFFF_FFFF) | ((sensitivity as u64) << 56)
}

/// Pack `PermissiveRoutingLane`, 29-bit Lamport clock, and 32-bit payload into `metadata`.
#[inline]
pub const fn pack_metadata(
    lane: PermissiveRoutingLane,
    lamport_clock: u32,
    payload_u32: u32,
) -> u64 {
    ((lane as u64) << 61) | (((lamport_clock as u64) & 0x1FFF_FFFF) << 32) | (payload_u32 as u64)
}

/// Check whether a class URI represents a human-centric or living entity that is strictly
/// forbidden from subclassing `owl:Thing` (`docs/manuals/standards/shacl-first-vs-owl-ok-class-list.md`).
pub fn is_non_thing_human_or_living_class(class_uri: &str) -> bool {
    let lower = class_uri.to_ascii_lowercase();
    const NON_THING_MARKERS: &[&str] = &[
        "naturalagent",
        "naturalperson",
        "person",
        "human",
        "child",
        "infant",
        "dependent",
        "guardian",
        "guardianship",
        "kinship",
        "family",
        "household",
        "citizen",
        "darwiniantaxon",
        "species",
        "livingentity",
        "flora",
        "fauna",
    ];
    NON_THING_MARKERS.iter().any(|m| lower.contains(m))
}

/// Verify that text/labels adhere to the Human-Centric / International Human-Rights nomenclature rule
/// (never using the prohibited term "sovereign" or "self-sovereign" for natural persons or systems).
pub fn validate_human_centric_nomenclature(text: &str) -> Result<(), &'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("sovereign") {
        return Err(
            "Prohibited nomenclature detected: use human-centric and international human-rights terminology instead of 'sovereign'",
        );
    }
    Ok(())
}

///Deterministic CRC-32C (Castagnoli) implementation (zero heap).
pub fn crc32c_bytes(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

pub mod cbor_ld;
pub use cbor_ld::{
    decode_quin_cbor_ld_zero_heap, encode_quin_cbor_ld_zero_heap, encode_quins_graph_cbor_ld,
    write_cbor_major_len, write_cbor_text, CBOR_LD_MEDIA_TYPE, CBOR_LD_QUIN_WIRE_SIZE,
    CBOR_LD_TAG_COMPRESSED, CBOR_LD_TAG_UNCOMPRESSED, WEBCIVICS_CBOR_LD_CONTEXT_TOKEN,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nquin_is_48_bytes_and_roundtrips_zero_heap() {
        assert_eq!(core::mem::size_of::<NQuin>(), 48);
        let q = NQuin::new(
            q_hash("did:qi:alice"),
            pack_predicate("https://ns.webcivics.net/deontic#obligates", OP_OBLIGATE, false),
            INLINE_TAG_INTEGER | 42,
            pack_context(q_hash("https://ns.webcivics.net/graph/commons"), SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 7, 1000),
        );
        assert!(q.verify_parity());
        assert_eq!(q.opcode(), OP_OBLIGATE);
        assert_eq!(q.routing_lane(), PermissiveRoutingLane::EnforcePermissiveCommons);
        assert_eq!(q.sensitivity(), SensitivityClass::Public);

        let bytes = q.to_le_bytes();
        let decoded = NQuin::from_le_bytes(&bytes);
        assert_eq!(decoded, q);
        assert!(decoded.verify_parity());
    }

    #[test]
    fn non_thing_and_nomenclature_guards_enforce_human_rights_rules() {
        assert!(is_non_thing_human_or_living_class(
            "https://ns.webcivics.net/agent#NaturalAgent"
        ));
        assert!(is_non_thing_human_or_living_class(
            "https://ns.webcivics.net/care#InfantDependent"
        ));
        assert!(!is_non_thing_human_or_living_class(
            "https://ns.webcivics.net/q42#VolumeHeader"
        ));

        assert!(validate_human_centric_nomenclature(
            "Human-Centric VPS Hosting Platform with Guardianship & Capacity Semantics"
        )
        .is_ok());
        assert!(validate_human_centric_nomenclature("Self-Sovereign Identity").is_err());
    }
}
