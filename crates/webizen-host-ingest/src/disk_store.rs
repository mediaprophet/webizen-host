//! On-disk `.q42` v4 binary persistence, HTTP 206 byte-range / `QualiaSuperBlock` slice readers,
//! and `.q42j` append-only `NQuin` journal storage with CRC-32C and XOR parity verification.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use webizen_host_core::{crc32c_bytes, NQuin, QUIN_SIZE, SUPERBLOCK_SIZE, TOKEN_60BIT_MASK};

use crate::{CompiledQ42Volume, Q42LexV4};

/// 4-byte file magic for `.q42` v4 binary volumes on disk.
pub const Q42_FILE_MAGIC: [u8; 4] = *b"Q42\x04";

/// Fixed 256-byte `.q42` v4 file header length.
pub const Q42_HEADER_SIZE: usize = 256;

/// Fixed 52-byte `.q42j` append-only journal record length (48-byte `NQuin` LE + 4-byte `crc32c` LE).
pub const Q42J_RECORD_SIZE: usize = QUIN_SIZE + 4;

/// Compute the deterministic CRC-32C checksum across a slice of 40,960-byte `QualiaSuperBlock`s.
pub fn compute_superblocks_crc32c(superblocks: &[[u8; SUPERBLOCK_SIZE]]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = !0u32;
    for block in superblocks {
        for &b in block.iter() {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (POLY & mask);
            }
        }
    }
    !crc
}

fn serialize_lexicon_entries(lexicon: &Q42LexV4) -> Vec<u8> {
    let mut buf = Vec::new();
    for (&token, &(ns_id, ref local)) in &lexicon.entries {
        let prefix = lexicon
            .namespaces
            .iter()
            .find_map(|(k, &v)| if v == ns_id { Some(k.as_str()) } else { None })
            .unwrap_or("");
        let full = format!("{prefix}{local}");
        let raw = full.as_bytes();
        buf.extend_from_slice(&token.to_le_bytes());
        buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        buf.extend_from_slice(raw);
    }
    buf
}

fn deserialize_lexicon_entries(bytes: &[u8]) -> io::Result<Q42LexV4> {
    let mut lexicon = Q42LexV4::default();
    let mut off = 0usize;
    while off < bytes.len() {
        if off + 12 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated Q42LEX entry header",
            ));
        }
        let token = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) & TOKEN_60BIT_MASK;
        let len = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 12;
        if off + len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated Q42LEX entry payload",
            ));
        }
        let term = std::str::from_utf8(&bytes[off..off + len]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in Q42LEX entry")
        })?;
        off += len;
        let (ns, local) = Q42LexV4::split_namespace(term);
        let ns_id = if let Some(&id) = lexicon.namespaces.get(ns) {
            id
        } else {
            let next_id = lexicon.namespaces.len() as u16;
            lexicon.namespaces.insert(ns.to_string(), next_id);
            lexicon.used_bytes += ns.len() + 2;
            next_id
        };
        lexicon.used_bytes += local.len() + 10;
        lexicon.entries.insert(token, (ns_id, local.to_string()));
    }
    Ok(lexicon)
}

impl CompiledQ42Volume {
    /// Write the complete binary `.q42` v4 volume to `path` and flush to disk, returning total bytes written.
    pub fn write_to_disk(&self, path: &Path) -> io::Result<u64> {
        let sb_count = self.superblocks.len() as u64;
        let bidx_count = self.bidx_ranges.len() as u64;
        let total_quins: u64 = self
            .superblocks
            .iter()
            .map(|sb| u64::from_le_bytes(sb[16..24].try_into().unwrap()))
            .sum();
        let sb_crc32c = compute_superblocks_crc32c(&self.superblocks);
        let lex_bytes = serialize_lexicon_entries(&self.lexicon);
        let lexicon_byte_len = lex_bytes.len() as u64;

        let mut header = [0u8; Q42_HEADER_SIZE];
        header[0..4].copy_from_slice(&Q42_FILE_MAGIC);
        header[8..16].copy_from_slice(&sb_count.to_le_bytes());
        header[16..24].copy_from_slice(&total_quins.to_le_bytes());
        header[24..28].copy_from_slice(&(self.flags as u32).to_le_bytes());
        header[28..32].copy_from_slice(&sb_crc32c.to_le_bytes());
        header[32..40].copy_from_slice(&bidx_count.to_le_bytes());
        header[40..48].copy_from_slice(&lexicon_byte_len.to_le_bytes());
        header[48..56].copy_from_slice(&(self.quarantined_triples as u64).to_le_bytes());

        let mut file = File::create(path)?;
        file.write_all(&header)?;
        for &(min_obj, max_obj) in &self.bidx_ranges {
            file.write_all(&min_obj.to_le_bytes())?;
            file.write_all(&max_obj.to_le_bytes())?;
        }
        for sb in &self.superblocks {
            file.write_all(sb)?;
        }
        file.write_all(&lex_bytes)?;
        file.flush()?;

        let total_bytes = (Q42_HEADER_SIZE as u64)
            + bidx_count * 16
            + sb_count * (SUPERBLOCK_SIZE as u64)
            + lexicon_byte_len;
        Ok(total_bytes)
    }

    /// Load and verify a binary `.q42` v4 volume from `path`, checking `Q42\x04` magic and `CRC-32C` across all superblocks.
    pub fn load_from_disk(path: &Path) -> io::Result<CompiledQ42Volume> {
        let mut file = File::open(path)?;
        let mut header = [0u8; Q42_HEADER_SIZE];
        file.read_exact(&mut header)?;
        if header[0..4] != Q42_FILE_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid .q42 v4 file magic",
            ));
        }

        let sb_count = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
        let flags = u32::from_le_bytes(header[24..28].try_into().unwrap()) as u16;
        let expected_crc = u32::from_le_bytes(header[28..32].try_into().unwrap());
        let bidx_count = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
        let lexicon_byte_len = u64::from_le_bytes(header[40..48].try_into().unwrap()) as usize;
        let quarantined_triples = u64::from_le_bytes(header[48..56].try_into().unwrap()) as usize;

        let mut bidx_ranges = Vec::with_capacity(bidx_count);
        for _ in 0..bidx_count {
            let mut entry = [0u8; 16];
            file.read_exact(&mut entry)?;
            let min_obj = u64::from_le_bytes(entry[0..8].try_into().unwrap());
            let max_obj = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            bidx_ranges.push((min_obj, max_obj));
        }

        let mut superblocks = Vec::with_capacity(sb_count);
        for _ in 0..sb_count {
            let mut sb = [0u8; SUPERBLOCK_SIZE];
            file.read_exact(&mut sb)?;
            superblocks.push(sb);
        }

        let actual_crc = compute_superblocks_crc32c(&superblocks);
        if actual_crc != expected_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "superblock CRC-32C checksum mismatch",
            ));
        }

        let mut lex_buf = vec![0u8; lexicon_byte_len];
        file.read_exact(&mut lex_buf)?;
        let lexicon = deserialize_lexicon_entries(&lex_buf)?;
        let peak_cold_bytes_used = sb_count * SUPERBLOCK_SIZE + lexicon.used_bytes;

        Ok(CompiledQ42Volume {
            flags,
            superblocks,
            bidx_ranges,
            lexicon,
            payload_catalogue: Vec::new(),
            uplifted_shacl_shapes: Vec::new(),
            quarantined_triples,
            peak_cold_bytes_used,
        })
    }

    /// Read ONLY the requested `[start_byte..=end_byte_inclusive]` window from disk via `Seek`.
    pub fn read_file_byte_range(
        path: &Path,
        start_byte: u64,
        end_byte_inclusive: u64,
    ) -> io::Result<(u64, Vec<u8>)> {
        read_file_byte_range(path, start_byte, end_byte_inclusive)
    }

    /// Seek directly to the `block_index`-th 40,960-byte `QualiaSuperBlock` on disk and read only those 40,960 bytes.
    pub fn read_superblock_slice_from_disk(
        path: &Path,
        block_index: usize,
    ) -> io::Result<[u8; SUPERBLOCK_SIZE]> {
        read_superblock_slice_from_disk(path, block_index)
    }
}

/// Read ONLY the requested `[start_byte..=end_byte_inclusive]` window from disk without reading the whole file,
/// returning `(total_file_bytes, slice_bytes)` for real `HTTP 206 Partial Content` serving.
pub fn read_file_byte_range(
    path: &Path,
    start_byte: u64,
    end_byte_inclusive: u64,
) -> io::Result<(u64, Vec<u8>)> {
    if end_byte_inclusive < start_byte {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "end_byte_inclusive must be >= start_byte",
        ));
    }
    let mut file = File::open(path)?;
    let total_file_bytes = file.metadata()?.len();
    let window_len = end_byte_inclusive
        .checked_sub(start_byte)
        .and_then(|d| d.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "byte range overflow"))?
        as usize;
    file.seek(SeekFrom::Start(start_byte))?;
    let mut buf = vec![0u8; window_len];
    file.read_exact(&mut buf)?;
    Ok((total_file_bytes, buf))
}

/// Seek directly to the `block_index`-th 40,960-byte `QualiaSuperBlock` on disk and read only those 40,960 bytes.
pub fn read_superblock_slice_from_disk(
    path: &Path,
    block_index: usize,
) -> io::Result<[u8; SUPERBLOCK_SIZE]> {
    let mut file = File::open(path)?;
    let mut header = [0u8; Q42_HEADER_SIZE];
    file.read_exact(&mut header)?;
    if header[0..4] != Q42_FILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid .q42 v4 file magic",
        ));
    }
    let sb_count = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    let bidx_count = u64::from_le_bytes(header[32..40].try_into().unwrap());
    if block_index >= sb_count {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "superblock index out of bounds",
        ));
    }
    let offset = (Q42_HEADER_SIZE as u64)
        + bidx_count * 16
        + (block_index as u64) * (SUPERBLOCK_SIZE as u64);
    file.seek(SeekFrom::Start(offset))?;
    let mut block = [0u8; SUPERBLOCK_SIZE];
    file.read_exact(&mut block)?;
    Ok(block)
}

/// Read only the 256-byte `.q42` v4 header, `BIDX` object-range index, and `Q42LEX` trailer from disk
/// via `Seek`—skipping the 40,960-byte `QualiaSuperBlock` payload region.
pub fn read_q42_index_and_lexicon_from_disk(
    path: &Path,
) -> io::Result<(u16, usize, Vec<(u64, u64)>, Q42LexV4)> {
    let mut file = File::open(path)?;
    let mut header = [0u8; Q42_HEADER_SIZE];
    file.read_exact(&mut header)?;
    if header[0..4] != Q42_FILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid .q42 v4 file magic",
        ));
    }
    let sb_count = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(header[24..28].try_into().unwrap()) as u16;
    let bidx_count = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
    let lexicon_byte_len = u64::from_le_bytes(header[40..48].try_into().unwrap()) as usize;

    let mut bidx_ranges = Vec::with_capacity(bidx_count);
    for _ in 0..bidx_count {
        let mut entry = [0u8; 16];
        file.read_exact(&mut entry)?;
        let min_obj = u64::from_le_bytes(entry[0..8].try_into().unwrap());
        let max_obj = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        bidx_ranges.push((min_obj, max_obj));
    }

    let lex_offset = (Q42_HEADER_SIZE as u64)
        + (bidx_count as u64) * 16
        + (sb_count as u64) * (SUPERBLOCK_SIZE as u64);
    file.seek(SeekFrom::Start(lex_offset))?;
    let mut lex_buf = vec![0u8; lexicon_byte_len];
    file.read_exact(&mut lex_buf)?;
    let lexicon = deserialize_lexicon_entries(&lex_buf)?;
    Ok((flags, sb_count, bidx_ranges, lexicon))
}

/// Verify `quin.verify_parity()` and append a 52-byte record (48-byte LE `NQuin` + 4-byte LE `crc32c`) to `journal_path`.
pub fn append_quin_to_journal(journal_path: &Path, quin: &NQuin) -> io::Result<()> {
    if !quin.verify_parity() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NQuin parity verification failed before journal append",
        ));
    }
    let quin_bytes = quin.to_le_bytes();
    let crc = crc32c_bytes(&quin_bytes);
    let mut record = [0u8; Q42J_RECORD_SIZE];
    record[0..QUIN_SIZE].copy_from_slice(&quin_bytes);
    record[QUIN_SIZE..Q42J_RECORD_SIZE].copy_from_slice(&crc.to_le_bytes());

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    file.write_all(&record)?;
    file.flush()
}

/// Read all 52-byte records from `journal_path`, verifying both the 4-byte `crc32c` and `quin.verify_parity()`
/// on every entry and failing closed with `InvalidData` if any record is corrupted.
pub fn replay_quin_journal(journal_path: &Path) -> io::Result<Vec<NQuin>> {
    let mut file = File::open(journal_path)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    if raw.len() % Q42J_RECORD_SIZE != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupted .q42j journal: file size is not a multiple of 52 bytes",
        ));
    }
    let mut out = Vec::with_capacity(raw.len() / Q42J_RECORD_SIZE);
    for rec in raw.chunks_exact(Q42J_RECORD_SIZE) {
        let quin_bytes: &[u8; QUIN_SIZE] = rec[0..QUIN_SIZE].try_into().unwrap();
        let stored_crc = u32::from_le_bytes(rec[QUIN_SIZE..Q42J_RECORD_SIZE].try_into().unwrap());
        if crc32c_bytes(quin_bytes) != stored_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupted .q42j journal: record CRC-32C mismatch",
            ));
        }
        let quin = NQuin::from_le_bytes(quin_bytes);
        if !quin.verify_parity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupted .q42j journal: NQuin parity check failed",
            ));
        }
        out.push(quin);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceEnvelope, StreamingOntologyCompiler};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_core::{
        pack_context, pack_metadata, pack_predicate, q_hash, PermissiveRoutingLane,
        SensitivityClass, OP_OBLIGATE,
    };

    struct ScopedTempDir {
        path: PathBuf,
    }

    impl ScopedTempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "qualia_webizen_disk_store_{}_{}_{}",
                label,
                std::process::id(),
                id
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { path: dir }
        }
    }

    impl Drop for ScopedTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn q42_disk_roundtrip_range_slice_and_journal_tamper_rejection() {
        let temp = ScopedTempDir::new("roundtrip");
        let q42_path = temp.path.join("webcivics_ns.q42");
        let journal_path = temp.path.join("ledger.q42j");

        let compiler = StreamingOntologyCompiler::default();
        let envelope = SourceEnvelope {
            repo_url: "https://github.com/WebCivics/ns".to_string(),
            commit_hash: "abcdef012345".to_string(),
            spdx_license: "SocialPermissiveCommons".to_string(),
            production_cost_cents: 25_000,
            roi_cap_percent: 150,
        };
        let vol = compiler
            .compile_chunks(
                &envelope,
                &[
                    "<https://ns.webcivics.net/agent#NaturalAgent> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> .",
                    "<https://ns.webcivics.net/care#Guardianship> <https://ns.webcivics.net/hr#supports> <https://ns.webcivics.net/agent#NaturalAgent> .",
                ],
                &[],
            )
            .unwrap();

        let written = vol.write_to_disk(&q42_path).unwrap();
        assert!(written > (Q42_HEADER_SIZE + SUPERBLOCK_SIZE) as u64);

        // 1. Verify full disk round-trip & lexicon resolution
        let loaded = CompiledQ42Volume::load_from_disk(&q42_path).unwrap();
        assert_eq!(loaded.superblocks.len(), vol.superblocks.len());
        assert_eq!(loaded.bidx_ranges, vol.bidx_ranges);
        assert_eq!(
            loaded
                .lexicon
                .resolve(q_hash("https://ns.webcivics.net/agent#NaturalAgent"))
                .as_deref(),
            Some("https://ns.webcivics.net/agent#NaturalAgent")
        );

        // 2. Verify HTTP 206 byte-range read & direct SuperBlock seek read
        let (total_len, header_magic) = read_file_byte_range(&q42_path, 0, 3).unwrap();
        assert_eq!(total_len, written);
        assert_eq!(header_magic, Q42_FILE_MAGIC);

        let sb0 = read_superblock_slice_from_disk(&q42_path, 0).unwrap();
        assert_eq!(&sb0[..], &vol.superblocks[0][..]);

        // 3. Verify .q42j append-only journal replay and tamper rejection
        let q1 = NQuin::new(
            q_hash("did:qi:alice"),
            pack_predicate("https://ns.webcivics.net/deontic#obligates", OP_OBLIGATE, false),
            q_hash("https://ns.webcivics.net/hr#DutyOfCare"),
            pack_context(q_hash("https://ns.webcivics.net/graph"), SensitivityClass::Public),
            pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 42),
        );
        append_quin_to_journal(&journal_path, &q1).unwrap();
        let replayed = replay_quin_journal(&journal_path).unwrap();
        assert_eq!(replayed, vec![q1]);

        // Tamper with a byte in the journal and verify fail-closed InvalidData
        let mut raw_j = std::fs::read(&journal_path).unwrap();
        raw_j[10] ^= 0xFF;
        std::fs::write(&journal_path, &raw_j).unwrap();
        assert_eq!(
            replay_quin_journal(&journal_path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
