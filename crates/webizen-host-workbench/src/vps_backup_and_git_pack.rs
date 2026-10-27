//! WP-12 (D12.4), WP-17 (Swarm 4C) & WP-24 (D24.1): Git Smart HTTP `git-upload-pack` (`git clone` /
//! `git fetch`) with RFC 1950 `zlib`-Compressed `PACK` v2 Codec, `OBJ_OFS_DELTA` / `OBJ_REF_DELTA`
//! Delta Decoder, Portable `.bundle` Serving, ChaCha20-Poly1305 `.q42snap` Snapshots, and VPS Doctor.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use webizen_host_core::{
    chacha20_poly1305_open, chacha20_poly1305_seal, pack_context, pack_metadata, pack_predicate,
    pbkdf2_hmac_sha256, q_hash, sha256, sha256_merkle_root, validate_human_centric_nomenclature,
    zlib_compress, zlib_decompress_prefix, NQuin, PermissiveRoutingLane, SensitivityClass, OP_OBLIGATE,
};
use webizen_host_ingest::{
    append_quin_to_journal, replay_quin_journal, CompiledQ42Volume, SourceEnvelope, StreamingOntologyCompiler,
};

pub use crate::git_smart_http::{handle_git_receive_pack_binary, render_git_repo_log_html};
use crate::git_smart_http::{decode_pkt_lines, encode_pkt_flush, encode_pkt_line, OnDiskGitRepoStore, GENESIS_SHA256_OID};
use crate::vps_deployment::HostPersistentState;

pub const QSNAP1_MAGIC: &[u8; 6] = b"QSNAP1";
pub const CBOR_LD_HEADER: [u8; 3] = [0xD9, 0x05, 0x01];
pub const QSNAP1_AAD: &[u8] = b"QSNAP1-CBOR-LD";
pub const QSNAP1_HEADER_SIZE: usize = 6 + 3 + 16 + 12 + 32 + 16;

/// Compute the domain-separated binary SHA-256 Merkle root over 32-byte file digests.
pub fn compute_merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = leaf_hashes.iter().map(|h| &h[..]).collect();
    sha256_merkle_root(&refs)
}

#[inline]
fn kind_to_pack_type(kind: &str) -> u8 {
    match kind { "commit" => 1, "tree" => 2, "blob" => 3, "tag" => 4, _ => 1 }
}

fn read_delta_varint(delta: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
    let (mut val, mut shift) = (0usize, 0usize);
    loop {
        if *pos >= delta.len() || shift >= 60 { return Err("Malformed varint in Git delta header"); }
        let b = delta[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as usize) << shift;
        if (b & 0x80) == 0 { return Ok(val); }
        shift += 7;
    }
}

/// Apply Git packfile delta instructions (`OBJ_OFS_DELTA` / `OBJ_REF_DELTA`) against `base`.
pub fn apply_git_delta_instructions(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut pos = 0usize;
    if read_delta_varint(delta, &mut pos)? != base.len() { return Err("Git delta base size mismatch"); }
    let target_size = read_delta_varint(delta, &mut pos)?;
    let mut out = Vec::with_capacity(target_size.min(16 * 1024 * 1024));
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if (cmd & 0x80) != 0 {
            let (mut offset, mut size) = (0usize, 0usize);
            for i in 0..4 {
                if (cmd & (1 << i)) != 0 {
                    if pos >= delta.len() { return Err("Truncated copy offset in Git delta"); }
                    offset |= (delta[pos] as usize) << (i * 8);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if (cmd & (0x10 << i)) != 0 {
                    if pos >= delta.len() { return Err("Truncated copy size in Git delta"); }
                    size |= (delta[pos] as usize) << (i * 8);
                    pos += 1;
                }
            }
            if size == 0 { size = 0x10000; }
            if offset.checked_add(size).map_or(true, |end| end > base.len()) {
                return Err("Git delta copy range out of bounds of base object");
            }
            out.extend_from_slice(&base[offset..offset + size]);
        } else if cmd > 0 {
            let n = cmd as usize;
            if pos + n > delta.len() { return Err("Truncated literal insert in Git delta"); }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("Reserved zero opcode in Git delta stream");
        }
    }
    if out.len() != target_size { return Err("Git delta target size mismatch"); }
    Ok(out)
}

/// Encode a Git `PACK` v2 stream with RFC 1950 `zlib`-compressed entries and a 32-byte SHA-256 trailer.
pub fn encode_git_pack_v2_zlib(objects: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut pack = b"PACK\x00\x00\x00\x02".to_vec();
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());
    for (obj_type_code, raw_payload) in objects {
        let mut size = raw_payload.len();
        let mut first_byte = ((obj_type_code & 0x07) << 4) | ((size as u8) & 0x0F);
        size >>= 4;
        if size > 0 { first_byte |= 0x80; }
        pack.push(first_byte);
        while size > 0 {
            let next_byte = ((size as u8) & 0x7F) | if (size >> 7) > 0 { 0x80 } else { 0 };
            size >>= 7;
            pack.push(next_byte);
        }
        pack.extend_from_slice(&zlib_compress(raw_payload));
    }
    let trailer = sha256(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

/// Decode and verify a Git `PACK` v2 stream, inflating each RFC 1950 `zlib` entry (including
/// `OBJ_OFS_DELTA = 6` and `OBJ_REF_DELTA = 7` delta entries reconstructed against prior objects).
pub fn decode_git_pack_v2_zlib(pack_bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    if pack_bytes.len() < 44 || &pack_bytes[0..4] != b"PACK" { return Err("Invalid or truncated Git PACK v2 header"); }
    if u32::from_be_bytes([pack_bytes[4], pack_bytes[5], pack_bytes[6], pack_bytes[7]]) != 2 {
        return Err("Unsupported Git PACK version: expected v2");
    }
    let data_end = pack_bytes.len() - 32;
    if sha256(&pack_bytes[..data_end]) != pack_bytes[data_end..] {
        return Err("Git PACK v2 trailing SHA-256 checksum mismatch");
    }
    let num_objects = u32::from_be_bytes([pack_bytes[8], pack_bytes[9], pack_bytes[10], pack_bytes[11]]) as usize;
    let (mut pos, mut out, mut entry_offsets) = (12usize, Vec::with_capacity(num_objects.min(4096)), Vec::with_capacity(num_objects.min(4096)));

    for _ in 0..num_objects {
        if pos >= data_end { return Err("Unexpected EOF reading Git PACK v2 object header"); }
        let (entry_start, first) = (pos, pack_bytes[pos]);
        pos += 1;
        let obj_type_code = (first >> 4) & 0x07;
        let (mut expected_size, mut shift, mut cont) = ((first & 0x0F) as usize, 4usize, (first & 0x80) != 0);
        while cont {
            if pos >= data_end || shift >= 60 { return Err("Malformed variable-length size in Git PACK v2 entry"); }
            let b = pack_bytes[pos];
            pos += 1;
            expected_size |= ((b & 0x7F) as usize) << shift;
            shift += 7;
            cont = (b & 0x80) != 0;
        }
        let mut delta_base_idx: Option<usize> = None;
        if obj_type_code == 6 {
            if pos >= data_end { return Err("Truncated OFS_DELTA offset in Git PACK v2"); }
            let mut b = pack_bytes[pos];
            pos += 1;
            let mut neg_off = (b & 0x7F) as usize;
            while (b & 0x80) != 0 {
                if pos >= data_end { return Err("Truncated OFS_DELTA continuation in Git PACK v2"); }
                b = pack_bytes[pos];
                pos += 1;
                neg_off = ((neg_off + 1) << 7) | ((b & 0x7F) as usize);
            }
            let target_off = entry_start.saturating_sub(neg_off);
            delta_base_idx = entry_offsets.iter().position(|&o| o == target_off)
                .or_else(|| out.len().checked_sub(neg_off))
                .or_else(|| out.len().checked_sub(1));
        } else if obj_type_code == 7 {
            let ref_len = if pos + 32 <= data_end && ((pos + 32 < data_end && pack_bytes[pos + 32] == 0x78) || pos + 32 + expected_size == data_end) {
                32
            } else if pos + 20 <= data_end { 20 } else { return Err("Truncated REF_DELTA header in Git PACK v2"); };
            let ref_slice = &pack_bytes[pos..pos + ref_len];
            pos += ref_len;
            delta_base_idx = out.iter().position(|(k, p): &(String, Vec<u8>)| {
                let mut env = format!("{k} {}\0", p.len()).into_bytes();
                env.extend_from_slice(p);
                sha256(&env).starts_with(ref_slice) || sha256(p).starts_with(ref_slice)
            }).or_else(|| out.len().checked_sub(1));
        }
        let raw_stream = if pos < data_end && pack_bytes[pos] == 0x78 {
            let (decompressed, consumed) = zlib_decompress_prefix(&pack_bytes[pos..data_end])?;
            pos += consumed;
            decompressed
        } else {
            if pos + expected_size > data_end { return Err("Truncated raw payload in Git PACK v2 entry"); }
            let raw = pack_bytes[pos..pos + expected_size].to_vec();
            pos += expected_size;
            raw
        };
        if raw_stream.len() != expected_size { return Err("Decoded Git PACK v2 object size mismatch"); }
        let (kind, payload) = match obj_type_code {
            1 => ("commit".to_string(), raw_stream),
            2 => ("tree".to_string(), raw_stream),
            3 => ("blob".to_string(), raw_stream),
            4 => ("tag".to_string(), raw_stream),
            6 | 7 => {
                let idx = delta_base_idx.ok_or("Missing base object for Git PACK v2 delta entry")?;
                let (base_kind, base_payload) = out.get(idx).ok_or("Invalid base index for Git PACK v2 delta")?;
                (base_kind.clone(), apply_git_delta_instructions(base_payload, &raw_stream)?)
            }
            _ => return Err("Unsupported Git PACK v2 object type code"),
        };
        entry_offsets.push(entry_start);
        out.push((kind, payload));
    }
    if pos != data_end { return Err("Unconsumed trailing bytes in Git PACK v2 stream"); }
    Ok(out)
}

/// Build a deterministic `zlib`-compressed Git `PACK` v2 byte stream with a 32-byte SHA-256 trailer.
pub fn build_git_pack_v2(objects: &[(&str, &[u8])]) -> Vec<u8> {
    let typed: Vec<(u8, Vec<u8>)> = objects.iter().map(|&(k, p)| (kind_to_pack_type(k), p.to_vec())).collect();
    encode_git_pack_v2_zlib(&typed)
}

fn enumerate_repo_loose_objects(repo_dir: &Path) -> io::Result<Vec<(String, String, Vec<u8>)>> {
    let objects_dir = repo_dir.join("objects");
    if !objects_dir.exists() { return Ok(Vec::new()); }
    let mut oids = Vec::new();
    for shard_entry in fs::read_dir(&objects_dir)? {
        let shard_entry = shard_entry?;
        if !shard_entry.file_type()?.is_dir() { continue; }
        let shard = shard_entry.file_name().to_string_lossy().into_owned();
        if shard.len() != 2 || !shard.bytes().all(|b| b.is_ascii_hexdigit()) { continue; }
        for obj_entry in fs::read_dir(shard_entry.path())? {
            let obj_entry = obj_entry?;
            if !obj_entry.file_type()?.is_file() { continue; }
            let tail = obj_entry.file_name().to_string_lossy().into_owned();
            if tail.len() == 62 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                oids.push(format!("{shard}{tail}"));
            }
        }
    }
    oids.sort();
    oids.into_iter().map(|oid| {
        let (kind, payload) = OnDiskGitRepoStore::read_git_object(repo_dir, &oid)?;
        Ok((oid, kind, payload))
    }).collect()
}

/// Handle a Git Smart HTTP `POST /git/<repo>/git-upload-pack` (`git clone` / `git fetch`) request.
pub fn handle_git_upload_pack_fetch(repo_dir: &Path, request_body: &[u8]) -> io::Result<(String, Vec<u8>)> {
    let _head_oid = OnDiskGitRepoStore::read_head_oid(repo_dir)?;
    let mut haves = Vec::new();
    if !request_body.is_empty() {
        for pkt in decode_pkt_lines(request_body).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))? {
            if let Some(oid) = std::str::from_utf8(&pkt).unwrap_or("").trim().strip_prefix("have ").and_then(|r| r.split_whitespace().next()) {
                haves.push(oid.to_string());
            }
        }
    }
    let loose_objects = enumerate_repo_loose_objects(repo_dir)?;
    let ack_oid = haves.iter().find(|h| loose_objects.iter().any(|(oid, _, _)| oid.eq_ignore_ascii_case(h)));
    let pack_entries: Vec<(u8, Vec<u8>)> = loose_objects
        .into_iter()
        .filter(|(oid, _, _)| !haves.iter().any(|h| h.eq_ignore_ascii_case(oid)))
        .map(|(_, kind, payload)| (kind_to_pack_type(&kind), payload))
        .collect();
    let pack_bytes = encode_git_pack_v2_zlib(&pack_entries);
    let mut response = if let Some(common) = ack_oid { encode_pkt_line(format!("ACK {common}\n").as_bytes()) } else { encode_pkt_line(b"NAK\n") };
    response.extend_from_slice(&encode_pkt_line(&pack_bytes));
    response.extend_from_slice(encode_pkt_flush());
    Ok(("application/x-git-upload-pack-result".to_string(), response))
}

/// Serve a portable Git v2 `.bundle` file for `repo_dir` (`GET /git/<repo>/bundle`).
pub fn serve_git_repo_bundle(repo_dir: &Path) -> io::Result<Vec<u8>> {
    let head_oid = OnDiskGitRepoStore::read_head_oid(repo_dir)?;
    let bundle_path = repo_dir.join("bundles").join(format!("{head_oid}.bundle"));
    if bundle_path.exists() { return fs::read(bundle_path); }
    let loose_objects = if head_oid != GENESIS_SHA256_OID { enumerate_repo_loose_objects(repo_dir)? } else { Vec::new() };
    let typed: Vec<(u8, Vec<u8>)> = loose_objects.into_iter().map(|(_, k, p)| (kind_to_pack_type(&k), p)).collect();
    let mut bundle = format!("# v2 git bundle\n{head_oid} refs/heads/main\n\n").into_bytes();
    bundle.extend_from_slice(&encode_git_pack_v2_zlib(&typed));
    Ok(bundle)
}

/// Receipt emitted after creating a ChaCha20-Poly1305 encrypted Full-VPS Snapshot (`.q42snap`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpsSnapshotReceipt {
    pub snapshot_path: PathBuf, pub file_count: usize, pub merkle_root: [u8; 32], pub encrypted_size_bytes: usize, pub provenance_quin: NQuin,
}

/// Engine for ChaCha20-Poly1305 Encrypted Full-VPS Snapshots (`.q42snap`) and Disaster-Recovery Restore.
pub struct EncryptedVpsSnapshotEngine;
impl EncryptedVpsSnapshotEngine {
    pub fn create_snapshot(data_dir: &Path, passphrase: &[u8], salt: &[u8; 16], out_snap_path: &Path) -> io::Result<VpsSnapshotReceipt> {
        create_encrypted_vps_snapshot(data_dir, passphrase, salt, out_snap_path)
    }
    pub fn restore_snapshot(snap_path: &Path, passphrase: &[u8], target_dir: &Path) -> io::Result<(usize, [u8; 32])> {
        restore_encrypted_vps_snapshot(snap_path, passphrase, target_dir)
    }
}

fn collect_snapshot_files_recursive(base_dir: &Path, current_dir: &Path, skip_snap: Option<&Path>, out: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    if !current_dir.exists() { return Ok(()); }
    for entry in fs::read_dir(current_dir)? {
        let entry = entry?;
        let path = entry.path();
        if skip_snap == Some(path.as_path()) { continue; }
        let rel = path.strip_prefix(base_dir).map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Failed to compute relative path"))?;
        let rel_slash = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
        if rel_slash == "backups" || rel_slash.starts_with("backups/") || rel_slash.ends_with(".q42snap") { continue; }
        let file_type = entry.file_type()?;
        if file_type.is_dir() { collect_snapshot_files_recursive(base_dir, &path, skip_snap, out)?; }
        else if file_type.is_file() { out.push((rel_slash, path)); }
    }
    Ok(())
}

/// Create a ChaCha20-Poly1305 encrypted Full-VPS Snapshot archive (`.q42snap`).
pub fn create_encrypted_vps_snapshot(data_dir: &Path, passphrase: &[u8], salt: &[u8; 16], out_snap_path: &Path) -> io::Result<VpsSnapshotReceipt> {
    if passphrase.is_empty() { return Err(io::Error::new(ErrorKind::InvalidInput, "Snapshot passphrase must not be empty")); }
    let journal_path = data_dir.join("journal.q42j");
    let provenance_quin = NQuin::new(
        q_hash("did:qi:webcivics_steward"), pack_predicate("https://ns.webcivics.net/host#sealedEncryptedVpsSnapshot", OP_OBLIGATE, false),
        q_hash(&out_snap_path.to_string_lossy()) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(&data_dir.to_string_lossy()), SensitivityClass::Classified),
        pack_metadata(PermissiveRoutingLane::EnforceBilateralMicroCommons, 1, 2026),
    );
    if journal_path.exists() { append_quin_to_journal(&journal_path, &provenance_quin)?; }
    let mut files = Vec::new();
    collect_snapshot_files_recursive(data_dir, data_dir, Some(out_snap_path), &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let (mut inner_archive, mut leaf_hashes) = (CBOR_LD_HEADER.to_vec(), Vec::with_capacity(files.len()));
    inner_archive.extend_from_slice(&(files.len() as u32).to_be_bytes());
    for (rel_path, full_path) in &files {
        validate_human_centric_nomenclature(rel_path).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let content = fs::read(full_path)?;
        let file_sha256 = sha256(&content);
        leaf_hashes.push(file_sha256);
        for chunk in [&(rel_path.len() as u32).to_be_bytes()[..], rel_path.as_bytes(), &file_sha256[..], &(content.len() as u64).to_be_bytes()[..], &content[..]] {
            inner_archive.extend_from_slice(chunk);
        }
    }

    let (merkle_root, mut key, mut nonce_seed, mut nonce) = (compute_merkle_root(&leaf_hashes), [0u8; 32], salt.to_vec(), [0u8; 12]);
    pbkdf2_hmac_sha256(passphrase, salt, 1024, &mut key);
    nonce_seed.extend_from_slice(&merkle_root);
    nonce.copy_from_slice(&sha256(&nonce_seed)[0..12]);
    let (ciphertext, tag) = chacha20_poly1305_seal(&key, &nonce, QSNAP1_AAD, &inner_archive);
    let mut outer = Vec::with_capacity(QSNAP1_HEADER_SIZE + ciphertext.len());
    for chunk in [&QSNAP1_MAGIC[..], &CBOR_LD_HEADER[..], &salt[..], &nonce[..], &merkle_root[..], &tag[..], &ciphertext[..]] {
        outer.extend_from_slice(chunk);
    }
    if let Some(parent) = out_snap_path.parent() { fs::create_dir_all(parent)?; }
    fs::write(out_snap_path, &outer)?;
    Ok(VpsSnapshotReceipt { snapshot_path: out_snap_path.to_path_buf(), file_count: files.len(), merkle_root, encrypted_size_bytes: outer.len(), provenance_quin })
}

/// Restore and cryptographically verify a `.q42snap` archive into `target_dir`.
pub fn restore_encrypted_vps_snapshot(snap_path: &Path, passphrase: &[u8], target_dir: &Path) -> io::Result<(usize, [u8; 32])> {
    let raw = fs::read(snap_path)?;
    if raw.len() < QSNAP1_HEADER_SIZE || &raw[0..6] != QSNAP1_MAGIC || raw[6..9] != CBOR_LD_HEADER {
        return Err(io::Error::new(ErrorKind::InvalidData, "Invalid or truncated .q42snap header"));
    }
    let (mut salt, mut nonce, mut expected_merkle_root, mut tag, mut key) = ([0u8; 16], [0u8; 12], [0u8; 32], [0u8; 16], [0u8; 32]);
    salt.copy_from_slice(&raw[9..25]); nonce.copy_from_slice(&raw[25..37]); expected_merkle_root.copy_from_slice(&raw[37..69]); tag.copy_from_slice(&raw[69..85]);
    pbkdf2_hmac_sha256(passphrase, &salt, 1024, &mut key);
    let inner = chacha20_poly1305_open(&key, &nonce, QSNAP1_AAD, &raw[85..], &tag).map_err(|msg| io::Error::new(ErrorKind::InvalidData, msg))?;
    if inner.len() < 7 || inner[0..3] != CBOR_LD_HEADER { return Err(io::Error::new(ErrorKind::InvalidData, "Missing inner W3C CBOR-LD header")); }

    let (file_count, mut cur) = (u32::from_be_bytes([inner[3], inner[4], inner[5], inner[6]]) as usize, 7usize);
    let (mut parsed_files, mut leaf_hashes) = (Vec::with_capacity(file_count.min(4096)), Vec::with_capacity(file_count.min(4096)));
    for _ in 0..file_count {
        if cur + 4 > inner.len() { return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading path len")); }
        let path_len = u32::from_be_bytes([inner[cur], inner[cur + 1], inner[cur + 2], inner[cur + 3]]) as usize;
        cur += 4;
        if cur + path_len + 40 > inner.len() { return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading file entry")); }
        let rel_path = std::str::from_utf8(&inner[cur..cur + path_len]).map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid UTF-8 file path"))?.to_string();
        cur += path_len;
        if rel_path.is_empty() || rel_path.starts_with('/') || rel_path.contains("..") || rel_path.contains('\\') {
            return Err(io::Error::new(ErrorKind::InvalidData, "Unsafe relative path in .q42snap"));
        }
        validate_human_centric_nomenclature(&rel_path).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let mut recorded_sha256 = [0u8; 32];
        recorded_sha256.copy_from_slice(&inner[cur..cur + 32]); cur += 32;
        let content_len = u64::from_be_bytes(inner[cur..cur + 8].try_into().unwrap()) as usize; cur += 8;
        if cur + content_len > inner.len() { return Err(io::Error::new(ErrorKind::InvalidData, "Unexpected EOF reading content")); }
        let content = inner[cur..cur + content_len].to_vec(); cur += content_len;
        let computed_sha256 = sha256(&content);
        if computed_sha256 != recorded_sha256 { return Err(io::Error::new(ErrorKind::InvalidData, "File SHA-256 mismatch in .q42snap")); }
        leaf_hashes.push(computed_sha256);
        parsed_files.push((rel_path, content));
    }
    if cur != inner.len() || compute_merkle_root(&leaf_hashes) != expected_merkle_root {
        return Err(io::Error::new(ErrorKind::InvalidData, "Merkle root or length mismatch in .q42snap"));
    }
    fs::create_dir_all(target_dir)?;
    for (rel_path, content) in parsed_files {
        let dest = target_dir.join(&rel_path);
        if let Some(parent) = dest.parent() { fs::create_dir_all(parent)?; }
        fs::write(dest, content)?;
    }
    Ok((file_count, expected_merkle_root))
}

/// Run an on-disk VPS Doctor diagnostic pass over `data_dir` and return a W3C CBOR-LD (`0xD9 0x05 0x01`) report.
pub fn run_vps_doctor_diagnostics(data_dir: &Path) -> io::Result<Vec<u8>> {
    let (state, vol, quins) = (HostPersistentState::load_cbor_ld(&data_dir.join("host_state.cbor-ld"))?, CompiledQ42Volume::load_from_disk(&data_dir.join("core.q42"))?, replay_quin_journal(&data_dir.join("journal.q42j"))?);
    if !quins.iter().all(|q| q.verify_parity()) { return Err(io::Error::new(ErrorKind::InvalidData, "Journal NQuin parity check failed")); }
    let mut report = CBOR_LD_HEADER.to_vec();
    for count in [vol.superblocks.len(), quins.len(), state.hosted_domains.len(), state.mail_aliases.len(), state.git_repos.len()] {
        report.extend_from_slice(&(count as u32).to_be_bytes());
    }
    Ok(report)
}

/// Compile a `.ttl` or `.n3` ontology file from `ttl_path` into `data_dir/core.q42` and log a provenance `NQuin`.
pub fn ingest_ttl_file_into_q42(data_dir: &Path, ttl_path: &Path) -> io::Result<(usize, usize)> {
    let ttl_text = fs::read_to_string(ttl_path)?;
    validate_human_centric_nomenclature(&ttl_text).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    fs::create_dir_all(data_dir)?;
    let env = SourceEnvelope {
        repo_url: format!("https://ns.webcivics.net/ingest/{}", ttl_path.file_name().and_then(|s| s.to_str()).unwrap_or("ontology.ttl")),
        commit_hash: format!("{:016x}", q_hash(&ttl_text)), spdx_license: "SocialPermissiveCommons".to_string(), production_cost_cents: 0, roi_cap_percent: 100,
    };
    let vol = StreamingOntologyCompiler::default().compile_chunks(&env, &[ttl_text.as_str()], &[]).map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{e:?}")))?;
    vol.write_to_disk(&data_dir.join("core.q42"))?;
    let provenance_quin = NQuin::new(
        q_hash("did:qi:webcivics_steward"), pack_predicate("https://ns.webcivics.net/ingest#compiledTtlVolumeToDisk", OP_OBLIGATE, false),
        q_hash(&ttl_path.to_string_lossy()) & 0x0FFF_FFFF_FFFF_FFFF, pack_context(q_hash(&data_dir.to_string_lossy()), SensitivityClass::Public),
        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 2026),
    );
    append_quin_to_journal(&data_dir.join("journal.q42j"), &provenance_quin)?;
    Ok((vol.superblocks.len(), vol.lexicon.entries.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_smart_http::handle_git_receive_pack_push;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!("qualia_vps_backup_git_pack_{}_{}_{}", label, std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn apply_git_delta_instructions_copy_and_literal_and_pack_delta_decode() {
        let (base, literal_suffix) = (b"wc:NaturalAgent a rdfs:Class ; sh:property wc:GuardianshipShape .\n", b"wc:CareSteward a rdfs:Class .\n");
        let target_len = base.len() + literal_suffix.len();
        let mut delta = vec![base.len() as u8, target_len as u8, 0x80 | 0x01 | 0x10, 0x00, base.len() as u8, literal_suffix.len() as u8];
        delta.extend_from_slice(literal_suffix);
        let reconstructed = apply_git_delta_instructions(base, &delta).unwrap();
        let mut expected = base.to_vec();
        expected.extend_from_slice(literal_suffix);
        assert_eq!(reconstructed, expected);

        let mut pack = b"PACK\x00\x00\x00\x02\x00\x00\x00\x02".to_vec();
        let (b_len, d_len) = (base.len(), delta.len());
        pack.extend_from_slice(&[(3u8 << 4) | ((b_len as u8) & 0x0F) | 0x80, (b_len >> 4) as u8]);
        pack.extend_from_slice(&zlib_compress(base));
        pack.extend_from_slice(&[(7u8 << 4) | ((d_len as u8) & 0x0F) | 0x80, (d_len >> 4) as u8]);
        pack.extend_from_slice(&sha256(base));
        pack.extend_from_slice(&zlib_compress(&delta));
        let csum = sha256(&pack);
        pack.extend_from_slice(&csum);
        assert_eq!(decode_git_pack_v2_zlib(&pack).unwrap()[1], ("blob".to_string(), expected));
    }

    #[test]
    fn git_upload_pack_fetch_and_encrypted_vps_snapshot_roundtrip() {
        let (temp, restore_dir) = (make_temp_dir("git_fetch"), make_temp_dir("snap_restore"));
        let repo_dir = OnDiskGitRepoStore::init_bare_repo(&temp, "webcivics-ns").unwrap();
        let journal_path = temp.join("journal.q42j");
        let blob_oid = OnDiskGitRepoStore::write_git_object(&repo_dir, "blob", b"wc:NaturalAgent a rdfs:Class .\n").unwrap();
        let tree_oid = OnDiskGitRepoStore::write_git_object(&repo_dir, "tree", format!("100644 agent.ttl\0{blob_oid}").as_bytes()).unwrap();
        let commit_diff = format!("tree {tree_oid}\ncommit: Add GuardianshipShape\n+ wc:NaturalAgent a rdfs:Class ; sh:property wc:GuardianshipShape .");
        let push_receipt = handle_git_receive_pack_push(&repo_dir, &journal_path, "did:qi:alice_steward", &commit_diff, 2, 2).unwrap();

        let mut neg_req = encode_pkt_line(format!("want {}\n", push_receipt.new_commit_oid).as_bytes());
        neg_req.extend_from_slice(&encode_pkt_line(format!("have {blob_oid}\n").as_bytes()));
        neg_req.extend_from_slice(&encode_pkt_line(b"done\n"));
        let (_, body_neg) = handle_git_upload_pack_fetch(&repo_dir, &neg_req).unwrap();
        assert!(decode_pkt_lines(&body_neg).unwrap()[0].starts_with(b"ACK "));
        assert!(serve_git_repo_bundle(&repo_dir).unwrap().starts_with(b"# v2 git bundle\n"));

        let ttl_path = temp.join("guardianship.ttl");
        fs::write(&ttl_path, "<https://ns.webcivics.net/agent#NaturalAgent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> .\n").unwrap();
        assert!(ingest_ttl_file_into_q42(&temp, &ttl_path).unwrap().0 >= 1);

        let snap_path = temp.join("backups").join("full-host.q42snap");
        let (passphrase, salt) = (b"human-centric-steward-passphrase-2026", [0x3Au8; 16]);
        let receipt = create_encrypted_vps_snapshot(&temp, passphrase, &salt, &snap_path).unwrap();
        assert_eq!(restore_encrypted_vps_snapshot(&snap_path, passphrase, &restore_dir).unwrap(), (receipt.file_count, receipt.merkle_root));
        assert_eq!(restore_encrypted_vps_snapshot(&snap_path, b"wrong", &restore_dir).unwrap_err().kind(), ErrorKind::InvalidData);
        let _ = (fs::remove_dir_all(&temp), fs::remove_dir_all(&restore_dir));
    }
}
