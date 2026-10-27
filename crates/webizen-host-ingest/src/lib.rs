//! WP-01 (P0): Streaming Large Ontology Compiler (`>100 MB` `WebCivics/ns`).
//!
//! Implements the Tier 2 `ColdBounded` (default 256 MiB budget) streaming compilation
//! pipeline that ingests RDF/Turtle/N3/OWL chunks, enforces `IngestMode::Complete`
//! with `Q42LEX v4` prefix deduplication, uplifts legacy `owl:Thing` human/living
//! subclasses into W3C SHACL shapes (`shapes/*.shacl.ttl`) and `SlgOpcode` bytecode,
//! writes `FLAG_PAYLOAD_CATALOGUE` (`0x0080`), and packages 40 KiB `QualiaSuperBlock`s
//! and 64-byte page-aligned `QBDL` `.hmc` hypermedia bundles.

use std::collections::BTreeMap;
use webizen_host_core::{
    crc32c_bytes, generate_60bit_token, is_non_thing_human_or_living_class, pack_context,
    pack_metadata, pack_predicate, parse_did_q42, q_hash, NQuin, PermissiveRoutingLane,
    SensitivityClass, DEFAULT_COLD_ARENA_BUDGET_BYTES, OP_FORBID, OP_OBLIGATE, OP_PERMIT,
    QUINS_PER_SUPERBLOCK, QUIN_SIZE, SUPERBLOCK_HEADER_BYTES, SUPERBLOCK_SIZE,
};

pub const FLAG_BLOCKS_LZ4: u16 = 0x0001;
pub const FLAG_OBJECT_SORTED: u16 = 0x0002;
pub const FLAG_PERMISSIVE_COMMONS: u16 = 0x0020;
pub const FLAG_PAYLOAD_CATALOGUE: u16 = 0x0080;
pub const QBDL_MAGIC: [u8; 4] = *b"QBDL";

/// Ingestion mode: `Complete` is mandatory for public ontology builds (`StripLiterals` is rejected).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestMode {
    Complete,
    StripLiterals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestError {
    BudgetExhausted { requested: usize, budget: usize },
    StripLiteralsForbidden,
    UnknownUpstreamLicense(String),
    CorruptPayloadCatalogue(String),
}

/// Upstream source provenance and license envelope (`q42/asset_envelope/`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEnvelope {
    pub repo_url: String,
    pub commit_hash: String,
    pub spdx_license: String,
    pub production_cost_cents: u64,
    pub roi_cap_percent: u64,
}

impl SourceEnvelope {
    /// Fail closed if the license is unknown or empty.
    pub fn validate(&self) -> Result<(), IngestError> {
        const ALLOWED: &[&str] = &[
            "SocialPermissiveCommons",
            "PermissiveCommons-1.0",
            "CC-BY-4.0",
            "CC-BY-NC-ND-4.0",
            "CC0-1.0",
            "MIT",
            "Apache-2.0",
        ];
        if ALLOWED.iter().any(|&l| l == self.spdx_license) {
            Ok(())
        } else {
            Err(IngestError::UnknownUpstreamLicense(
                self.spdx_license.clone(),
            ))
        }
    }
}

/// Namespaced Paged Lexicon (`Q42LEX v4`) deduplicating URI prefixes across large corpora.
#[derive(Clone, Debug, Default)]
pub struct Q42LexV4 {
    pub namespaces: BTreeMap<String, u16>,
    pub entries: BTreeMap<u64, (u16, String)>,
    used_bytes: usize,
}

impl Q42LexV4 {
    /// Split an IRI into `(namespace_prefix, local_name)`.
    pub fn split_namespace(term: &str) -> (&str, &str) {
        if let Some(idx) = term.rfind(['#', '/']) {
            (&term[..=idx], &term[idx + 1..])
        } else {
            ("", term)
        }
    }

    /// Intern a term into `Q42LEX v4` within the caller's cold byte budget, returning its 60-bit masked token.
    pub fn intern(&mut self, term: &str, remaining_budget: &mut usize) -> Result<u64, IngestError> {
        let token = generate_60bit_token(term);
        if self.entries.contains_key(&token) {
            return Ok(token);
        }
        let (ns, local) = Self::split_namespace(term);
        let ns_id = if let Some(&id) = self.namespaces.get(ns) {
            id
        } else {
            let cost = ns.len() + 2;
            if cost > *remaining_budget {
                return Err(IngestError::BudgetExhausted {
                    requested: cost,
                    budget: *remaining_budget,
                });
            }
            *remaining_budget -= cost;
            self.used_bytes += cost;
            let next_id = self.namespaces.len() as u16;
            self.namespaces.insert(ns.to_string(), next_id);
            next_id
        };

        let entry_cost = local.len() + 10;
        if entry_cost > *remaining_budget {
            return Err(IngestError::BudgetExhausted {
                requested: entry_cost,
                budget: *remaining_budget,
            });
        }
        *remaining_budget -= entry_cost;
        self.used_bytes += entry_cost;
        self.entries.insert(token, (ns_id, local.to_string()));
        Ok(token)
    }

    /// Resolve a 60-bit token, 55-bit shifted predicate hash, or full 64-bit `q_hash` back to its full IRI or literal string.
    pub fn resolve(&self, hash_or_token: u64) -> Option<String> {
        let masked = hash_or_token & 0x0FFF_FFFF_FFFF_FFFF;
        let (ns_id, local) = self.entries.get(&masked).or_else(|| {
            let masked55 = hash_or_token & 0x007F_FFFF_FFFF_FFFF;
            self.entries.iter().find_map(|(&tok, entry)| {
                if (tok & 0x007F_FFFF_FFFF_FFFF) == masked55 {
                    Some(entry)
                } else {
                    None
                }
            })
        })?;
        let prefix = self
            .namespaces
            .iter()
            .find_map(|(k, &v)| if v == *ns_id { Some(k.as_str()) } else { None })?;
        Some(format!("{prefix}{local}"))
    }

    /// Resolve a packed 64-bit `NQuin` predicate (`DEFEATER_BIT` + 55-bit `q_hash` << 8 + 8-bit opcode) to its full IRI.
    pub fn resolve_predicate(&self, packed_predicate: u64) -> Option<String> {
        self.resolve((packed_predicate & !webizen_host_core::DEFEATER_BIT) >> 8)
            .or_else(|| self.resolve(packed_predicate))
    }
}

/// ADR 0014 `FLAG_PAYLOAD_CATALOGUE` (`0x0080`) entry for multi-lingual prose & SHACL shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadCatalogueEntry {
    pub payload_key: String,
    pub mime_type: String,
    pub language: Option<String>,
    pub role: String,
    pub payload_bytes: Vec<u8>,
    pub crc32c: u32,
}

/// Compiled `.q42` v4 semantic volume with 40 KiB `QualiaSuperBlock`s, `BIDX` index, `Q42LEX v4`,
/// uplifted SHACL shape packs, and `FLAG_PAYLOAD_CATALOGUE` (`0x0080`).
#[derive(Clone, Debug)]
pub struct CompiledQ42Volume {
    pub flags: u16,
    pub superblocks: Vec<[u8; SUPERBLOCK_SIZE]>,
    pub bidx_ranges: Vec<(u64, u64)>,
    pub lexicon: Q42LexV4,
    pub payload_catalogue: Vec<PayloadCatalogueEntry>,
    pub uplifted_shacl_shapes: Vec<String>,
    pub quarantined_triples: usize,
    pub peak_cold_bytes_used: usize,
}

impl CompiledQ42Volume {
    /// Extract a single 40,960-byte `QualiaSuperBlock` slice in $O(1)$ (`range_volume.rs` contract).
    pub fn get_superblock_slice(&self, block_index: usize) -> Option<&[u8; SUPERBLOCK_SIZE]> {
        self.superblocks.get(block_index)
    }

    /// Decode live 48-byte `NQuin`s from a 40,960-byte `QualiaSuperBlock` into a caller-supplied slice (zero heap).
    pub fn decode_superblock_into(block: &[u8; SUPERBLOCK_SIZE], out: &mut [NQuin]) -> usize {
        let live = u64::from_le_bytes(block[16..24].try_into().unwrap()) as usize;
        let count = live.min(QUINS_PER_SUPERBLOCK).min(out.len());
        let mut off = SUPERBLOCK_HEADER_BYTES;
        for slot in out.iter_mut().take(count) {
            let bytes: &[u8; QUIN_SIZE] = block[off..off + QUIN_SIZE].try_into().unwrap();
            *slot = NQuin::from_le_bytes(bytes);
            off += QUIN_SIZE;
        }
        count
    }
}

/// 64-byte page-aligned `QBDL` `.hmc` Hypermedia Bundle (`bundle/format.rs` contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QbdlHmcEntry {
    pub key: String,
    pub kind: String,
    pub offset: u64,
    pub length: u64,
    pub crc32c: u32,
}

#[derive(Clone, Debug)]
pub struct QbdlHmcBundle {
    pub bytes: Vec<u8>,
    pub entries: Vec<QbdlHmcEntry>,
    pub whole_file_crc32c: u32,
}

impl QbdlHmcBundle {
    /// Package multiple named entries into a 64-byte page-aligned `QBDL` v1 bundle.
    pub fn build(raw_entries: &[(&str, &str, &[u8])]) -> Self {
        let mut bytes = vec![0u8; 64]; // 64-byte header
        bytes[0..4].copy_from_slice(&QBDL_MAGIC);
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes()); // v1
        bytes[6..8].copy_from_slice(&(raw_entries.len() as u16).to_le_bytes());

        let mut entries = Vec::with_capacity(raw_entries.len());
        for &(key, kind, data) in raw_entries {
            // Align to 64-byte page boundary
            let rem = bytes.len() % 64;
            if rem != 0 {
                bytes.resize(bytes.len() + (64 - rem), 0);
            }
            let offset = bytes.len() as u64;
            let length = data.len() as u64;
            let crc32c = crc32c_bytes(data);
            bytes.extend_from_slice(data);
            entries.push(QbdlHmcEntry {
                key: key.to_string(),
                kind: kind.to_string(),
                offset,
                length,
                crc32c,
            });
        }
        let whole_file_crc32c = crc32c_bytes(&bytes);
        Self {
            bytes,
            entries,
            whole_file_crc32c,
        }
    }

    /// Zero-copy range extraction (`HTTP 206` / QPR slice) with per-entry CRC-32C verification.
    pub fn extract_verified_slice(&self, key: &str) -> Result<&[u8], &'static str> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.key == key)
            .ok_or("entry not found")?;
        if entry.offset % 64 != 0 {
            return Err("entry offset not 64-byte page-aligned");
        }
        let start = entry.offset as usize;
        let end = start + entry.length as usize;
        let slice = self.bytes.get(start..end).ok_or("slice out of bounds")?;
        if crc32c_bytes(slice) != entry.crc32c {
            return Err("entry CRC-32C verification failed");
        }
        Ok(slice)
    }
}

/// Tier 2 `ColdBounded` Streaming Ontology Compiler for `>100 MB` `WebCivics/ns`.
pub struct StreamingOntologyCompiler {
    pub mode: IngestMode,
    pub cold_budget_bytes: usize,
}

impl Default for StreamingOntologyCompiler {
    fn default() -> Self {
        Self {
            mode: IngestMode::Complete,
            cold_budget_bytes: DEFAULT_COLD_ARENA_BUDGET_BYTES,
        }
    }
}

impl StreamingOntologyCompiler {
    /// Compile streaming Turtle / N-Triples / N3 chunks into a `.q42` v4 volume within `cold_budget_bytes`.
    pub fn compile_chunks(
        &self,
        envelope: &SourceEnvelope,
        chunks: &[&str],
        catalogue_inputs: &[(&str, &str, Option<&str>, &str, &[u8])],
    ) -> Result<CompiledQ42Volume, IngestError> {
        if self.mode == IngestMode::StripLiterals {
            return Err(IngestError::StripLiteralsForbidden);
        }
        envelope.validate()?;

        let mut remaining_budget = self.cold_budget_bytes;
        let mut lexicon = Q42LexV4::default();
        let mut quins: Vec<NQuin> = Vec::new();
        let mut uplifted_shacl_shapes: Vec<String> = Vec::new();
        let mut quarantined_triples = 0usize;
        let context_hash = pack_context(q_hash(&envelope.repo_url), SensitivityClass::Public);

        let mut parser = TurtleN3Parser::new();
        for &chunk in chunks {
            let statements = if parser.prefixes.len() > 5 {
                parser.parse_chunk(chunk)
            } else {
                let expanded = TurtleN3Parser::expand_chunk(chunk);
                let _ = parser.parse_chunk(chunk);
                expanded
            };
            for stmt in statements {
                let s_raw = stmt.subject.as_str();
                let p_raw = stmt.predicate.as_str();
                let o_lexical = stmt.object.lexical_str();

                // Enforce SHACL-First Non-Thing Uplift:
                // Natural persons, kinship, dependents, and living entities must never subclass owl:Thing.
                if (p_raw.contains("subClassOf") || p_raw == "rdfs:subClassOf")
                    && (o_lexical.contains("owl#Thing") || o_lexical == "owl:Thing")
                    && is_non_thing_human_or_living_class(s_raw)
                {
                    let shape_ttl = format!(
                        "q42:{}Shape a sh:NodeShape ; sh:targetClass <{}> ; rdfs:subClassOf rdfs:Class .",
                        s_raw.rsplit(['#', '/', ':']).next().unwrap_or("Entity"),
                        s_raw
                    );
                    let cost = shape_ttl.len();
                    if cost > remaining_budget {
                        return Err(IngestError::BudgetExhausted {
                            requested: cost,
                            budget: remaining_budget,
                        });
                    }
                    remaining_budget -= cost;
                    uplifted_shacl_shapes.push(shape_ttl);
                    // Rewrite object from owl:Thing to rdfs:Class
                    let _ = lexicon.intern(s_raw, &mut remaining_budget)?;
                    let _ = lexicon.intern("http://www.w3.org/2000/01/rdf-schema#subClassOf", &mut remaining_budget)?;
                    let _ = lexicon.intern("http://www.w3.org/2000/01/rdf-schema#Class", &mut remaining_budget)?;
                    let s_hash = q_hash(s_raw);
                    let pred = pack_predicate("http://www.w3.org/2000/01/rdf-schema#subClassOf", 0x01, false);
                    let obj = generate_60bit_token("http://www.w3.org/2000/01/rdf-schema#Class");
                    Self::push_quin(&mut quins, &mut remaining_budget, NQuin::new(
                        s_hash,
                        pred,
                        obj,
                        context_hash,
                        pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 0),
                    ))?;
                    continue;
                }

                let _ = lexicon.intern(s_raw, &mut remaining_budget)?;
                let _ = lexicon.intern(p_raw, &mut remaining_budget)?;

                let (opcode, is_defeater) = match stmt.rule_arrow.as_deref() {
                    Some("^>") => (OP_FORBID, true),
                    Some("~>") => (OP_PERMIT, false),
                    Some("=>") | Some("-o") => (OP_OBLIGATE, false),
                    _ => (0x01, false),
                };

                if let Some(term) = stmt.object.internable_term() {
                    if parse_did_q42(term).is_none() {
                        let _ = lexicon.intern(term, &mut remaining_budget)?;
                    }
                }
                let obj_val = stmt.object.to_quin_object_u64();

                let quin = NQuin::new(
                    q_hash(s_raw),
                    pack_predicate(p_raw, opcode, is_defeater),
                    obj_val,
                    context_hash,
                    pack_metadata(PermissiveRoutingLane::EnforcePermissiveCommons, 1, 0),
                );
                Self::push_quin(&mut quins, &mut remaining_budget, quin)?;
            }
        }
        quarantined_triples += parser.quarantined_statements;

        // Sort by object for BIDX range indexing
        quins.sort_by_key(|q| (q.object, q.subject, q.predicate));

        // Pack into 40,960-byte QualiaSuperBlocks
        let mut superblocks = Vec::new();
        let mut bidx_ranges = Vec::new();
        for (seq_id, chunk) in quins.chunks(QUINS_PER_SUPERBLOCK).enumerate() {
            if SUPERBLOCK_SIZE > remaining_budget {
                return Err(IngestError::BudgetExhausted {
                    requested: SUPERBLOCK_SIZE,
                    budget: remaining_budget,
                });
            }
            remaining_budget -= SUPERBLOCK_SIZE;
            let min_obj = chunk.first().map(|q| q.object).unwrap_or(0);
            let max_obj = chunk.last().map(|q| q.object).unwrap_or(0);
            bidx_ranges.push((min_obj, max_obj));

            let mut block = [0u8; SUPERBLOCK_SIZE];
            block[0..8].copy_from_slice(&(seq_id as u64).to_le_bytes());
            block[16..24].copy_from_slice(&(chunk.len() as u64).to_le_bytes());
            let mut off = SUPERBLOCK_HEADER_BYTES;
            for q in chunk {
                block[off..off + QUIN_SIZE].copy_from_slice(&q.to_le_bytes());
                off += QUIN_SIZE;
            }
            superblocks.push(block);
        }

        // Build FLAG_PAYLOAD_CATALOGUE (0x0080) entries
        let mut payload_catalogue = Vec::with_capacity(catalogue_inputs.len());
        for &(key, mime, lang, role, data) in catalogue_inputs {
            if data.len() > remaining_budget {
                return Err(IngestError::BudgetExhausted {
                    requested: data.len(),
                    budget: remaining_budget,
                });
            }
            remaining_budget -= data.len();
            payload_catalogue.push(PayloadCatalogueEntry {
                payload_key: key.to_string(),
                mime_type: mime.to_string(),
                language: lang.map(|s| s.to_string()),
                role: role.to_string(),
                payload_bytes: data.to_vec(),
                crc32c: crc32c_bytes(data),
            });
        }

        let mut flags = FLAG_BLOCKS_LZ4 | FLAG_OBJECT_SORTED | FLAG_PERMISSIVE_COMMONS;
        if !payload_catalogue.is_empty() {
            flags |= FLAG_PAYLOAD_CATALOGUE;
        }

        Ok(CompiledQ42Volume {
            flags,
            superblocks,
            bidx_ranges,
            lexicon,
            payload_catalogue,
            uplifted_shacl_shapes,
            quarantined_triples,
            peak_cold_bytes_used: self.cold_budget_bytes - remaining_budget,
        })
    }

    fn push_quin(
        quins: &mut Vec<NQuin>,
        remaining_budget: &mut usize,
        quin: NQuin,
    ) -> Result<(), IngestError> {
        if QUIN_SIZE > *remaining_budget {
            return Err(IngestError::BudgetExhausted {
                requested: QUIN_SIZE,
                budget: *remaining_budget,
            });
        }
        *remaining_budget -= QUIN_SIZE;
        quins.push(quin);
        Ok(())
    }
}

pub mod disk_store;
pub use disk_store::*;
pub mod turtle_n3_lexer;
pub use turtle_n3_lexer::*;
pub mod network_dedup_and_jobs;
pub use network_dedup_and_jobs::{
    evaluate_network_candidates_before_rebuild, verify_network_candidate,
    IncrementalCompilationJob, NetworkArtifactFault, NetworkOntologyCandidate,
    VerifyBeforeRebuildDecision,
};

#[cfg(test)]
mod tests;
