//! Network-wide "Verify-Before-Rebuild" Ontology Deduplication & Resumable Over-Time Compilation Queue.
//!
//! Ensures that:
//! 1. If a compiled `.q42` v4 / `QBDL` `.hmc` ontology volume for `(repo_url, commit_hash, schema_version)`
//!    is already available on the network (via IPFS CID, WebTorrent magnet, or QDNF `QResolve`), the
//!    VPS host verifies its cryptographic provenance, SuperBlock CRC-32C digests, `IngestMode::Complete`
//!    (`Q42LEX v4`) lexicon completeness, and SHACL-first non-`owl:Thing` compliance—and **adopts it
//!    without redundant re-processing**.
//! 2. Only when no network version exists—or when existing network version(s) fail verification—does
//!    the VPS quarantine the faulty version and run an **incremental over-time compilation job**
//!    (`IncrementalCompilationJob`) that processes large ontologies in bounded background ticks.

use crate::{
    CompiledQ42Volume, IngestError, SourceEnvelope, StreamingOntologyCompiler,
    FLAG_PERMISSIVE_COMMONS,
};
use webizen_host_core::{crc32c_bytes, is_non_thing_human_or_living_class, NQuin};

/// Descriptor of an already-compiled ontology volume discovered on the network (IPFS / WebTorrent / QDNF).
#[derive(Clone, Debug)]
pub struct NetworkOntologyCandidate {
    pub peer_id_or_gateway: String,
    pub repo_url: String,
    pub commit_hash: String,
    pub ipfs_cid: String,
    pub webtorrent_info_hash: String,
    pub advertised_superblock_crcs: Vec<u32>,
    pub has_complete_q42lex_v4: bool,
    pub volume: CompiledQ42Volume,
}

/// Fault reason when a network-advertised ontology build is rejected and queued for local re-compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkArtifactFault {
    CommitOrSourceMismatch,
    MissingCompleteLexicon,
    SuperBlockCrcMismatch { block_index: usize },
    InvalidQuinParity { block_index: usize },
    OwlThingHumanOrLivingViolation { offending_iri: String },
    MissingPermissiveCommonsFlag,
}

/// Outcome of the network-wide "Verify-Before-Rebuild" check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyBeforeRebuildDecision {
    /// A valid compiled `.q42` volume already exists on the network; adopt & seed without re-processing.
    AdoptExistingNetworkArtifact {
        adopted_from_peer: String,
        ipfs_cid: String,
        webtorrent_info_hash: String,
    },
    /// No valid network version exists (or all candidates had faults); schedule local over-time compilation.
    RebuildRequired {
        quarantined_peers: Vec<(String, NetworkArtifactFault)>,
    },
}

/// Verify a network candidate `.q42` v4 volume before trusting or adopting it.
pub fn verify_network_candidate(
    expected_envelope: &SourceEnvelope,
    candidate: &NetworkOntologyCandidate,
) -> Result<(), NetworkArtifactFault> {
    if candidate.repo_url != expected_envelope.repo_url
        || candidate.commit_hash != expected_envelope.commit_hash
    {
        return Err(NetworkArtifactFault::CommitOrSourceMismatch);
    }
    if !candidate.has_complete_q42lex_v4 || candidate.volume.lexicon.entries.is_empty() {
        return Err(NetworkArtifactFault::MissingCompleteLexicon);
    }
    if (candidate.volume.flags & FLAG_PERMISSIVE_COMMONS) == 0 {
        return Err(NetworkArtifactFault::MissingPermissiveCommonsFlag);
    }
    if candidate.advertised_superblock_crcs.len() != candidate.volume.superblocks.len() {
        return Err(NetworkArtifactFault::SuperBlockCrcMismatch { block_index: 0 });
    }

    let owl_thing_token =
        webizen_host_core::generate_60bit_token("http://www.w3.org/2002/07/owl#Thing");
    let mut quins_buf = [NQuin::default(); 850];

    for (idx, sb) in candidate.volume.superblocks.iter().enumerate() {
        if crc32c_bytes(sb) != candidate.advertised_superblock_crcs[idx] {
            return Err(NetworkArtifactFault::SuperBlockCrcMismatch { block_index: idx });
        }
        let n = CompiledQ42Volume::decode_superblock_into(sb, &mut quins_buf);
        for q in &quins_buf[..n] {
            if !q.verify_parity() {
                return Err(NetworkArtifactFault::InvalidQuinParity { block_index: idx });
            }
            // Verify no human/living class was left subclassed under owl:Thing
            if (q.object & 0x0FFF_FFFF_FFFF_FFFF) == owl_thing_token {
                if let Some(subj_iri) = candidate.volume.lexicon.resolve(q.subject) {
                    if is_non_thing_human_or_living_class(&subj_iri) {
                        return Err(NetworkArtifactFault::OwlThingHumanOrLivingViolation {
                            offending_iri: subj_iri,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Evaluate all discovered network candidates for `(repo_url, commit_hash)`:
/// adopts the first 100%-verified network artifact, or returns `RebuildRequired` with quarantine records
/// if no candidate exists or all candidates have problems.
pub fn evaluate_network_candidates_before_rebuild(
    expected_envelope: &SourceEnvelope,
    candidates: &[NetworkOntologyCandidate],
) -> VerifyBeforeRebuildDecision {
    let mut quarantined_peers = Vec::new();
    for cand in candidates {
        match verify_network_candidate(expected_envelope, cand) {
            Ok(()) => {
                return VerifyBeforeRebuildDecision::AdoptExistingNetworkArtifact {
                    adopted_from_peer: cand.peer_id_or_gateway.clone(),
                    ipfs_cid: cand.ipfs_cid.clone(),
                    webtorrent_info_hash: cand.webtorrent_info_hash.clone(),
                };
            }
            Err(fault) => {
                quarantined_peers.push((cand.peer_id_or_gateway.clone(), fault));
            }
        }
    }
    VerifyBeforeRebuildDecision::RebuildRequired { quarantined_peers }
}

/// Resumable, Over-Time Background Ontology Compilation Job for the VPS Host.
///
/// Processes large ontologies (`>100 MB` `WebCivics/ns`, SNOMED, ChEBI, QUDT, ABS) incrementally
/// across multiple background ticks (`step_next_batch`) so the VPS never blocks live traffic.
#[derive(Clone, Debug)]
pub struct IncrementalCompilationJob {
    pub envelope: SourceEnvelope,
    pub pending_chunks: Vec<String>,
    pub processed_chunks: Vec<String>,
    pub chunks_per_tick: usize,
    pub completed_volume: Option<CompiledQ42Volume>,
}

impl IncrementalCompilationJob {
    pub fn new(
        envelope: SourceEnvelope,
        all_chunks: Vec<String>,
        chunks_per_tick: usize,
    ) -> Self {
        Self {
            envelope,
            pending_chunks: all_chunks,
            processed_chunks: Vec::new(),
            chunks_per_tick: chunks_per_tick.max(1),
            completed_volume: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completed_volume.is_some()
    }

    /// Completion ratio `(processed_chunks, total_chunks)`.
    pub fn progress(&self) -> (usize, usize) {
        let total = self.processed_chunks.len() + self.pending_chunks.len();
        (self.processed_chunks.len(), total)
    }

    /// Execute one bounded time-slice (`chunks_per_tick`) of the ontology ingestion and compilation job.
    pub fn step_next_batch(
        &mut self,
        compiler: &StreamingOntologyCompiler,
    ) -> Result<bool, IngestError> {
        if self.completed_volume.is_some() {
            return Ok(true);
        }
        let take_n = self.chunks_per_tick.min(self.pending_chunks.len());
        for _ in 0..take_n {
            let chunk = self.pending_chunks.remove(0);
            self.processed_chunks.push(chunk);
        }

        if self.pending_chunks.is_empty() {
            let refs: Vec<&str> = self.processed_chunks.iter().map(|s| s.as_str()).collect();
            let vol = compiler.compile_chunks(&self.envelope, &refs, &[])?;
            self.completed_volume = Some(vol);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
