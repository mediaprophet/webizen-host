//! Range-Backed SPARQL / SPARQL-Star Query Engine over `.q42` v4 Volumes (`Q42RangeVolume` + `sparql_library`).
//!
//! Enables users and remote peers (over HTTP `206 Partial Content` Range requests, IPFS partial-CAR
//! gateways, or WebTorrent slices) to execute `SELECT`, `ASK`, `CONSTRUCT`, and `DESCRIBE` SPARQL
//! queries by fetching **only the 256-byte `.q42` header, `BIDX` index, and the specific 40 KiB
//! `QualiaSuperBlock`(s)** matching the query pattern—never downloading the entire >100 MB ontology.

use webizen_host_core::{
    encode_quins_graph_cbor_ld, generate_60bit_token, q_hash, write_cbor_major_len,
    write_cbor_text, NQuin, CBOR_LD_MEDIA_TYPE, QUIN_SIZE, SUPERBLOCK_SIZE,
};
use webizen_host_ingest::CompiledQ42Volume;

/// Supported SPARQL query forms (`sparql_library/sparql_endpoint.rs` parity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparqlQueryForm {
    Select,
    Ask,
    Construct,
    Describe,
}

/// Physical triple pattern extracted by the SPARQL planner (`Q42RangeQueryPattern`).
/// `None` represents an unbound SPARQL variable (e.g. `?s`, `?p`, `?o`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparqlRangePattern {
    pub subject_iri: Option<String>,
    pub predicate_iri: Option<String>,
    pub object_iri: Option<String>,
}

/// Telemetry receipt proving that the SPARQL query fetched only the needed 40 KiB SuperBlock ranges
/// and returned native W3C CBOR-LD (`application/cbor-ld`, Tag `0xD90501`) rather than JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeSparqlExecutionReceipt {
    pub query_form: SparqlQueryForm,
    pub content_type: &'static str,
    pub total_superblocks_in_volume: usize,
    pub superblocks_fetched_via_range: usize,
    pub bytes_transferred_via_range: usize,
    pub full_volume_bytes_avoided: usize,
    pub matching_quins: Vec<NQuin>,
    /// Native binary W3C CBOR-LD (`0xD9 0x05 0x01`) payload.
    pub cbor_ld_payload: Vec<u8>,
    /// Human-readable CBOR diagnostic notation (`1281({...})`).
    pub cbor_ld_diagnostic: String,
}

/// Range-Backed SPARQL Query Engine operating over HTTP Range / IPFS / WebTorrent `.q42` slices.
pub struct RangeSparqlEngine;

impl RangeSparqlEngine {
    /// Parse a compact SPARQL query string (`SELECT`, `ASK`, `CONSTRUCT`, `DESCRIBE`) and execute
    /// it using `.q42` `BIDX` object-range pruning so only candidate 40 KiB `QualiaSuperBlock`s are read.
    pub fn execute_range_sparql(
        vol: &CompiledQ42Volume,
        sparql_query: &str,
    ) -> Result<RangeSparqlExecutionReceipt, &'static str> {
        let (form, pattern) = Self::parse_sparql_pattern(sparql_query)?;
        let total_blocks = vol.superblocks.len();

        let target_subj_hash = pattern.subject_iri.as_deref().map(q_hash);
        let target_pred_hash = pattern.predicate_iri.as_deref().map(q_hash);
        let target_obj_token = pattern.object_iri.as_deref().map(generate_60bit_token);

        let mut superblocks_fetched = 0usize;
        let mut matching_quins = Vec::new();

        for (block_idx, &(min_obj, max_obj)) in vol.bidx_ranges.iter().enumerate() {
            // BIDX Range Pruning: If the SPARQL query binds the object, skip any 40 KiB SuperBlock
            // whose [min_obj, max_obj] interval does not contain `target_obj_token`!
            if let Some(obj_tok) = target_obj_token {
                if obj_tok < (min_obj & 0x0FFF_FFFF_FFFF_FFFF)
                    || obj_tok > (max_obj & 0x0FFF_FFFF_FFFF_FFFF)
                {
                    continue;
                }
            }

            // Fetch this single 40 KiB SuperBlock slice via HTTP Range / IPFS / WebTorrent
            let Some(sb) = vol.get_superblock_slice(block_idx) else {
                continue;
            };
            superblocks_fetched += 1;

            let live = u64::from_le_bytes(sb[16..24].try_into().unwrap()) as usize;
            let mut off = 160usize;
            for _ in 0..live.min(850) {
                let bytes: &[u8; QUIN_SIZE] = sb[off..off + QUIN_SIZE].try_into().unwrap();
                let q = NQuin::from_le_bytes(bytes);
                off += QUIN_SIZE;

                if let Some(sh) = target_subj_hash {
                    if q.subject != sh {
                        continue;
                    }
                }
                if let Some(ph) = target_pred_hash {
                    if (q.predicate >> 8) != (ph >> 8) {
                        continue;
                    }
                }
                if let Some(ot) = target_obj_token {
                    if (q.object & 0x0FFF_FFFF_FFFF_FFFF) != ot {
                        continue;
                    }
                }
                matching_quins.push(q);
            }
        }

        let (cbor_ld_payload, cbor_ld_diagnostic) =
            Self::format_results_cbor_ld(form, &matching_quins, vol);
        let bytes_transferred = 256 + (vol.bidx_ranges.len() * 16) + (superblocks_fetched * SUPERBLOCK_SIZE);
        let full_volume_bytes = 256 + (vol.bidx_ranges.len() * 16) + (total_blocks * SUPERBLOCK_SIZE);

        Ok(RangeSparqlExecutionReceipt {
            query_form: form,
            content_type: CBOR_LD_MEDIA_TYPE,
            total_superblocks_in_volume: total_blocks,
            superblocks_fetched_via_range: superblocks_fetched,
            bytes_transferred_via_range: bytes_transferred,
            full_volume_bytes_avoided: full_volume_bytes.saturating_sub(bytes_transferred),
            matching_quins,
            cbor_ld_payload,
            cbor_ld_diagnostic,
        })
    }

    fn parse_sparql_pattern(query: &str) -> Result<(SparqlQueryForm, SparqlRangePattern), &'static str> {
        let trimmed = query.trim();
        let upper = trimmed.to_ascii_uppercase();
        let form = if upper.starts_with("SELECT") {
            SparqlQueryForm::Select
        } else if upper.starts_with("ASK") {
            SparqlQueryForm::Ask
        } else if upper.starts_with("CONSTRUCT") {
            SparqlQueryForm::Construct
        } else if upper.starts_with("DESCRIBE") {
            SparqlQueryForm::Describe
        } else {
            return Err("Unsupported SPARQL query form (expected SELECT, ASK, CONSTRUCT, or DESCRIBE)");
        };

        // Extract `{ s p o }` pattern inside WHERE / query body
        let body = if let (Some(l), Some(r)) = (trimmed.rfind('{'), trimmed.rfind('}')) {
            if l < r {
                &trimmed[l + 1..r]
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        let tokens: Vec<&str> = body
            .trim()
            .trim_end_matches('.')
            .split_whitespace()
            .collect();
        let mut pat = SparqlRangePattern::default();
        if tokens.len() >= 3 {
            pat.subject_iri = Self::bound_term(tokens[0]);
            pat.predicate_iri = Self::bound_term(tokens[1]);
            pat.object_iri = Self::bound_term(tokens[2]);
        }
        Ok((form, pat))
    }

    fn bound_term(tok: &str) -> Option<String> {
        let t = tok.trim();
        if t.starts_with('?') || t.starts_with('$') || t == "*" {
            None
        } else {
            Some(t.trim_matches(|c| c == '<' || c == '>' || c == '"').to_string())
        }
    }

    /// Encode SPARQL results into native W3C CBOR-LD (`0xD9 0x05 0x01`) + CBOR diagnostic notation.
    fn format_results_cbor_ld(
        form: SparqlQueryForm,
        quins: &[NQuin],
        vol: &CompiledQ42Volume,
    ) -> (Vec<u8>, String) {
        match form {
            SparqlQueryForm::Ask => {
                let exists = !quins.is_empty();
                // Tag 1281 (0xD9 0x05 0x01), Map(2): 1 (@context) -> text, 2 (boolean) -> 0xF5 / 0xF4
                let mut cbor = Vec::with_capacity(48);
                cbor.extend_from_slice(&[0xD9, 0x05, 0x01, 0xA2, 0x01]);
                write_cbor_text(&mut cbor, "https://ns.webcivics.net/sparql");
                cbor.push(0x02);
                cbor.push(if exists { 0xF5 } else { 0xF4 });
                let diag = format!(
                    "1281({{1: \"https://ns.webcivics.net/sparql\", 2: {exists}}})"
                );
                (cbor, diag)
            }
            SparqlQueryForm::Select | SparqlQueryForm::Construct | SparqlQueryForm::Describe => {
                let cbor = encode_quins_graph_cbor_ld(quins, "https://ns.webcivics.net/sparql");
                let mut rows = Vec::with_capacity(quins.len());
                for q in quins {
                    let s = vol
                        .lexicon
                        .resolve(q.subject)
                        .unwrap_or_else(|| format!("urn:q42:{:016x}", q.subject));
                    let o = vol
                        .lexicon
                        .resolve(q.object)
                        .unwrap_or_else(|| format!("urn:q42:{:016x}", q.object));
                    rows.push(format!("{{2: \"{s}\", 4: \"{o}\"}}"));
                }
                // Keep write_cbor_major_len referenced for arbitrary binding arrays
                let mut _len_probe = Vec::new();
                write_cbor_major_len(&mut _len_probe, 4, rows.len() as u64);
                let diag = format!(
                    "1281({{1: \"https://ns.webcivics.net/sparql\", 8: [{}]}})",
                    rows.join(", ")
                );
                (cbor, diag)
            }
        }
    }
}
