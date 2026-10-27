//! Range-Backed SPARQL 1.1 / SPARQL-Star Multi-BGP Join, `FILTER`, `LIMIT` & `OFFSET` Engine
//! over `.q42` v4 Volumes (`Q42RangeVolume` + `sparql_library`).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use webizen_host_core::{
    encode_quins_graph_cbor_ld, generate_60bit_token, q_hash, write_cbor_major_len, write_cbor_text,
    NQuin, CBOR_LD_MEDIA_TYPE, QUIN_SIZE, SUPERBLOCK_SIZE,
};
use webizen_host_ingest::{read_q42_index_and_lexicon_from_disk, read_superblock_slice_from_disk, CompiledQ42Volume, Q42LexV4};

const PRED_HASH55_MASK: u64 = 0x007F_FFFF_FFFF_FFFF;
const OBJ_TOKEN60_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const RDF_TYPE_URI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// Supported SPARQL query forms (`sparql_library/sparql_endpoint.rs` parity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparqlQueryForm { Select, Ask, Construct, Describe }

/// Physical triple pattern extracted by the single-pattern SPARQL planner (`Q42RangeQueryPattern`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparqlRangePattern { pub subject_iri: Option<String>, pub predicate_iri: Option<String>, pub object_iri: Option<String> }

/// Term pattern in a SPARQL 1.1 Basic Graph Pattern (`Variable` or pre-hashed `UriHash`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SparqlTermPattern {
    Variable(String),
    UriHash { uri: String, hash64: u64, hash55: u64, token60: u64 },
}

impl SparqlTermPattern {
    pub fn from_uri(uri: impl Into<String>) -> Self {
        let uri = uri.into();
        let (hash64, token60) = (q_hash(&uri), generate_60bit_token(&uri));
        let hash55 = hash64 & PRED_HASH55_MASK;
        register_known_uri_hashes(hash64, hash55, token60, &uri);
        Self::UriHash { uri, hash64, hash55, token60 }
    }
}

/// Single triple pattern inside a multi-pattern SPARQL 1.1 `WHERE { ... }` Basic Graph Pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparqlTriplePattern { pub subject: SparqlTermPattern, pub predicate: SparqlTermPattern, pub object: SparqlTermPattern }

/// Parsed SPARQL 1.1 query with expanded prefixes, multi-triple BGPs, `FILTER`, `LIMIT`, and `OFFSET`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSparqlQuery {
    pub select_vars: Vec<String>, pub patterns: Vec<SparqlTriplePattern>,
    pub filter_contains: Option<String>, pub limit: Option<usize>, pub offset: usize,
}

/// Telemetry receipt proving that the SPARQL query fetched only candidate 40 KiB SuperBlock ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeSparqlExecutionReceipt {
    pub query_form: SparqlQueryForm, pub content_type: &'static str,
    pub total_superblocks_in_volume: usize, pub superblocks_fetched_via_range: usize,
    pub bytes_transferred_via_range: usize, pub full_volume_bytes_avoided: usize,
    pub matching_quins: Vec<NQuin>, pub cbor_ld_payload: Vec<u8>, pub cbor_ld_diagnostic: String,
}

fn known_uri_registry() -> &'static Mutex<BTreeMap<u64, String>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<u64, String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn register_known_uri_hashes(hash64: u64, hash55: u64, token60: u64, uri: &str) {
    if let Ok(mut guard) = known_uri_registry().lock() {
        for h in [hash64, hash55, token60] { guard.entry(h).or_insert_with(|| uri.to_string()); }
    }
}
fn register_lexicon_entries(lexicon: &Q42LexV4) {
    for &token in lexicon.entries.keys() {
        if let Some(uri) = lexicon.resolve(token) {
            let h64 = q_hash(&uri);
            register_known_uri_hashes(h64, h64 & PRED_HASH55_MASK, token & OBJ_TOKEN60_MASK, &uri);
        }
    }
}

/// Parse a SPARQL 1.1 query string into `ParsedSparqlQuery` (expanding `PREFIX`, multi-triple BGPs,
/// `;` predicate-object lists, `a` -> `rdf:type`, `FILTER`, `LIMIT`, and `OFFSET`).
pub fn parse_sparql_query(sparql: &str) -> Result<ParsedSparqlQuery, &'static str> {
    let _form = detect_query_form(sparql)?;
    let trimmed = sparql.trim();
    let (prologue_and_head, raw_body, trailer) = if let (Some(first_l), Some(r)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if first_l >= r { return Err("Malformed WHERE { ... } block in SPARQL query"); }
        let where_l = trimmed[..r].rfind('{').unwrap_or(first_l);
        (&trimmed[..first_l], &trimmed[where_l + 1..r], &trimmed[r + 1..])
    } else if let Some(d_pos) = trimmed.to_ascii_uppercase().find("DESCRIBE") {
        (&trimmed[..d_pos], trimmed[d_pos + 8..].trim(), "")
    } else { (trimmed, trimmed, "") };

    let (mut prefixes, mut select_vars) = (default_prefixes(), Vec::new());
    let head_tokens: Vec<&str> = prologue_and_head.split_whitespace().collect();
    let (mut i, mut in_select) = (0usize, false);
    while i < head_tokens.len() {
        let upper = head_tokens[i].to_ascii_uppercase();
        if upper == "PREFIX" || upper == "@PREFIX" {
            if i + 2 >= head_tokens.len() { return Err("Incomplete PREFIX declaration in SPARQL query"); }
            prefixes.insert(head_tokens[i + 1].trim_end_matches(':').to_string(), head_tokens[i + 2].trim_end_matches('.').trim_matches(['<', '>']).to_string());
            i += 3; continue;
        }
        if upper == "SELECT" { in_select = true; }
        else if upper == "WHERE" || upper == "FROM" { in_select = false; }
        else if in_select && (head_tokens[i].starts_with('?') || head_tokens[i].starts_with('$')) {
            select_vars.push(format!("?{}", head_tokens[i].trim_start_matches(['?', '$'])));
        }
        i += 1;
    }

    let (body_without_filter, filter_contains) = extract_filter_clause(raw_body);
    let bgp_tokens = tokenize_bgp_body(&body_without_filter);
    let mut patterns = Vec::new();
    if bgp_tokens.len() == 1 {
        let single = parse_sparql_term(&bgp_tokens[0], &prefixes);
        patterns.push(SparqlTriplePattern { subject: single.clone(), predicate: single.clone(), object: single });
    } else {
        let mut idx = 0usize;
        while idx < bgp_tokens.len() {
            if matches!(bgp_tokens[idx].as_str(), "." | ";" | ",") { idx += 1; continue; }
            if idx + 2 >= bgp_tokens.len() { break; }
            let subj = parse_sparql_term(&bgp_tokens[idx], &prefixes);
            idx += 1;
            while idx < bgp_tokens.len() {
                if bgp_tokens[idx] == "." { idx += 1; break; }
                if idx + 1 >= bgp_tokens.len() { break; }
                let pred = parse_sparql_term(&bgp_tokens[idx], &prefixes);
                idx += 1;
                while idx < bgp_tokens.len() {
                    let obj = parse_sparql_term(&bgp_tokens[idx], &prefixes);
                    idx += 1;
                    patterns.push(SparqlTriplePattern { subject: subj.clone(), predicate: pred.clone(), object: obj });
                    if idx < bgp_tokens.len() && bgp_tokens[idx] == "," { idx += 1; } else { break; }
                }
                if idx < bgp_tokens.len() && bgp_tokens[idx] == ";" {
                    idx += 1;
                    if idx < bgp_tokens.len() && bgp_tokens[idx] == "." { idx += 1; break; }
                } else {
                    if idx < bgp_tokens.len() && bgp_tokens[idx] == "." { idx += 1; }
                    break;
                }
            }
        }
    }

    let (mut limit, mut offset, mut m) = (None, 0usize, 0usize);
    let mod_tokens: Vec<&str> = trailer.split_whitespace().collect();
    while m < mod_tokens.len() {
        match mod_tokens[m].to_ascii_uppercase().as_str() {
            "LIMIT" => { limit = Some(mod_tokens.get(m + 1).ok_or("Missing value after LIMIT")?.parse::<usize>().map_err(|_| "Invalid LIMIT integer")?); m += 2; }
            "OFFSET" => { offset = mod_tokens.get(m + 1).ok_or("Missing value after OFFSET")?.parse::<usize>().map_err(|_| "Invalid OFFSET integer")?; m += 2; }
            _ => m += 1,
        }
    }
    Ok(ParsedSparqlQuery { select_vars, patterns, filter_contains, limit, offset })
}

/// Evaluate a multi-triple SPARQL 1.1 BGP join, `FILTER`, `OFFSET`, and `LIMIT` against a slice of `NQuin`s.
pub fn evaluate_bgp_join_on_quins(quins: &[NQuin], query: &ParsedSparqlQuery) -> (Vec<NQuin>, Vec<BTreeMap<String, u64>>) {
    if query.patterns.is_empty() { return (Vec::new(), Vec::new()); }
    let mut solutions: Vec<(NQuin, BTreeMap<String, u64>)> = Vec::new();
    for &q in quins {
        let mut map = BTreeMap::new();
        if match_pattern_against_quin(&query.patterns[0], &q, &mut map) { solutions.push((q, map)); }
    }
    for pat in &query.patterns[1..] {
        let mut joined = Vec::new();
        for (anchor_quin, existing_map) in &solutions {
            for &q in quins {
                let mut next_map = existing_map.clone();
                if match_pattern_against_quin(pat, &q, &mut next_map) { joined.push((*anchor_quin, next_map)); }
            }
        }
        solutions = joined;
        if solutions.is_empty() { break; }
    }
    if let Some(ref needle) = query.filter_contains { solutions.retain(|(q, map)| solution_matches_filter(q, map, needle)); }
    let iter = solutions.into_iter().skip(query.offset);
    let bounded: Vec<(NQuin, BTreeMap<String, u64>)> = match query.limit { Some(lim) => iter.take(lim).collect(), None => iter.collect() };
    let (mut out_quins, mut out_bindings) = (Vec::with_capacity(bounded.len()), Vec::with_capacity(bounded.len()));
    for (q, mut map) in bounded {
        let bare: Vec<(String, u64)> = map.iter().filter_map(|(k, &v)| k.strip_prefix('?').map(|b| (b.to_string(), v))).collect();
        for (b, v) in bare { map.entry(b).or_insert(v); }
        out_quins.push(q); out_bindings.push(map);
    }
    (out_quins, out_bindings)
}

/// Range-Backed SPARQL Query Engine operating over HTTP Range / IPFS / WebTorrent `.q42` slices.
pub struct RangeSparqlEngine;

impl RangeSparqlEngine {
    pub fn parse_sparql_query(sparql: &str) -> Result<ParsedSparqlQuery, &'static str> { parse_sparql_query(sparql) }
    pub fn evaluate_bgp_join_on_quins(quins: &[NQuin], query: &ParsedSparqlQuery) -> (Vec<NQuin>, Vec<BTreeMap<String, u64>>) { evaluate_bgp_join_on_quins(quins, query) }

    pub fn execute_range_sparql(vol: &CompiledQ42Volume, sparql_query: &str) -> Result<RangeSparqlExecutionReceipt, &'static str> {
        let (form, parsed) = (detect_query_form(sparql_query)?, parse_sparql_query(sparql_query)?);
        register_lexicon_entries(&vol.lexicon);
        let (mut superblocks_fetched, mut candidate_quins) = (0usize, Vec::new());
        for (block_idx, &(min_obj, max_obj)) in vol.bidx_ranges.iter().enumerate() {
            if !superblock_is_bidx_candidate(min_obj, max_obj, &parsed.patterns) { continue; }
            let Some(sb) = vol.get_superblock_slice(block_idx) else { continue; };
            superblocks_fetched += 1;
            collect_matching_superblock_quins(sb, &parsed.patterns, &mut candidate_quins);
        }
        Ok(Self::build_receipt(form, &parsed, vol.superblocks.len(), vol.bidx_ranges.len(), superblocks_fetched, &candidate_quins, &vol.lexicon))
    }

    pub fn execute_range_sparql_on_disk_file(q42_path: &Path, sparql_query: &str) -> Result<RangeSparqlExecutionReceipt, &'static str> {
        let (form, parsed) = (detect_query_form(sparql_query)?, parse_sparql_query(sparql_query)?);
        let (_flags, total_blocks, bidx_ranges, lexicon) = read_q42_index_and_lexicon_from_disk(q42_path).map_err(|_| "Failed to read .q42 v4 header, BIDX index, or lexicon from disk")?;
        register_lexicon_entries(&lexicon);
        let (mut superblocks_fetched, mut candidate_quins) = (0usize, Vec::new());
        for (block_idx, &(min_obj, max_obj)) in bidx_ranges.iter().enumerate() {
            if !superblock_is_bidx_candidate(min_obj, max_obj, &parsed.patterns) { continue; }
            let sb = read_superblock_slice_from_disk(q42_path, block_idx).map_err(|_| "Failed to read candidate 40 KiB QualiaSuperBlock slice from disk")?;
            superblocks_fetched += 1;
            collect_matching_superblock_quins(&sb, &parsed.patterns, &mut candidate_quins);
        }
        Ok(Self::build_receipt(form, &parsed, total_blocks, bidx_ranges.len(), superblocks_fetched, &candidate_quins, &lexicon))
    }

    fn build_receipt(
        form: SparqlQueryForm, parsed: &ParsedSparqlQuery, total_blocks: usize, bidx_len: usize,
        superblocks_fetched: usize, candidate_quins: &[NQuin], lexicon: &Q42LexV4,
    ) -> RangeSparqlExecutionReceipt {
        let (matching_quins, _) = evaluate_bgp_join_on_quins(candidate_quins, parsed);
        let (cbor_ld_payload, cbor_ld_diagnostic) = Self::format_results_cbor_ld(form, &matching_quins, lexicon);
        let (bytes_transferred, full_volume_bytes) = (256 + (bidx_len * 16) + (superblocks_fetched * SUPERBLOCK_SIZE), 256 + (bidx_len * 16) + (total_blocks * SUPERBLOCK_SIZE));
        RangeSparqlExecutionReceipt {
            query_form: form, content_type: CBOR_LD_MEDIA_TYPE, total_superblocks_in_volume: total_blocks,
            superblocks_fetched_via_range: superblocks_fetched, bytes_transferred_via_range: bytes_transferred,
            full_volume_bytes_avoided: full_volume_bytes.saturating_sub(bytes_transferred),
            matching_quins, cbor_ld_payload, cbor_ld_diagnostic,
        }
    }

    fn format_results_cbor_ld(form: SparqlQueryForm, quins: &[NQuin], lexicon: &Q42LexV4) -> (Vec<u8>, String) {
        match form {
            SparqlQueryForm::Ask => {
                let (exists, mut cbor) = (!quins.is_empty(), Vec::with_capacity(48));
                cbor.extend_from_slice(&[0xD9, 0x05, 0x01, 0xA2, 0x01]);
                write_cbor_text(&mut cbor, "https://ns.webcivics.net/sparql");
                cbor.extend_from_slice(&[0x02, if exists { 0xF5 } else { 0xF4 }]);
                (cbor, format!("1281({{1: \"https://ns.webcivics.net/sparql\", 2: {exists}}})"))
            }
            SparqlQueryForm::Select | SparqlQueryForm::Construct | SparqlQueryForm::Describe => {
                let cbor = encode_quins_graph_cbor_ld(quins, "https://ns.webcivics.net/sparql");
                let rows: Vec<String> = quins.iter().map(|q| {
                    let s = lexicon.resolve(q.subject).unwrap_or_else(|| format!("urn:q42:{:016x}", q.subject));
                    let p = lexicon.resolve_predicate(q.predicate).unwrap_or_else(|| format!("urn:q42:pred:{:016x}", q.predicate));
                    let o = lexicon.resolve(q.object).unwrap_or_else(|| format!("urn:q42:{:016x}", q.object));
                    format!("{{2: \"{s}\", 3: \"{p}\", 4: \"{o}\"}}")
                }).collect();
                let mut _len_probe = Vec::new();
                write_cbor_major_len(&mut _len_probe, 4, rows.len() as u64);
                (cbor, format!("1281({{1: \"https://ns.webcivics.net/sparql\", 8: [{}]}})", rows.join(", ")))
            }
        }
    }

    pub fn execute_sparql_or_update_on_disk(q42_path: &Path, journal_path: &Path, sparql_or_update: &str) -> Result<RangeSparqlExecutionReceipt, &'static str> {
        let upper = sparql_or_update.to_ascii_uppercase();
        let (is_insert, is_delete) = (upper.contains("INSERT DATA"), upper.contains("DELETE DATA"));
        if !is_insert && !is_delete { return Self::execute_range_sparql_on_disk_file(q42_path, sparql_or_update); }
        let (Some(l), Some(r)) = (sparql_or_update.find('{'), sparql_or_update.rfind('}')) else { return Err("Malformed SPARQL Update: missing { ... } block"); };
        if l >= r { return Err("Malformed SPARQL Update: empty or inverted { ... } block"); }
        let body = sparql_or_update[l + 1..r].trim();
        webizen_host_core::validate_human_centric_nomenclature(body)?;
        if (body.contains("owl:Thing") || body.contains("owl#Thing")) && webizen_host_core::is_non_thing_human_or_living_class(body) {
            return Err("SHACL Non-Thing violation in SPARQL Update: human/living classes must not subclass owl:Thing");
        }
        let env = webizen_host_ingest::SourceEnvelope { repo_url: "https://github.com/WebCivics/ns".into(), commit_hash: "sparql-update".into(), spdx_license: "SocialPermissiveCommons".into(), production_cost_cents: 0, roi_cap_percent: 100 };
        let compiler = webizen_host_ingest::StreamingOntologyCompiler::default();
        let existing_nt = if q42_path.exists() {
            decode_volume_ntriples(&CompiledQ42Volume::load_from_disk(q42_path).map_err(|_| "Failed to load existing .q42 volume for SPARQL Update")?)
        } else { String::new() };
        let combined_ttl = if is_insert {
            if existing_nt.is_empty() { body.to_string() } else { format!("{existing_nt}\n{body}") }
        } else {
            let del_nt = decode_volume_ntriples(&compiler.compile_chunks(&env, &[body], &[]).map_err(|_| "Failed to parse DELETE DATA triples")?);
            let del_lines: Vec<&str> = del_nt.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
            existing_nt.lines().filter(|line| !del_lines.contains(&line.trim())).collect::<Vec<_>>().join("\n")
        };
        let new_vol = compiler.compile_chunks(&env, &[&combined_ttl], &[]).map_err(|_| "Failed to compile updated .q42 volume")?;
        new_vol.write_to_disk(q42_path).map_err(|_| "Failed to write updated .q42 volume to disk")?;
        register_lexicon_entries(&new_vol.lexicon);
        let mut mutated_quins = Vec::new();
        for sb in &new_vol.superblocks {
            let mut slot = [NQuin::default(); 850];
            let n = CompiledQ42Volume::decode_superblock_into(sb, &mut slot);
            for q in &slot[..n] {
                webizen_host_ingest::append_quin_to_journal(journal_path, q).map_err(|_| "Failed to append updated NQuin to .q42j journal")?;
                mutated_quins.push(*q);
            }
        }
        let (cbor_ld_payload, cbor_ld_diagnostic) = Self::format_results_cbor_ld(SparqlQueryForm::Construct, &mutated_quins, &new_vol.lexicon);
        Ok(RangeSparqlExecutionReceipt {
            query_form: SparqlQueryForm::Construct, content_type: CBOR_LD_MEDIA_TYPE, total_superblocks_in_volume: new_vol.superblocks.len(),
            superblocks_fetched_via_range: new_vol.superblocks.len(), bytes_transferred_via_range: new_vol.superblocks.len() * SUPERBLOCK_SIZE,
            full_volume_bytes_avoided: 0, matching_quins: mutated_quins, cbor_ld_payload, cbor_ld_diagnostic,
        })
    }
}

fn decode_volume_ntriples(vol: &CompiledQ42Volume) -> String {
    let (mut quins, mut buf) = (Vec::new(), Vec::new());
    for sb in &vol.superblocks {
        let mut slot = [NQuin::default(); 850];
        let n = CompiledQ42Volume::decode_superblock_into(sb, &mut slot);
        quins.extend_from_slice(&slot[..n]);
    }
    let _ = crate::format_quins_to_rdf(&quins, vol, crate::NegotiatedFormat::NTriples, &mut buf);
    String::from_utf8(buf).unwrap_or_default()
}
fn default_prefixes() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("rdf".into(), "http://www.w3.org/1999/02/22-rdf-syntax-ns#".into()), ("rdfs".into(), "http://www.w3.org/2000/01/rdf-schema#".into()),
        ("owl".into(), "http://www.w3.org/2002/07/owl#".into()), ("xsd".into(), "http://www.w3.org/2001/XMLSchema#".into()), ("sh".into(), "http://www.w3.org/ns/shacl#".into()),
    ])
}
fn detect_query_form(sparql: &str) -> Result<SparqlQueryForm, &'static str> {
    let tokens: Vec<&str> = sparql.split_whitespace().collect();
    let mut i = 0usize;
    while i < tokens.len() {
        let upper = tokens[i].to_ascii_uppercase();
        if upper == "PREFIX" || upper == "@PREFIX" { i += 3; continue; }
        return match upper.as_str() {
            "SELECT" => Ok(SparqlQueryForm::Select), "ASK" => Ok(SparqlQueryForm::Ask),
            "CONSTRUCT" => Ok(SparqlQueryForm::Construct), "DESCRIBE" => Ok(SparqlQueryForm::Describe),
            _ => Err("Unsupported SPARQL query form (expected SELECT, ASK, CONSTRUCT, or DESCRIBE)"),
        };
    }
    Err("Empty or incomplete SPARQL query")
}
fn extract_filter_clause(body: &str) -> (String, Option<String>) {
    let Some(f_pos) = body.to_ascii_uppercase().find("FILTER") else { return (body.to_string(), None); };
    let rest = &body[f_pos + 6..];
    let (end_offset, expr) = if let Some(open_rel) = rest.find('(') {
        let (mut depth, mut close_rel) = (0usize, rest.len());
        for (idx, ch) in rest[open_rel..].char_indices() {
            if ch == '(' { depth += 1; } else if ch == ')' {
                depth = depth.saturating_sub(1);
                if depth == 0 { close_rel = open_rel + idx + 1; break; }
            }
        }
        (f_pos + 6 + close_rel, &rest[open_rel..close_rel])
    } else { (body.len(), rest) };
    let needle = expr.split('"').nth(1).or_else(|| expr.split('\'').nth(1)).map(str::to_string);
    (format!("{} {}", &body[..f_pos], &body[end_offset..]), needle)
}
fn tokenize_bgp_body(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in body.split_whitespace() {
        let mut s = raw.trim();
        while s.starts_with(['.', ';', ',']) { out.push(s[..1].to_string()); s = s[1..].trim(); }
        let mut trailing = Vec::new();
        while s.ends_with(['.', ';', ',']) && !s.ends_with('>') {
            let last = s.len() - 1;
            trailing.push(s[last..].to_string()); s = s[..last].trim();
        }
        if !s.is_empty() { out.push(s.to_string()); }
        for t in trailing.into_iter().rev() { out.push(t); }
    }
    out
}
fn parse_sparql_term(raw: &str, prefixes: &BTreeMap<String, String>) -> SparqlTermPattern {
    let t = raw.trim();
    if t.starts_with('?') || t.starts_with('$') || t == "*" {
        SparqlTermPattern::Variable(if t == "*" { "*".to_string() } else { format!("?{}", t.trim_start_matches(['?', '$'])) })
    } else if t == "a" { SparqlTermPattern::from_uri(RDF_TYPE_URI) }
    else if t.starts_with('<') && t.ends_with('>') { SparqlTermPattern::from_uri(&t[1..t.len() - 1]) }
    else if let Some((pfx, local)) = t.split_once(':') {
        if let Some(ns) = prefixes.get(pfx) { SparqlTermPattern::from_uri(format!("{ns}{local}")) } else { SparqlTermPattern::from_uri(t.trim_matches('"')) }
    } else { SparqlTermPattern::from_uri(t.trim_matches(['<', '>', '"'])) }
}
fn match_pattern_against_quin(pat: &SparqlTriplePattern, q: &NQuin, map: &mut BTreeMap<String, u64>) -> bool {
    let (pred55, obj60) = ((q.predicate >> 8) & PRED_HASH55_MASK, q.object & OBJ_TOKEN60_MASK);
    if pat.subject == pat.predicate && pat.predicate == pat.object {
        if let SparqlTermPattern::UriHash { hash64, hash55, token60, .. } = &pat.subject { return q.subject == *hash64 || pred55 == *hash55 || obj60 == *token60; }
    }
    match &pat.subject { SparqlTermPattern::UriHash { hash64, .. } if q.subject != *hash64 => return false, SparqlTermPattern::Variable(v) if !bind_var(map, v, q.subject) => return false, _ => {} }
    match &pat.predicate { SparqlTermPattern::UriHash { hash55, hash64, .. } if pred55 != *hash55 && (q.predicate >> 8) != (*hash64 >> 8) => return false, SparqlTermPattern::Variable(v) if !bind_var(map, v, pred55) => return false, _ => {} }
    match &pat.object { SparqlTermPattern::UriHash { token60, .. } if obj60 != *token60 => return false, SparqlTermPattern::Variable(v) if !bind_var(map, v, obj60) => return false, _ => {} }
    true
}
fn bind_var(map: &mut BTreeMap<String, u64>, var: &str, val: u64) -> bool {
    if var == "*" { return true; }
    if let Some(&existing) = map.get(var) {
        if existing != val && (existing & OBJ_TOKEN60_MASK) != (val & OBJ_TOKEN60_MASK) { return false; }
        if (existing & !OBJ_TOKEN60_MASK) == 0 && (val & !OBJ_TOKEN60_MASK) != 0 { map.insert(var.to_string(), val); }
        true
    } else { map.insert(var.to_string(), val); true }
}
fn solution_matches_filter(q: &NQuin, map: &BTreeMap<String, u64>, needle: &str) -> bool {
    let Ok(guard) = known_uri_registry().lock() else { return true; };
    let mut candidates: Vec<u64> = map.values().copied().collect();
    candidates.extend([q.subject, (q.predicate >> 8) & PRED_HASH55_MASK, q.object & OBJ_TOKEN60_MASK]);
    candidates.into_iter().any(|h| guard.get(&h).or_else(|| guard.get(&(h & OBJ_TOKEN60_MASK))).map(|u| u.contains(needle)).unwrap_or(false))
}
fn superblock_is_bidx_candidate(min_obj: u64, max_obj: u64, patterns: &[SparqlTriplePattern]) -> bool {
    let all_bound = !patterns.is_empty() && patterns.iter().all(|p| !(p.subject == p.predicate && p.predicate == p.object) && matches!(p.object, SparqlTermPattern::UriHash { .. }));
    if !all_bound { return true; }
    let (lo, hi) = (min_obj & OBJ_TOKEN60_MASK, max_obj & OBJ_TOKEN60_MASK);
    patterns.iter().any(|p| match p.object { SparqlTermPattern::UriHash { token60, .. } => token60 >= lo && token60 <= hi, SparqlTermPattern::Variable(_) => true })
}
fn collect_matching_superblock_quins(sb: &[u8; SUPERBLOCK_SIZE], patterns: &[SparqlTriplePattern], out: &mut Vec<NQuin>) {
    let live = u64::from_le_bytes(sb[16..24].try_into().unwrap()) as usize;
    let mut off = 160usize;
    for _ in 0..live.min(850) {
        let bytes: &[u8; QUIN_SIZE] = sb[off..off + QUIN_SIZE].try_into().unwrap();
        let q = NQuin::from_le_bytes(bytes);
        off += QUIN_SIZE;
        if patterns.iter().any(|p| match_pattern_against_quin(p, &q, &mut BTreeMap::new())) { out.push(q); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use webizen_host_ingest::{SourceEnvelope, StreamingOntologyCompiler};

    struct ScopedTempDir { path: PathBuf }
    impl ScopedTempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(1);
            let dir = std::env::temp_dir().join(format!("qualia_webizen_range_sparql_{}_{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { path: dir }
        }
    }
    impl Drop for ScopedTempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.path); } }
    #[test]
    fn execute_range_sparql_on_disk_file_fetches_only_candidate_superblocks() {
        let (temp, env) = (ScopedTempDir::new(), SourceEnvelope { repo_url: "https://github.com/WebCivics/ns".into(), commit_hash: "deadbeef1234".into(), spdx_license: "SocialPermissiveCommons".into(), production_cost_cents: 10_000, roi_cap_percent: 100 });
        let q42_path = temp.path.join("webcivics_ns_disk.q42");
        let vol = StreamingOntologyCompiler::default().compile_chunks(&env, &["<https://ns.webcivics.net/agent#NaturalAgent> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> ."], &[]).unwrap();
        vol.write_to_disk(&q42_path).unwrap();
        let receipt = RangeSparqlEngine::execute_range_sparql_on_disk_file(&q42_path, "SELECT ?s ?p WHERE { ?s ?p <https://ns.webcivics.net/hr#Inalienable> }").unwrap();
        assert_eq!((receipt.query_form, receipt.superblocks_fetched_via_range, receipt.matching_quins.len()), (SparqlQueryForm::Select, 1, 1));
        assert_eq!(&receipt.cbor_ld_payload[0..3], &[0xD9, 0x05, 0x01]);
        assert!(receipt.cbor_ld_diagnostic.contains("https://ns.webcivics.net/agent#NaturalAgent") && receipt.cbor_ld_diagnostic.contains("https://ns.webcivics.net/hr#hasDignity"));
    }
    #[test]
    fn multi_triple_bgp_join_with_limit_offset_and_superblock_pruning() {
        let (temp, env) = (ScopedTempDir::new(), SourceEnvelope { repo_url: "https://github.com/WebCivics/ns".into(), commit_hash: "bgp20261027".into(), spdx_license: "SocialPermissiveCommons".into(), production_cost_cents: 10_000, roi_cap_percent: 100 });
        let q42_path = temp.path.join("multi_bgp_join.q42");
        let mut lines: Vec<String> = (0..855).map(|i| format!("<https://ns.webcivics.net/world#Item{i}> <https://ns.webcivics.net/world#category> <https://ns.webcivics.net/world#MineralSpecimen> .")).collect();
        lines.extend([
            "<https://ns.webcivics.net/agent#Alice> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> .".into(),
            "<https://ns.webcivics.net/agent#Alice> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://ns.webcivics.net/agent#NaturalAgent> .".into(),
            "<https://ns.webcivics.net/agent#UnjoinedBot> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> .".into(),
        ]);
        let vol = StreamingOntologyCompiler::default().compile_chunks(&env, &[&lines.join("\n")], &[]).unwrap();
        assert_eq!(vol.superblocks.len(), 2);
        vol.write_to_disk(&q42_path).unwrap();
        let query = "SELECT ?agent WHERE { ?agent <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> . ?agent <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://ns.webcivics.net/agent#NaturalAgent> } LIMIT 5 OFFSET 0";
        let receipt = RangeSparqlEngine::execute_range_sparql_on_disk_file(&q42_path, query).unwrap();
        assert_eq!((receipt.total_superblocks_in_volume, receipt.superblocks_fetched_via_range, receipt.matching_quins.len()), (2, 1, 1));
        assert!(receipt.full_volume_bytes_avoided >= SUPERBLOCK_SIZE && receipt.cbor_ld_diagnostic.contains("https://ns.webcivics.net/agent#Alice") && !receipt.cbor_ld_diagnostic.contains("UnjoinedBot"));
        let pfx_query = "PREFIX hr: <https://ns.webcivics.net/hr#> PREFIX agent: <https://ns.webcivics.net/agent#> SELECT ?agent WHERE { ?agent hr:hasDignity hr:Inalienable ; a agent:NaturalAgent . FILTER(CONTAINS(STR(?agent), \"Alice\")) } LIMIT 5 OFFSET 0";
        let pfx_receipt = RangeSparqlEngine::execute_range_sparql_on_disk_file(&q42_path, pfx_query).unwrap();
        assert_eq!((pfx_receipt.matching_quins.len(), pfx_receipt.superblocks_fetched_via_range), (1, 1));
    }
    #[test]
    fn sparql_update_insert_delete_construct_describe_and_shacl_non_thing_gate() {
        let temp = ScopedTempDir::new();
        let (q42_path, journal_path) = (temp.path.join("sparql_update.q42"), temp.path.join("sparql_update.q42j"));
        let upd = RangeSparqlEngine::execute_sparql_or_update_on_disk(&q42_path, &journal_path, "INSERT DATA { <https://ns.webcivics.net/agent#Bob> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> . }").unwrap();
        assert_eq!((upd.query_form, upd.matching_quins.len(), &upd.cbor_ld_payload[0..3]), (SparqlQueryForm::Construct, 1, &[0xD9, 0x05, 0x01][..]));
        let sel = RangeSparqlEngine::execute_sparql_or_update_on_disk(&q42_path, &journal_path, "SELECT ?s ?p WHERE { ?s ?p <https://ns.webcivics.net/hr#Inalienable> }").unwrap();
        assert!(sel.cbor_ld_diagnostic.contains("https://ns.webcivics.net/agent#Bob") && sel.cbor_ld_diagnostic.contains("https://ns.webcivics.net/hr#hasDignity"));
        let con = RangeSparqlEngine::execute_sparql_or_update_on_disk(&q42_path, &journal_path, "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p <https://ns.webcivics.net/hr#Inalienable> }").unwrap();
        assert_eq!((con.query_form, con.matching_quins.len()), (SparqlQueryForm::Construct, 1));
        let desc = RangeSparqlEngine::execute_sparql_or_update_on_disk(&q42_path, &journal_path, "DESCRIBE <https://ns.webcivics.net/agent#Bob>").unwrap();
        assert_eq!((desc.query_form, desc.matching_quins.len()), (SparqlQueryForm::Describe, 1));
        let bad = RangeSparqlEngine::execute_sparql_or_update_on_disk(&q42_path, &journal_path, "INSERT DATA { <https://ns.webcivics.net/agent#NaturalAgent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> . }");
        assert!(bad.is_err());
    }
}
