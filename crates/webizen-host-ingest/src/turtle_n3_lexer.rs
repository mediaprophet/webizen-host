//! Full W3C Turtle / TriG / N3 Streaming Lexer & Statement Expander (`WP-17` Swarm 4A).
//!
//! Expands `@prefix` and SPARQL `PREFIX` declarations, CURIEs (`foo:Bar`), the `a` (`rdf:type`)
//! keyword, `;` predicate-object list continuations, `,` object list continuations, blank nodes
//! (`_:b0` and `[ pred obj ]`), TriG named graph blocks, N3 implication rules (`=>`, `~>`, `^>`, `-o`),
//! and typed literals mapped directly to 48-byte `NQuin` inline type tags (`INLINE_TAG_*`).

use std::collections::BTreeMap;
use webizen_host_core::{
    parse_did_q42, q_hash, INLINE_TAG_BOOLEAN, INLINE_TAG_DECIMAL, INLINE_TAG_INTEGER,
    INLINE_TAG_IRI, TOKEN_60BIT_MASK,
};

pub const RDF_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const N3_IMPLIES_IRI: &str = "https://ns.webcivics.net/n3#implies";

/// Parsed and typed RDF object value mapped to authoritative 48-byte `NQuin` inline type tags.
#[derive(Clone, Debug, PartialEq)]
pub enum RdfObjectValue {
    Iri(String),
    LiteralString { value: String, language: Option<String>, datatype: Option<String> },
    Integer(i64),
    Decimal(f64),
    Boolean(bool),
}

impl RdfObjectValue {
    /// Encode this RDF object directly into the 64-bit `NQuin.object` field with its inline type tag.
    pub fn to_quin_object_u64(&self) -> u64 {
        match self {
            Self::Iri(uri) => parse_did_q42(uri).unwrap_or_else(|| INLINE_TAG_IRI | (q_hash(uri) & TOKEN_60BIT_MASK)),
            Self::LiteralString { value, .. } => INLINE_TAG_IRI | (q_hash(value) & TOKEN_60BIT_MASK),
            Self::Integer(val) => INLINE_TAG_INTEGER | ((*val as u64) & TOKEN_60BIT_MASK),
            Self::Decimal(val) => INLINE_TAG_DECIMAL | (((*val * 1_000_000.0) as i64 as u64) & TOKEN_60BIT_MASK),
            Self::Boolean(b) => INLINE_TAG_BOOLEAN | u64::from(*b),
        }
    }

    pub fn internable_term(&self) -> Option<&str> {
        match self {
            Self::Iri(uri) => Some(uri.as_str()),
            Self::LiteralString { value, .. } => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn lexical_str(&self) -> String {
        match self {
            Self::Iri(uri) => uri.clone(),
            Self::LiteralString { value, .. } => value.clone(),
            Self::Integer(v) => v.to_string(),
            Self::Decimal(v) => v.to_string(),
            Self::Boolean(b) => b.to_string(),
        }
    }
}

/// A single expanded RDF / TriG / N3 statement produced by [`TurtleN3Parser`].
#[derive(Clone, Debug, PartialEq)]
pub struct ExpandedRdfStatement {
    pub subject: String, pub predicate: String, pub object: RdfObjectValue,
    pub graph: Option<String>, pub rule_arrow: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Dot, Semicolon, Comma, LBracket, RBracket, LBrace, RBrace, Arrow(String), Term(String),
    QuotedLiteral { value: String, lang: Option<String>, datatype: Option<String> },
}

/// Stateful W3C Turtle / TriG / N3 Streaming Lexer and Statement Expander.
#[derive(Clone, Debug)]
pub struct TurtleN3Parser {
    pub prefixes: BTreeMap<String, String>, pub base_iri: Option<String>,
    pub blank_node_counter: u64, pub quarantined_statements: usize,
}

impl Default for TurtleN3Parser { fn default() -> Self { Self::new() } }

impl TurtleN3Parser {
    /// Construct a parser initialized with standard W3C namespace prefixes (`rdf`, `rdfs`, `owl`, `xsd`, `sh`).
    pub fn new() -> Self {
        let prefixes = BTreeMap::from([
            ("rdf".to_string(), "http://www.w3.org/1999/02/22-rdf-syntax-ns#".to_string()),
            ("rdfs".to_string(), "http://www.w3.org/2000/01/rdf-schema#".to_string()),
            ("owl".to_string(), "http://www.w3.org/2002/07/owl#".to_string()),
            ("xsd".to_string(), "http://www.w3.org/2001/XMLSchema#".to_string()),
            ("sh".to_string(), "http://www.w3.org/ns/shacl#".to_string()),
        ]);
        Self { prefixes, base_iri: None, blank_node_counter: 0, quarantined_statements: 0 }
    }

    pub fn expand_chunk(chunk_text: &str) -> Vec<ExpandedRdfStatement> {
        Self::new().parse_chunk(chunk_text)
    }

    pub fn parse_chunk(&mut self, chunk_text: &str) -> Vec<ExpandedRdfStatement> {
        let (tokens, mut out, mut pos) = (Self::tokenize(chunk_text), Vec::new(), 0usize);
        self.parse_block(&tokens, &mut pos, None, &mut out);
        out
    }

    pub fn expand_term(&self, raw: &str) -> String {
        if raw == "a" { return RDF_TYPE_IRI.to_string(); }
        if raw.starts_with('<') && raw.ends_with('>') && raw.len() >= 2 {
            let inner = &raw[1..raw.len() - 1];
            if !inner.contains(':') {
                if let Some(ref base) = self.base_iri { return format!("{base}{inner}"); }
            }
            return inner.to_string();
        }
        if !raw.starts_with("_:") && !raw.starts_with('?') {
            if let Some((prefix, local)) = raw.split_once(':') {
                if !local.starts_with("//") {
                    if let Some(ns) = self.prefixes.get(prefix) { return format!("{ns}{local}"); }
                }
            }
        }
        raw.to_string()
    }

    fn parse_block(&mut self, tokens: &[Token], pos: &mut usize, graph: Option<String>, out: &mut Vec<ExpandedRdfStatement>) {
        while *pos < tokens.len() {
            match &tokens[*pos] {
                Token::Dot | Token::Semicolon | Token::Comma => *pos += 1,
                Token::RBrace | Token::RBracket => break,
                Token::Term(t) if t == "@prefix" || t.eq_ignore_ascii_case("PREFIX") => {
                    let is_at = t == "@prefix";
                    *pos += 1;
                    if let (Some(Token::Term(pfx)), Some(Token::Term(iri))) = (tokens.get(*pos), tokens.get(*pos + 1)) {
                        self.prefixes.insert(pfx.trim_end_matches(':').to_string(), self.expand_term(iri));
                        *pos += 2 + usize::from(is_at && matches!(tokens.get(*pos + 2), Some(Token::Dot)));
                    } else { self.recover_to_dot(tokens, pos); }
                }
                Token::Term(t) if t == "@base" || t.eq_ignore_ascii_case("BASE") => {
                    let is_at = t == "@base";
                    *pos += 1;
                    if let Some(Token::Term(iri)) = tokens.get(*pos) {
                        self.base_iri = Some(self.expand_term(iri));
                        *pos += 1 + usize::from(is_at && matches!(tokens.get(*pos + 1), Some(Token::Dot)));
                    } else { self.recover_to_dot(tokens, pos); }
                }
                Token::Term(t) if t.eq_ignore_ascii_case("GRAPH") => {
                    *pos += 1;
                    if let (Some(Token::Term(g_raw)), Some(Token::LBrace)) = (tokens.get(*pos), tokens.get(*pos + 1)) {
                        let g_iri = self.expand_term(g_raw);
                        *pos += 2;
                        self.parse_block(tokens, pos, Some(g_iri), out);
                        if matches!(tokens.get(*pos), Some(Token::RBrace)) { *pos += 1; }
                    } else { self.recover_to_dot(tokens, pos); }
                }
                Token::LBrace => {
                    let lhs = self.consume_formula_string(tokens, pos);
                    if let Some(Token::Arrow(arrow)) = tokens.get(*pos).cloned() {
                        *pos += 1;
                        let rhs = if matches!(tokens.get(*pos), Some(Token::LBrace)) {
                            self.consume_formula_string(tokens, pos)
                        } else if let Some(Token::Term(t)) = tokens.get(*pos) {
                            *pos += 1;
                            self.expand_term(t)
                        } else { String::new() };
                        if matches!(tokens.get(*pos), Some(Token::Dot)) { *pos += 1; }
                        if !lhs.is_empty() && !rhs.is_empty() {
                            out.push(ExpandedRdfStatement {
                                subject: lhs, predicate: N3_IMPLIES_IRI.to_string(),
                                object: RdfObjectValue::Iri(rhs), graph: graph.clone(), rule_arrow: Some(arrow),
                            });
                        } else { self.quarantined_statements += 1; }
                    } else { self.quarantined_statements += 1; }
                }
                Token::LBracket => {
                    let bnode = self.parse_blank_node(tokens, pos, &graph, out);
                    if !matches!(tokens.get(*pos), Some(Token::Dot))
                        && !self.parse_predicate_object_list(&bnode, tokens, pos, &graph, out)
                    {
                        self.quarantined_statements += 1;
                    }
                    if matches!(tokens.get(*pos), Some(Token::Dot)) { *pos += 1; }
                }
                Token::Term(subj_raw) => {
                    let subj = self.expand_term(subj_raw);
                    *pos += 1;
                    if matches!(tokens.get(*pos), Some(Token::LBrace)) {
                        *pos += 1;
                        self.parse_block(tokens, pos, Some(subj), out);
                        if matches!(tokens.get(*pos), Some(Token::RBrace)) { *pos += 1; }
                    } else if !self.parse_predicate_object_list(&subj, tokens, pos, &graph, out) {
                        self.quarantined_statements += 1;
                        self.recover_to_dot(tokens, pos);
                    } else if matches!(tokens.get(*pos), Some(Token::Dot)) { *pos += 1; }
                }
                _ => { self.quarantined_statements += 1; self.recover_to_dot(tokens, pos); }
            }
        }
    }

    fn parse_predicate_object_list(&mut self, subject: &str, tokens: &[Token], pos: &mut usize, graph: &Option<String>, out: &mut Vec<ExpandedRdfStatement>) -> bool {
        let mut emitted = false;
        while *pos < tokens.len() {
            match tokens.get(*pos) {
                Some(Token::Dot | Token::RBracket | Token::RBrace) | None => break,
                Some(Token::Semicolon) => { *pos += 1; continue; }
                _ => {}
            }
            let Some(Token::Term(pred_raw)) = tokens.get(*pos) else { break };
            let predicate = self.expand_term(pred_raw);
            *pos += 1;
            loop {
                let Some(object) = self.parse_object(tokens, pos, graph, out) else { return emitted };
                out.push(ExpandedRdfStatement { subject: subject.to_string(), predicate: predicate.clone(), object, graph: graph.clone(), rule_arrow: None });
                emitted = true;
                if matches!(tokens.get(*pos), Some(Token::Comma)) { *pos += 1; } else { break; }
            }
            if matches!(tokens.get(*pos), Some(Token::Semicolon)) { *pos += 1; } else { break; }
        }
        emitted
    }

    fn parse_object(&mut self, tokens: &[Token], pos: &mut usize, graph: &Option<String>, out: &mut Vec<ExpandedRdfStatement>) -> Option<RdfObjectValue> {
        match tokens.get(*pos)?.clone() {
            Token::LBracket => Some(RdfObjectValue::Iri(self.parse_blank_node(tokens, pos, graph, out))),
            Token::QuotedLiteral { value, lang, datatype } => { *pos += 1; Some(self.classify_quoted_literal(value, lang, datatype)) }
            Token::Term(raw) => { *pos += 1; Some(self.classify_unquoted_term(&raw)) }
            _ => None,
        }
    }

    fn parse_blank_node(&mut self, tokens: &[Token], pos: &mut usize, graph: &Option<String>, out: &mut Vec<ExpandedRdfStatement>) -> String {
        let bnode = format!("_:b{}", self.blank_node_counter);
        self.blank_node_counter += 1;
        if matches!(tokens.get(*pos), Some(Token::LBracket)) { *pos += 1; }
        let _ = self.parse_predicate_object_list(&bnode, tokens, pos, graph, out);
        if matches!(tokens.get(*pos), Some(Token::RBracket)) { *pos += 1; }
        bnode
    }

    fn consume_formula_string(&self, tokens: &[Token], pos: &mut usize) -> String {
        if matches!(tokens.get(*pos), Some(Token::LBrace)) { *pos += 1; }
        let (mut depth, mut parts) = (1usize, Vec::new());
        while *pos < tokens.len() && depth > 0 {
            match &tokens[*pos] {
                Token::LBrace => { depth += 1; parts.push("{".to_string()); }
                Token::RBrace => { depth -= 1; if depth > 0 { parts.push("}".to_string()); } }
                Token::Term(t) => parts.push(self.expand_term(t)),
                Token::QuotedLiteral { value, .. } => parts.push(value.clone()),
                Token::Dot if !matches!(tokens.get(*pos + 1), Some(Token::RBrace)) => parts.push(".".to_string()),
                Token::Dot => {}
                Token::Semicolon => parts.push(";".to_string()),
                Token::Comma => parts.push(",".to_string()),
                Token::LBracket => parts.push("[".to_string()),
                Token::RBracket => parts.push("]".to_string()),
                Token::Arrow(a) => parts.push(a.clone()),
            }
            *pos += 1;
        }
        parts.join(" ")
    }

    fn classify_quoted_literal(&self, value: String, language: Option<String>, datatype: Option<String>) -> RdfObjectValue {
        if let Some(dt_raw) = datatype {
            let dt = self.expand_term(&dt_raw);
            if ["#integer", "#int", "#long", "#short", "#byte", "#nonNegativeInteger", "#positiveInteger"].iter().any(|s| dt.ends_with(s)) {
                if let Ok(v) = value.trim().parse::<i64>() { return RdfObjectValue::Integer(v); }
            } else if ["#decimal", "#double", "#float"].iter().any(|s| dt.ends_with(s)) {
                if let Ok(v) = value.trim().parse::<f64>() { return RdfObjectValue::Decimal(v); }
            } else if dt.ends_with("#boolean") {
                match value.trim() {
                    "true" | "1" => return RdfObjectValue::Boolean(true),
                    "false" | "0" => return RdfObjectValue::Boolean(false),
                    _ => {}
                }
            }
            return RdfObjectValue::LiteralString { value, language, datatype: Some(dt) };
        }
        RdfObjectValue::LiteralString { value, language, datatype: None }
    }

    fn classify_unquoted_term(&self, raw: &str) -> RdfObjectValue {
        if raw == "true" { return RdfObjectValue::Boolean(true); }
        if raw == "false" { return RdfObjectValue::Boolean(false); }
        let body = raw.strip_prefix(['+', '-']).unwrap_or(raw);
        if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(v) = raw.parse::<i64>() { return RdfObjectValue::Integer(v); }
        }
        if !body.is_empty() && body.contains('.') && body.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')) {
            if let Ok(v) = raw.parse::<f64>() { return RdfObjectValue::Decimal(v); }
        }
        RdfObjectValue::Iri(self.expand_term(raw))
    }

    fn recover_to_dot(&mut self, tokens: &[Token], pos: &mut usize) {
        while *pos < tokens.len() {
            let is_dot = matches!(tokens[*pos], Token::Dot);
            *pos += 1;
            if is_dot { break; }
        }
    }

    fn tokenize(input: &str) -> Vec<Token> {
        let (mut tokens, bytes, n, mut i) = (Vec::new(), input.as_bytes(), input.len(), 0usize);
        while i < n {
            let b = bytes[i];
            if b.is_ascii_whitespace() { i += 1; continue; }
            if b == b'#' { while i < n && bytes[i] != b'\n' { i += 1; } continue; }
            if i + 1 < n {
                let pair = &input[i..i + 2];
                if matches!(pair, "=>" | "~>" | "^>") || (pair == "-o" && (i + 2 == n || bytes[i + 2].is_ascii_whitespace() || bytes[i + 2] == b'{')) {
                    tokens.push(Token::Arrow(pair.to_string())); i += 2; continue;
                }
            }
            match b {
                b'.' => { tokens.push(Token::Dot); i += 1; }
                b';' => { tokens.push(Token::Semicolon); i += 1; }
                b',' => { tokens.push(Token::Comma); i += 1; }
                b'[' => { tokens.push(Token::LBracket); i += 1; }
                b']' => { tokens.push(Token::RBracket); i += 1; }
                b'{' => { tokens.push(Token::LBrace); i += 1; }
                b'}' => { tokens.push(Token::RBrace); i += 1; }
                b'<' => {
                    let start = i; i += 1;
                    while i < n && bytes[i] != b'>' { i += 1; }
                    if i < n { i += 1; }
                    tokens.push(Token::Term(input[start..i].to_string()));
                }
                b'"' | b'\'' => {
                    let (quote, is_triple) = (b, i + 2 < n && bytes[i + 1] == b && bytes[i + 2] == b);
                    let mut val = String::new();
                    i += if is_triple { 3 } else { 1 };
                    while i < n {
                        if is_triple && i + 2 < n && bytes[i] == quote && bytes[i + 1] == quote && bytes[i + 2] == quote { i += 3; break; }
                        if !is_triple && bytes[i] == quote { i += 1; break; }
                        if bytes[i] == b'\\' && i + 1 < n {
                            i += 1;
                            val.push(match bytes[i] { b'n' => '\n', b'r' => '\r', b't' => '\t', c => c as char });
                            i += 1;
                        } else {
                            let ch = input[i..].chars().next().unwrap();
                            val.push(ch); i += ch.len_utf8();
                        }
                    }
                    let (mut lang, mut datatype) = (None, None);
                    if i + 1 < n && bytes[i] == b'^' && bytes[i + 1] == b'^' {
                        i += 2;
                        let dt_start = i;
                        if i < n && bytes[i] == b'<' {
                            while i < n && bytes[i] != b'>' { i += 1; }
                            if i < n { i += 1; }
                        } else { while i < n && !Self::is_delim(bytes, i) { i += 1; } }
                        datatype = Some(input[dt_start..i].to_string());
                    } else if i < n && bytes[i] == b'@' {
                        i += 1;
                        let lg_start = i;
                        while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-') { i += 1; }
                        lang = Some(input[lg_start..i].to_string());
                    }
                    tokens.push(Token::QuotedLiteral { value: val, lang, datatype });
                }
                _ => {
                    let start = i;
                    while i < n && !Self::is_delim(bytes, i) { i += 1; }
                    tokens.push(Token::Term(input[start..i].to_string()));
                }
            }
        }
        tokens
    }

    fn is_delim(bytes: &[u8], idx: usize) -> bool {
        let b = bytes[idx];
        b.is_ascii_whitespace()
            || matches!(b, b';' | b',' | b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b'"' | b'\'' | b'#')
            || (b == b'.' && (idx + 1 >= bytes.len() || !bytes[idx + 1].is_ascii_alphanumeric()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceEnvelope, StreamingOntologyCompiler};
    use webizen_host_core::{NQuin, DEFEATER_BIT, OP_FORBID, OP_OBLIGATE};

    #[test]
    fn wp17_turtle_n3_lexer_expands_prefixes_lists_blank_nodes_literals_and_rules() {
        let ttl = r#"
            @prefix ag: <https://ns.webcivics.net/agent#> .
            PREFIX hr: <https://ns.webcivics.net/hr#>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            ag:Alice a ag:NaturalAgent ;
                hr:protects ag:Child1 , ag:Child2 ;
                hr:guardianQuorum 3 ;
                hr:capacityWeight 0.85 ;
                hr:activeStewardship true ;
                hr:explicitInt "42"^^<http://www.w3.org/2001/XMLSchema#integer> ;
                hr:explicitDec "3.14"^^xsd:decimal ;
                hr:explicitBool "false"^^xsd:boolean ;
                hr:namedBlank _:b99 ;
                hr:scope [ a hr:GuardianshipScope ; hr:level 2 ] .
            { ?s a ag:NaturalAgent } => { ?s hr:hasDignity true } .
            { <https://ns.webcivics.net/guardianship#Stop> } ^> { <https://ns.webcivics.net/deontic#Default> } .
        "#;

        let stmts = TurtleN3Parser::expand_chunk(ttl);
        assert_eq!(stmts.len(), 15);
        assert_eq!(stmts[0].subject, "https://ns.webcivics.net/agent#Alice");
        assert_eq!(stmts[0].predicate, RDF_TYPE_IRI);
        assert_eq!(stmts[0].object, RdfObjectValue::Iri("https://ns.webcivics.net/agent#NaturalAgent".to_string()));
        assert_eq!(stmts[3].object.to_quin_object_u64(), INLINE_TAG_INTEGER | (3 & TOKEN_60BIT_MASK));
        assert_eq!(stmts[4].object.to_quin_object_u64(), INLINE_TAG_DECIMAL | (((0.85 * 1_000_000.0) as u64) & TOKEN_60BIT_MASK));
        assert_eq!(stmts[5].object.to_quin_object_u64(), INLINE_TAG_BOOLEAN | 1);
        assert_eq!(stmts[6].object.to_quin_object_u64(), INLINE_TAG_INTEGER | (42 & TOKEN_60BIT_MASK));
        assert_eq!(stmts[7].object.to_quin_object_u64(), INLINE_TAG_DECIMAL | (((3.14 * 1_000_000.0) as u64) & TOKEN_60BIT_MASK));
        assert_eq!(stmts[8].object.to_quin_object_u64(), INLINE_TAG_BOOLEAN);
        assert_eq!(stmts[9].object, RdfObjectValue::Iri("_:b99".to_string()));
        assert_eq!(stmts[13].rule_arrow.as_deref(), Some("=>"));
        assert_eq!(stmts[14].rule_arrow.as_deref(), Some("^>"));
    }

    #[test]
    fn wp17_end_to_end_multi_prefix_turtle_compilation_into_q42_volume() {
        let compiler = StreamingOntologyCompiler::default();
        let envelope = SourceEnvelope {
            repo_url: "https://github.com/WebCivics/ns".to_string(),
            commit_hash: "wp17turtle2026".to_string(),
            spdx_license: "SocialPermissiveCommons".to_string(),
            production_cost_cents: 10_000,
            roi_cap_percent: 150,
        };
        let ttl = r#"
            @prefix ag: <https://ns.webcivics.net/agent#> .
            @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            PREFIX hr: <https://ns.webcivics.net/hr#>
            ag:NaturalAgent rdfs:subClassOf owl:Thing .
            ag:Alice a ag:NaturalAgent ;
                hr:hasRight hr:FreedomOfThought , hr:Privacy ;
                hr:quorumThreshold 2 ;
                hr:confidence 0.99 ;
                hr:active true .
            { ?a a ag:NaturalAgent } => { ?a hr:hasHumanAgency true } .
            { hr:EmergencyOverride } ^> { hr:StandardPolicy } .
        "#;

        let vol = compiler.compile_chunks(&envelope, &[ttl], &[]).unwrap();
        assert_eq!(vol.uplifted_shacl_shapes.len(), 1);
        assert!(vol.uplifted_shacl_shapes[0].contains("NaturalAgentShape"));

        let sb = vol.get_superblock_slice(0).unwrap();
        let mut decoded = [NQuin::default(); 16];
        let count = crate::CompiledQ42Volume::decode_superblock_into(sb, &mut decoded);
        assert_eq!(count, 9);
        assert!(decoded[..count].iter().all(|q| q.verify_parity()));
        assert!(decoded[..count].iter().any(|q| q.opcode() == OP_OBLIGATE));
        assert!(decoded[..count].iter().any(|q| (q.predicate & DEFEATER_BIT) != 0 && q.opcode() == OP_FORBID));
    }
}
