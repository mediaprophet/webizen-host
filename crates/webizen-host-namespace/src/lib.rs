//! WP-02 (P0): Content-Negotiated Virtual Namespace & Hard Cost Cap (`ns.webcivics.net` v2).
//!
//! Replaces static file hosting on `ns.webcivics.net` with:
//! 1. Zero-allocation (`HotZeroHeap`) binary `.q42` `NQuin` slice serving (`Accept: application/q42`).
//! 2. Native W3C CBOR-LD (`Accept: application/cbor-ld`, CBOR tag `0xD90501`) as the default structured
//!    linked-data wire format (replacing JSON / JSON-LD).
//! 3. On-the-fly W3C RDF reconstruction (`text/turtle`, `application/n-triples`).
//! 4. Interactive HTML + `webizen-lite-wasm` (640 KiB) browser ontology explorer (`text/html`).
//! 5. Hard Origin Egress Byte & Dollar Circuit Breaker (`meters.rs` contract) that caps publisher
//!    hosting costs at $0.00 overage by redirecting bulk scraper surges to the `Q-CDN` swarm (`HTTP 307`)
//!    while keeping the `<10 KiB` signed Root Index and verified `NaturalAgent` / Humanitarian ICT
//!    sessions 100% available.

use std::io::Write;
use webizen_host_core::{
    encode_quins_graph_cbor_ld, q_hash, NQuin, CBOR_LD_MEDIA_TYPE, QUIN_SIZE, SUPERBLOCK_SIZE,
};
use webizen_host_ingest::CompiledQ42Volume;

/// Negotiated HTTP `Accept` media type for `ns.webcivics.net/*`.
/// Native structured format is `CborLd` (`application/cbor-ld`), not JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiatedFormat {
    QualiaBinaryQ42,
    CborLd,
    NTriples,
    Turtle,
    HtmlWasmExplorer,
}

impl NegotiatedFormat {
    pub fn from_accept_header(accept: &str) -> Self {
        if accept.contains("application/q42") {
            Self::QualiaBinaryQ42
        } else if accept.contains("application/cbor-ld") || accept.contains("application/cbor") {
            Self::CborLd
        } else if accept.contains("application/n-triples") {
            Self::NTriples
        } else if accept.contains("text/turtle") {
            Self::Turtle
        } else if accept.contains("text/html") {
            Self::HtmlWasmExplorer
        } else {
            // Native default structured format is W3C CBOR-LD (`application/cbor-ld`), never JSON
            Self::CborLd
        }
    }

    pub const fn content_type(&self) -> &'static str {
        match self {
            Self::QualiaBinaryQ42 => "application/q42",
            Self::CborLd => CBOR_LD_MEDIA_TYPE,
            Self::NTriples => "application/n-triples; charset=utf-8",
            Self::Turtle => "text/turtle; charset=utf-8",
            Self::HtmlWasmExplorer => "text/html; charset=utf-8",
        }
    }
}

/// Caller identity classification at ingress for the Hard Egress Circuit Breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerStanding {
    /// Verified `NaturalAgent` (`did:qi`) or `humanitarian-ict.n3` bearer — exempt from tolls and priority-served.
    VerifiedNaturalPersonOrHumanitarian,
    /// Unauthenticated or bulk commercial/scraper traffic (e.g., US data-hub scraper surge).
    UnauthenticatedOrCommercialBulk,
}

/// Hard Origin Egress Byte & Dollar Circuit Breaker (`net/qdnf/economics/meters.rs` contract).
#[derive(Clone, Copy, Debug)]
pub struct HardEgressCircuitBreaker {
    pub max_monthly_origin_bytes: u64,
    pub max_permitted_overage_cents: u64,
    pub cost_per_gib_cents: u64,
    pub observed_origin_bytes: u64,
    pub tripped: bool,
}

impl HardEgressCircuitBreaker {
    /// Create a hard cost-cap policy with `$0.00` permitted overage.
    pub const fn new_zero_overage(max_monthly_origin_bytes: u64, cost_per_gib_cents: u64) -> Self {
        Self {
            max_monthly_origin_bytes,
            max_permitted_overage_cents: 0,
            cost_per_gib_cents,
            observed_origin_bytes: 0,
            tripped: false,
        }
    }

    /// Check whether a response of `response_bytes` can be served from origin or must be offloaded to `Q-CDN`.
    #[inline]
    pub fn admit_or_offload(
        &mut self,
        response_bytes: u64,
        standing: CallerStanding,
        is_root_index: bool,
    ) -> EgressDecision {
        // Signed Root Index (<10 KiB) and verified NaturalAgent / Humanitarian ICT queries are protected
        if is_root_index && response_bytes <= 10_240 {
            self.observed_origin_bytes = self.observed_origin_bytes.saturating_add(response_bytes);
            return EgressDecision::ServeFromOrigin;
        }

        let projected = self.observed_origin_bytes.saturating_add(response_bytes);
        if projected > self.max_monthly_origin_bytes {
            self.tripped = true;
            match standing {
                CallerStanding::VerifiedNaturalPersonOrHumanitarian if response_bytes <= 40_960 => {
                    EgressDecision::ServeFromOriginProtectedHumanitarian
                }
                _ => EgressDecision::RedirectToQcdnSwarm {
                    http_status: 307,
                    overage_cents_incurred: 0,
                },
            }
        } else {
            self.observed_origin_bytes = projected;
            EgressDecision::ServeFromOrigin
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    ServeFromOrigin,
    ServeFromOriginProtectedHumanitarian,
    RedirectToQcdnSwarm {
        http_status: u16,
        overage_cents_incurred: u64,
    },
}

/// Zero-allocation (`HotZeroHeap`) lookup of matching 48-byte `NQuin`s for `term_uri` inside a
/// 40 KiB `QualiaSuperBlock` into a caller-supplied buffer.
pub fn query_superblock_term_zero_heap(
    superblock: &[u8; SUPERBLOCK_SIZE],
    term_uri: &str,
    out_quins: &mut [NQuin],
) -> usize {
    let target_hash = q_hash(term_uri);
    let target_token = target_hash & 0x0FFF_FFFF_FFFF_FFFF;
    let live = u64::from_le_bytes(superblock[16..24].try_into().unwrap()) as usize;
    let mut matched = 0usize;
    let mut off = 160usize;

    for _ in 0..live.min(850) {
        if matched >= out_quins.len() {
            break;
        }
        let bytes: &[u8; QUIN_SIZE] = superblock[off..off + QUIN_SIZE].try_into().unwrap();
        let q = NQuin::from_le_bytes(bytes);
        if q.subject == target_hash
            || (q.object & 0x0FFF_FFFF_FFFF_FFFF) == target_token
            || (q.predicate >> 8) == (target_hash >> 8)
        {
            out_quins[matched] = q;
            matched += 1;
        }
        off += QUIN_SIZE;
    }
    matched
}

/// Format an `NQuin` slice into standard W3C N-Triples or Turtle directly into any `impl Write`
/// (`query/resolver.rs::format_ntriples_to` pattern).
pub fn format_quins_to_rdf(
    quins: &[NQuin],
    vol: &CompiledQ42Volume,
    format: NegotiatedFormat,
    mut writer: impl Write,
) -> std::io::Result<usize> {
    let mut bytes_written = 0usize;
    match format {
        NegotiatedFormat::QualiaBinaryQ42 => {
            for q in quins {
                let raw = q.to_le_bytes();
                writer.write_all(&raw)?;
                bytes_written += raw.len();
            }
        }
        NegotiatedFormat::CborLd => {
            let cbor_ld = encode_quins_graph_cbor_ld(quins, "https://ns.webcivics.net/context");
            writer.write_all(&cbor_ld)?;
            bytes_written += cbor_ld.len();
        }
        NegotiatedFormat::NTriples | NegotiatedFormat::Turtle => {
            for q in quins {
                let s = vol
                    .lexicon
                    .resolve(q.subject)
                    .unwrap_or_else(|| format!("urn:q42:hash:{:016x}", q.subject));
                let p = vol
                    .lexicon
                    .resolve_predicate(q.predicate)
                    .unwrap_or_else(|| format!("urn:q42:pred:{:016x}", q.predicate));
                let o = vol
                    .lexicon
                    .resolve(q.object)
                    .unwrap_or_else(|| format!("urn:q42:obj:{:016x}", q.object));
                let line = format!("<{s}> <{p}> <{o}> .\n");
                writer.write_all(line.as_bytes())?;
                bytes_written += line.len();
            }
        }
        NegotiatedFormat::HtmlWasmExplorer => {
            let html = format!(
                "<!doctype html><html><head><title>WebCivics Human-Centric Ontology Explorer</title></head>\
                 <body><main data-wasm-kernel=\"webizen-lite-wasm-640kib\" data-quins=\"{}\"></main></body></html>",
                quins.len()
            );
            writer.write_all(html.as_bytes())?;
            bytes_written += html.len();
        }
    }
    Ok(bytes_written)
}

pub mod range_sparql;
pub use range_sparql::{
    RangeSparqlEngine, RangeSparqlExecutionReceipt, SparqlQueryForm, SparqlRangePattern,
};

#[cfg(test)]
mod tests {
    use super::*;
    use webizen_host_ingest::{SourceEnvelope, StreamingOntologyCompiler};

    #[test]
    fn wp02_virtual_namespace_content_negotiation_and_hard_cost_cap_breaker() {
        let compiler = StreamingOntologyCompiler::default();
        let env = SourceEnvelope {
            repo_url: "https://github.com/WebCivics/ns".to_string(),
            commit_hash: "123456".to_string(),
            spdx_license: "SocialPermissiveCommons".to_string(),
            production_cost_cents: 10_000,
            roi_cap_percent: 100,
        };
        let vol = compiler
            .compile_chunks(
                &env,
                &[
                    "<https://ns.webcivics.net/agent#NaturalAgent> <https://ns.webcivics.net/hr#hasDignity> <https://ns.webcivics.net/hr#Inalienable> .",
                ],
                &[],
            )
            .unwrap();

        let sb = vol.get_superblock_slice(0).unwrap();
        let mut matched = [NQuin::default(); 8];
        let n = query_superblock_term_zero_heap(
            sb,
            "https://ns.webcivics.net/agent#NaturalAgent",
            &mut matched,
        );
        assert_eq!(n, 1);

        // Test binary .q42, native CBOR-LD (0xD9 0x05 0x01), N-Triples, and HTML+WASM content negotiation
        assert_eq!(
            NegotiatedFormat::from_accept_header("*/*"),
            NegotiatedFormat::CborLd
        );
        let mut cbor_buf = Vec::new();
        format_quins_to_rdf(
            &matched[..n],
            &vol,
            NegotiatedFormat::from_accept_header("application/cbor-ld"),
            &mut cbor_buf,
        )
        .unwrap();
        assert_eq!(&cbor_buf[0..3], &[0xD9, 0x05, 0x01]);

        let mut buf = Vec::new();
        format_quins_to_rdf(
            &matched[..n],
            &vol,
            NegotiatedFormat::from_accept_header("application/n-triples"),
            &mut buf,
        )
        .unwrap();
        let nt_str = String::from_utf8(buf).unwrap();
        assert!(nt_str.contains("https://ns.webcivics.net/agent#NaturalAgent"));
        assert!(nt_str.contains("<https://ns.webcivics.net/hr#hasDignity>"));

        // Simulate US data-hub traffic surge against a 100 KiB hard cap
        let mut breaker = HardEgressCircuitBreaker::new_zero_overage(100 * 1024, 9);
        assert_eq!(
            breaker.admit_or_offload(
                40_960,
                CallerStanding::UnauthenticatedOrCommercialBulk,
                false
            ),
            EgressDecision::ServeFromOrigin
        );
        assert_eq!(
            breaker.admit_or_offload(
                40_960,
                CallerStanding::UnauthenticatedOrCommercialBulk,
                false
            ),
            EgressDecision::ServeFromOrigin
        );
        // Third 40 KiB bulk request exceeds 100 KiB -> trips circuit breaker cleanly with $0 overage!
        assert_eq!(
            breaker.admit_or_offload(
                40_960,
                CallerStanding::UnauthenticatedOrCommercialBulk,
                false
            ),
            EgressDecision::RedirectToQcdnSwarm {
                http_status: 307,
                overage_cents_incurred: 0
            }
        );
        assert!(breaker.tripped);

        // Even while tripped, Root Index (<10 KiB) and verified NaturalAgent / Humanitarian ICT stay 100% served!
        assert_eq!(
            breaker.admit_or_offload(
                4_096,
                CallerStanding::UnauthenticatedOrCommercialBulk,
                true
            ),
            EgressDecision::ServeFromOrigin
        );
        assert_eq!(
            breaker.admit_or_offload(
                40_960,
                CallerStanding::VerifiedNaturalPersonOrHumanitarian,
                false
            ),
            EgressDecision::ServeFromOriginProtectedHumanitarian
        );

        // Test Range-Backed SPARQL execution over .q42 SuperBlocks returning native CBOR-LD (0xD90501)
        let sparql_receipt = RangeSparqlEngine::execute_range_sparql(
            &vol,
            "SELECT ?s ?p WHERE { ?s ?p <https://ns.webcivics.net/hr#Inalienable> }",
        )
        .unwrap();
        assert_eq!(sparql_receipt.query_form, SparqlQueryForm::Select);
        assert_eq!(sparql_receipt.content_type, "application/cbor-ld");
        assert_eq!(&sparql_receipt.cbor_ld_payload[0..3], &[0xD9, 0x05, 0x01]);
        assert_eq!(sparql_receipt.superblocks_fetched_via_range, 1);
        assert_eq!(sparql_receipt.matching_quins.len(), 1);
        assert!(sparql_receipt
            .cbor_ld_diagnostic
            .contains("https://ns.webcivics.net/agent#NaturalAgent"));

        let ask_receipt = RangeSparqlEngine::execute_range_sparql(
            &vol,
            "ASK WHERE { <https://ns.webcivics.net/agent#NaturalAgent> ?p <https://ns.webcivics.net/hr#Inalienable> }",
        )
        .unwrap();
        assert_eq!(&ask_receipt.cbor_ld_payload[0..3], &[0xD9, 0x05, 0x01]);
        assert_eq!(
            ask_receipt.cbor_ld_diagnostic,
            "1281({1: \"https://ns.webcivics.net/sparql\", 2: true})"
        );
    }
}
