use super::*;
use webizen_host_core::DEFEATER_BIT;

#[test]
fn wp01_streaming_compiler_uplifts_non_thing_and_packs_superblocks_and_hmc() {
    let compiler = StreamingOntologyCompiler::default();
    let envelope = SourceEnvelope {
        repo_url: "https://github.com/WebCivics/ns".to_string(),
        commit_hash: "a1b2c3d4e5f6".to_string(),
        spdx_license: "SocialPermissiveCommons".to_string(),
        production_cost_cents: 100_000,
        roi_cap_percent: 200,
    };

    let chunk_1 = r#"
        <https://ns.webcivics.net/agent#NaturalAgent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> .
        <https://ns.webcivics.net/care#InfantDependent> <http://www.w3.org/2000/01/rdf-schema#subClassOf> <http://www.w3.org/2002/07/owl#Thing> .
        <https://ns.webcivics.net/hr#UDHR_Article1> <https://ns.webcivics.net/deontic#protects> <https://ns.webcivics.net/agent#NaturalAgent> .
        { <https://ns.webcivics.net/guardianship#EmergencyStop> } ^> { <https://ns.webcivics.net/deontic#DefaultRule> } .
    "#;

    let prose_bytes = b"All human beings are born free and equal in dignity and rights.";
    let vol = compiler
        .compile_chunks(
            &envelope,
            &[chunk_1],
            &[(
                "udhr/article-1.txt",
                "text/plain",
                Some("en"),
                "human_rights_instrument",
                prose_bytes,
            )],
        )
        .expect("compilation succeeds within 256 MiB cold budget");

    assert_ne!(vol.flags & FLAG_PAYLOAD_CATALOGUE, 0);
    assert_eq!(vol.payload_catalogue.len(), 1);
    assert_eq!(vol.uplifted_shacl_shapes.len(), 2);
    assert!(vol.uplifted_shacl_shapes[0].contains("NaturalAgentShape"));
    assert!(vol.uplifted_shacl_shapes[1].contains("InfantDependentShape"));

    let sb = vol.get_superblock_slice(0).unwrap();
    let mut decoded = [NQuin::default(); 16];
    let count = CompiledQ42Volume::decode_superblock_into(sb, &mut decoded);
    assert_eq!(count, 4);
    assert!(decoded[..count].iter().all(|q| q.verify_parity()));
    assert!(decoded[..count]
        .iter()
        .any(|q| (q.predicate & DEFEATER_BIT) != 0 && q.opcode() == OP_FORBID));

    let hmc = QbdlHmcBundle::build(&[
        ("volumes/webcivics_ns.q42", "q42_superblock", sb),
        ("prose/udhr_article1.txt", "normative_prose", prose_bytes),
    ]);
    let extracted = hmc.extract_verified_slice("prose/udhr_article1.txt").unwrap();
    assert_eq!(extracted, prose_bytes);
}

#[test]
fn wp01_compiler_fails_closed_on_budget_exhaustion() {
    let compiler = StreamingOntologyCompiler {
        mode: IngestMode::Complete,
        cold_budget_bytes: 32,
    };
    let envelope = SourceEnvelope {
        repo_url: "https://github.com/WebCivics/ns".to_string(),
        commit_hash: "deadbeef".to_string(),
        spdx_license: "SocialPermissiveCommons".to_string(),
        production_cost_cents: 0,
        roi_cap_percent: 0,
    };
    let res = compiler.compile_chunks(
        &envelope,
        &["<https://ns.webcivics.net/a> <https://ns.webcivics.net/b> <https://ns.webcivics.net/c> ."],
        &[],
    );
    assert!(matches!(res, Err(IngestError::BudgetExhausted { .. })));
}

#[test]
fn wp01_network_verify_before_rebuild_and_incremental_over_time_job() {
    let compiler = StreamingOntologyCompiler::default();
    let envelope = SourceEnvelope {
        repo_url: "https://github.com/WebCivics/ns".to_string(),
        commit_hash: "20261026abcdef".to_string(),
        spdx_license: "SocialPermissiveCommons".to_string(),
        production_cost_cents: 50_000,
        roi_cap_percent: 100,
    };

    let mut job = IncrementalCompilationJob::new(
        envelope.clone(),
        vec![
            "<https://ns.webcivics.net/hr#UDHR> <https://ns.webcivics.net/hr#affirm> <https://ns.webcivics.net/hr#HumanDignity> .".to_string(),
            "<https://ns.webcivics.net/agent#NaturalAgent> <https://ns.webcivics.net/hr#hasCapacity> <https://ns.webcivics.net/hr#LegalCapacity> .".to_string(),
        ],
        1,
    );
    assert_eq!(job.progress(), (0, 2));
    assert!(!job.step_next_batch(&compiler).unwrap());
    assert_eq!(job.progress(), (1, 2));
    assert!(job.step_next_batch(&compiler).unwrap());
    assert!(job.is_complete());

    let valid_vol = job.completed_volume.unwrap();
    let sb_crcs: Vec<u32> = valid_vol
        .superblocks
        .iter()
        .map(|sb| crc32c_bytes(sb))
        .collect();

    let good_candidate = NetworkOntologyCandidate {
        peer_id_or_gateway: "https://peer1.civics.au:4242".to_string(),
        repo_url: envelope.repo_url.clone(),
        commit_hash: envelope.commit_hash.clone(),
        ipfs_cid: "bafkreiwebcivicsns2026".to_string(),
        webtorrent_info_hash: "0123456789abcdef0123456789abcdef01234567".to_string(),
        advertised_superblock_crcs: sb_crcs,
        has_complete_q42lex_v4: true,
        volume: valid_vol.clone(),
    };
    let decision =
        evaluate_network_candidates_before_rebuild(&envelope, &[good_candidate.clone()]);
    assert_eq!(
        decision,
        VerifyBeforeRebuildDecision::AdoptExistingNetworkArtifact {
            adopted_from_peer: "https://peer1.civics.au:4242".to_string(),
            ipfs_cid: "bafkreiwebcivicsns2026".to_string(),
            webtorrent_info_hash: "0123456789abcdef0123456789abcdef01234567".to_string(),
        }
    );

    let mut bad_candidate = good_candidate;
    bad_candidate.advertised_superblock_crcs[0] ^= 0xDEAD_BEEF;
    let rebuild_decision =
        evaluate_network_candidates_before_rebuild(&envelope, &[bad_candidate]);
    assert!(matches!(
        rebuild_decision,
        VerifyBeforeRebuildDecision::RebuildRequired { .. }
    ));
}
