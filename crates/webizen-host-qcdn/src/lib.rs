//! WP-06 (P1): User-Powered Decentralized CDN (`Q-CDN` Swarm).
//!
//! Transforms every hosted domain and ontology volume into a self-capping origin backed by:
//! 1. **Compact Signed Root Index (`< 10 KiB`)**: Catalogs the CRC-32C / FNV-1a digest, byte offset,
//!    and micropayment weight of every 40 KiB `.q42` `QualiaSuperBlock` or `.hmc` / `.10d` slice.
//! 2. **Three-Tier Peer Swarm**:
//!    - **Tier A**: Cooperative VPS Mirrors (`net/peer/replication/` Merkle custody proofs)
//!    - **Tier B**: `webizen-desktop` User Seeders (`services/webtorrent_*.rs` on `:4242` + QPR)
//!    - **Tier C**: Browser Visitors (`wasm_storage.rs` OPFS cache + WebRTC DataChannels)
//! 3. **Zero-Trust Chunk Verification**: Any peer can serve cached slices; corrupted chunks are
//!    rejected before arena admission.

use webizen_host_core::{crc32c_bytes, q_hash, q_hash_bytes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QcdnSwarmTier {
    TierACooperativeVpsMirror,
    TierBDesktopUserSeederPort4242,
    TierCBrowserOpfsWebRtc,
}

/// Chunk descriptor inside the `< 10 KiB` Signed Root Index (`cbor_ld_manifest.rs` / `BIDX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedChunkIndexEntry {
    pub chunk_seq: u32,
    pub byte_offset: u64,
    pub byte_length: u32,
    pub expected_crc32c: u32,
    pub expected_content_hash: u64,
    pub micropayment_weight_micro_cents: u64,
}

/// Lightweight Signed Root Index (`< 10 KiB`) served directly by the origin VPS.
#[derive(Clone, Debug)]
pub struct SignedRootIndex {
    pub asset_uri: String,
    pub publisher_did_hash: u64,
    pub chunks: Vec<SignedChunkIndexEntry>,
    pub signature_tag: u64,
}

impl SignedRootIndex {
    pub fn build(
        asset_uri: &str,
        publisher_did: &str,
        raw_chunks: &[&[u8]],
        weight_per_chunk_micro_cents: u64,
    ) -> Self {
        let publisher_did_hash = q_hash(publisher_did);
        let mut offset = 0u64;
        let mut chunks = Vec::with_capacity(raw_chunks.len());
        let mut sig_acc = publisher_did_hash ^ q_hash(asset_uri);

        for (seq, slice) in raw_chunks.iter().enumerate() {
            let crc = crc32c_bytes(slice);
            let chash = q_hash_bytes(slice);
            sig_acc = sig_acc.rotate_left(13) ^ chash ^ (crc as u64);
            chunks.push(SignedChunkIndexEntry {
                chunk_seq: seq as u32,
                byte_offset: offset,
                byte_length: slice.len() as u32,
                expected_crc32c: crc,
                expected_content_hash: chash,
                micropayment_weight_micro_cents: weight_per_chunk_micro_cents,
            });
            offset += slice.len() as u64;
        }

        Self {
            asset_uri: asset_uri.to_string(),
            publisher_did_hash,
            chunks,
            signature_tag: sig_acc,
        }
    }

    /// Verify a peer-supplied chunk against the Signed Root Index before admitting it into the arena or OPFS cache.
    pub fn verify_peer_chunk(&self, chunk_seq: u32, peer_bytes: &[u8]) -> Result<u64, &'static str> {
        let entry = self
            .chunks
            .iter()
            .find(|c| c.chunk_seq == chunk_seq)
            .ok_or("chunk sequence not in Signed Root Index")?;
        if peer_bytes.len() != entry.byte_length as usize {
            return Err("peer chunk byte length mismatch");
        }
        if crc32c_bytes(peer_bytes) != entry.expected_crc32c {
            return Err("peer chunk CRC-32C verification failed (tampered bytes rejected)");
        }
        if q_hash_bytes(peer_bytes) != entry.expected_content_hash {
            return Err("peer chunk content hash mismatch");
        }
        Ok(entry.micropayment_weight_micro_cents)
    }
}

/// Active peer seeder entry in the `Q-CDN` Swarm Router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QcdnPeerSeeder {
    pub seeder_did: String,
    pub tier: QcdnSwarmTier,
    pub endpoint_url: String, // e.g., "qpr://node1.civics.au:4242" or "wss://peer.webizen.au:4242"
    pub verified_chunks_served: u64,
    pub banned_for_corruption: bool,
}

pub struct QcdnSwarmCoordinator {
    pub seeders: Vec<QcdnPeerSeeder>,
}

impl Default for QcdnSwarmCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl QcdnSwarmCoordinator {
    pub const fn new() -> Self {
        Self {
            seeders: Vec::new(),
        }
    }

    pub fn register_seeder(&mut self, seeder_did: &str, tier: QcdnSwarmTier, endpoint_url: &str) {
        self.seeders.push(QcdnPeerSeeder {
            seeder_did: seeder_did.to_string(),
            tier,
            endpoint_url: endpoint_url.to_string(),
            verified_chunks_served: 0,
            banned_for_corruption: false,
        });
    }

    /// Record a chunk delivery from `seeder_did`, verifying it against `root_index`.
    /// If tampered, immediately bans the peer and rejects admission.
    pub fn admit_chunk_from_seeder(
        &mut self,
        seeder_did: &str,
        root_index: &SignedRootIndex,
        chunk_seq: u32,
        peer_bytes: &[u8],
    ) -> Result<u64, &'static str> {
        let seeder = self
            .seeders
            .iter_mut()
            .find(|s| s.seeder_did == seeder_did)
            .ok_or("seeder not registered")?;
        if seeder.banned_for_corruption {
            return Err("seeder is banned for prior chunk corruption");
        }
        match root_index.verify_peer_chunk(chunk_seq, peer_bytes) {
            Ok(weight) => {
                seeder.verified_chunks_served += 1;
                Ok(weight)
            }
            Err(e) => {
                seeder.banned_for_corruption = true;
                Err(e)
            }
        }
    }
}

pub mod multi_protocol_share;
pub use multi_protocol_share::{
    MultiProtocolShareDescriptor, PublicationDenyReason, FLAG_PERMISSIVE_COMMONS, FLAG_SANCTUARY,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp06_qcdn_three_tier_swarm_verifies_chunks_and_bans_tampered_peers() {
        let chunk_0 = b"40KiB SuperBlock #0: Human Rights Instruments NQuin payload";
        let chunk_1 = b"40KiB SuperBlock #1: SHACL Guardianship & Capacity shapes";
        let root_index = SignedRootIndex::build(
            "https://ns.webcivics.net/volumes/core.q42",
            "did:qi:webcivics_origin",
            &[chunk_0, chunk_1],
            250, // 250 micro-cents per verified chunk
        );

        let mut swarm = QcdnSwarmCoordinator::new();
        swarm.register_seeder(
            "did:qi:coop_vps_mirror_1",
            QcdnSwarmTier::TierACooperativeVpsMirror,
            "https://mirror1.civics.au:4242",
        );
        swarm.register_seeder(
            "did:qi:desktop_user_alice",
            QcdnSwarmTier::TierBDesktopUserSeederPort4242,
            "qpr://alice.desktop:4242",
        );
        swarm.register_seeder(
            "did:qi:malicious_peer",
            QcdnSwarmTier::TierCBrowserOpfsWebRtc,
            "webrtc://malicious",
        );

        // Honest Tier-B desktop user seeder serves valid chunk_0 -> verified & credited!
        let weight = swarm
            .admit_chunk_from_seeder("did:qi:desktop_user_alice", &root_index, 0, chunk_0)
            .unwrap();
        assert_eq!(weight, 250);
        assert_eq!(swarm.seeders[1].verified_chunks_served, 1);

        // Malicious peer flips 1 byte in chunk_1 -> rejected by CRC-32C before arena admission and peer banned!
        let mut tampered = chunk_1.to_vec();
        tampered[0] ^= 0xFF;
        assert!(swarm
            .admit_chunk_from_seeder("did:qi:malicious_peer", &root_index, 1, &tampered)
            .is_err());
        assert!(swarm.seeders[2].banned_for_corruption);

        // Test Multi-Protocol Sharing (IPFS CID, IPNS, WebTorrent magnet with HTTP Range WebSeed, & HTTP 206 range slice)
        let share = MultiProtocolShareDescriptor::publish_permissive_commons(
            "webcivics_ns.q42",
            FLAG_PERMISSIVE_COMMONS,
            webizen_host_core::SensitivityClass::Public,
            chunk_0,
            "https://ns.webcivics.net",
            "https://ipfs.webcivics.net",
            Some("ns.webcivics.net"),
        )
        .unwrap();
        assert!(share.ipfs_cid.starts_with("bafkrei"));
        assert!(share.magnet_uri.contains("xt=urn:btih:"));
        assert!(share.magnet_uri.contains("&ws=https://ns.webcivics.net/torrent/webseed/"));
        assert!(share.magnet_uri.contains("&xs=urn:cid:bafkrei"));

        let (status, content_range, slice) =
            share.serve_exact_byte_range(chunk_0, 0, 16).unwrap();
        assert_eq!(status, 206);
        assert_eq!(
            content_range,
            format!("bytes 0-15/{}", chunk_0.len())
        );
        assert_eq!(slice, &chunk_0[0..16]);

        // Sanctuary volumes must fail closed and never be published to public IPFS/WebTorrent!
        assert_eq!(
            MultiProtocolShareDescriptor::publish_permissive_commons(
                "sanctuary_private.q42",
                FLAG_PERMISSIVE_COMMONS | FLAG_SANCTUARY,
                webizen_host_core::SensitivityClass::Public,
                chunk_0,
                "https://ns.webcivics.net",
                "https://ipfs.webcivics.net",
                None,
            ),
            Err(PublicationDenyReason::SanctuaryVolumePublicSharingForbidden)
        );
    }
}
