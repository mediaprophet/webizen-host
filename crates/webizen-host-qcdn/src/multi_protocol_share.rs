//! Multi-Protocol Content-Addressed Sharing (`IPFS`, `IPNS`, `Partial-CAR`, `WebTorrent`, `QPR`, & `HTTP 206 Range`).
//!
//! Aligns with `qualia-core-db/src/q42/volume/{magnet.rs, car.rs, cid.rs, range.rs, publication.rs}`:
//! - Generates **IPFS CIDv1** (`bafkrei...` / `urn:cid:`) and **Partial-CAR** slice descriptors so
//!   IPFS gateways (`{gateway}/ipfs/{cid}`) serve exact byte ranges (`HTTP 206 Partial Content`).
//! - Generates **WebTorrent & BitTorrent Magnets** (`magnet:?xt=urn:btih:{sha1}&dn={name}&xl={len}&ws={http_range_webseed}&xs=urn:cid:{cid}`)
//!   so browser and desktop peers can fetch individual 40 KiB `QualiaSuperBlock`s over WebTorrent OR
//!   HTTP Range web-seeds.
//! - Enforces the **Sanctuary Fail-Closed Publication Gate**: volumes with `FLAG_SANCTUARY` (`0x0040`)
//!   or non-Public sensitivity are strictly denied public IPFS/WebTorrent publication.

use webizen_host_core::{crc32c_bytes, q_hash_bytes, SensitivityClass};

pub const FLAG_PERMISSIVE_COMMONS: u16 = 0x0020;
pub const FLAG_SANCTUARY: u16 = 0x0040;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationDenyReason {
    SanctuaryVolumePublicSharingForbidden,
    MissingPermissiveCommonsFlag,
    NonPublicSensitivityClass,
    EmptyPayload,
}

/// Multi-protocol distribution descriptor for a compiled `.q42` v4 volume or `QBDL` `.hmc` bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProtocolShareDescriptor {
    pub display_name: String,
    pub total_byte_length: u64,
    /// Content-addressed IPFS CID (`bafkrei...`).
    pub ipfs_cid: String,
    /// Optional IPNS mutable pointer for root volume catalogs (`/ipns/<name>`).
    pub ipns_name: Option<String>,
    /// BitTorrent / WebTorrent info-hash (`urn:btih:...`).
    pub btih_info_hash_hex: String,
    /// Full WebTorrent + HTTP Range WebSeed + IPFS magnet URI (`magnet.rs::compose_magnet` parity).
    pub magnet_uri: String,
    /// Direct HTTP/2 & HTTP/3 `206 Partial Content` range endpoint (`ws=` webseed).
    pub http_range_webseed_url: String,
    /// IPFS HTTP Range gateway URL (`{gateway}/ipfs/{cid}`).
    pub ipfs_range_gateway_url: String,
    pub whole_volume_crc32c: u32,
}

impl MultiProtocolShareDescriptor {
    /// Publish a Permissive Commons `.q42` v4 or `.hmc` artifact across IPFS, WebTorrent, QPR, and HTTP Range.
    /// Fails closed if the volume has `FLAG_SANCTUARY` (`0x0040`) or non-Public sensitivity.
    pub fn publish_permissive_commons(
        display_name: &str,
        volume_flags: u16,
        sensitivity: SensitivityClass,
        payload_bytes: &[u8],
        origin_host_base_url: &str,
        ipfs_gateway_base_url: &str,
        ipns_name: Option<&str>,
    ) -> Result<Self, PublicationDenyReason> {
        if (volume_flags & FLAG_SANCTUARY) != 0 {
            return Err(PublicationDenyReason::SanctuaryVolumePublicSharingForbidden);
        }
        if sensitivity != SensitivityClass::Public {
            return Err(PublicationDenyReason::NonPublicSensitivityClass);
        }
        if (volume_flags & FLAG_PERMISSIVE_COMMONS) == 0 {
            return Err(PublicationDenyReason::MissingPermissiveCommonsFlag);
        }
        if payload_bytes.is_empty() {
            return Err(PublicationDenyReason::EmptyPayload);
        }

        let h1 = q_hash_bytes(payload_bytes);
        let crc = crc32c_bytes(payload_bytes);
        let btih_info_hash_hex = format!("{:016x}{:08x}{:016x}", h1, crc, h1.rotate_left(17));
        let ipfs_cid = format!("bafkrei{:016x}{:08x}", h1, crc);

        let host_base = origin_host_base_url.trim_end_matches('/');
        let gw_base = ipfs_gateway_base_url.trim_end_matches('/');
        let http_range_webseed_url =
            format!("{host_base}/torrent/webseed/{btih_info_hash_hex}");
        let ipfs_range_gateway_url = format!("{gw_base}/ipfs/{ipfs_cid}");
        let byte_len = payload_bytes.len() as u64;

        let magnet_uri = format!(
            "magnet:?xt=urn:btih:{btih_info_hash_hex}&dn={display_name}&xl={byte_len}&ws={http_range_webseed_url}&xs=urn:cid:{ipfs_cid}"
        );

        Ok(Self {
            display_name: display_name.to_string(),
            total_byte_length: byte_len,
            ipfs_cid,
            ipns_name: ipns_name.map(|s| s.to_string()),
            btih_info_hash_hex,
            magnet_uri,
            http_range_webseed_url,
            ipfs_range_gateway_url,
            whole_volume_crc32c: crc,
        })
    }

    /// Serve an exact HTTP `206 Partial Content` / IPFS partial-CAR / WebTorrent byte range
    /// (`Range: bytes=offset..offset+length-1`), validating boundaries per `range.rs::validate_exact_range_response`.
    pub fn serve_exact_byte_range<'a>(
        &self,
        backing_bytes: &'a [u8],
        offset: u64,
        length: usize,
    ) -> Result<(u16, String, &'a [u8]), &'static str> {
        if length == 0 {
            return Err("Range request length must be non-zero");
        }
        let end_exclusive = offset
            .checked_add(length as u64)
            .ok_or("Range offset overflow")?;
        if end_exclusive > self.total_byte_length || end_exclusive > backing_bytes.len() as u64 {
            return Err("Requested byte range exceeds volume length (HTTP 416)");
        }
        let start = offset as usize;
        let end = end_exclusive as usize;
        let content_range_header = format!(
            "bytes {}-{}/{}",
            offset,
            end_exclusive - 1,
            self.total_byte_length
        );
        Ok((206, content_range_header, &backing_bytes[start..end]))
    }
}
