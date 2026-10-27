//! RFC 1035 Authoritative DNS RDATA Wire Encoders (`SOA`, `NS`, `MX`, `TXT`, `CNAME`, `CAA`) (`WP-15` Swarm 2A).
//!
//! Provides both `Vec<u8>` builders and `HotZeroHeap` slice writers for RFC 1035 / RFC 8659
//! resource record payloads, plus RFC 1035 §4.1.4 domain-name decompression (`0xC0` pointers).

/// Parsed RFC 1035 §3.3.13 `SOA` RDATA fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoaRdata {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// Parsed RFC 8659 §4.1 `CAA` RDATA fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaRdata {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

/// Zero-heap helper that writes an optional prefix label followed by `domain` in RFC 1035 wire format.
#[inline]
pub fn write_domain_name_zero_heap(
    prefix_label: Option<&str>,
    domain: &str,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let mut pos = 0usize;
    if let Some(prefix) = prefix_label {
        let p_trimmed = prefix.trim_matches('.');
        if !p_trimmed.is_empty() {
            let bytes = p_trimmed.as_bytes();
            let len = bytes.len().min(63);
            if pos + 1 + len >= out.len() {
                return Err("RFC 1035 domain wire buffer overflow on prefix label");
            }
            out[pos] = len as u8;
            out[pos + 1..pos + 1 + len].copy_from_slice(&bytes[..len]);
            pos += 1 + len;
        }
    }

    let trimmed = domain.trim_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                continue;
            }
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            if pos + 1 + len >= out.len() {
                return Err("RFC 1035 domain wire buffer overflow on label");
            }
            out[pos] = len as u8;
            out[pos + 1..pos + 1 + len].copy_from_slice(&bytes[..len]);
            pos += 1 + len;
        }
    }

    if pos >= out.len() {
        return Err("RFC 1035 domain wire buffer overflow on root terminator");
    }
    out[pos] = 0x00;
    pos += 1;
    Ok(pos)
}

/// Encode a domain name into RFC 1035 uncompressed wire format (`<length><label>...<0x00>`).
pub fn encode_domain_name_wire(domain: &str, out: &mut Vec<u8>) {
    let trimmed = domain.trim_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                continue;
            }
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.push(0x00);
}

/// Decode an RFC 1035 wire-encoded domain name starting at `start_offset` in `packet`.
///
/// Supports RFC 1035 §4.1.4 `0xC0` message compression pointers with bounded jump protection.
/// Returns `(decoded_domain, next_offset_after_name)`.
pub fn decode_domain_name_wire(packet: &[u8], start_offset: usize) -> Option<(String, usize)> {
    if start_offset >= packet.len() {
        return None;
    }
    let mut domain = String::new();
    let mut pos = start_offset;
    let mut end_offset = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            if !jumped {
                end_offset = pos + 1;
            }
            break;
        }
        match b & 0xC0 {
            0xC0 => {
                if pos + 1 >= packet.len() {
                    return None;
                }
                if !jumped {
                    end_offset = pos + 2;
                    jumped = true;
                }
                jumps += 1;
                if jumps > 16 {
                    return None;
                }
                let ptr = (((b as usize) & 0x3F) << 8) | (packet[pos + 1] as usize);
                if ptr >= packet.len() {
                    return None;
                }
                pos = ptr;
            }
            0x00 => {
                let label_len = b as usize;
                if label_len > 63 || pos + 1 + label_len > packet.len() {
                    return None;
                }
                let label_str =
                    core::str::from_utf8(&packet[pos + 1..pos + 1 + label_len]).ok()?;
                if !domain.is_empty() {
                    domain.push('.');
                }
                domain.push_str(label_str);
                pos += 1 + label_len;
            }
            _ => return None,
        }
    }

    Some((domain, end_offset))
}

/// Zero-heap RFC 1035 `SOA` RDATA writer into caller-supplied buffer.
#[inline]
pub fn write_soa_rdata_zero_heap(
    mname_prefix: Option<&str>,
    rname_prefix: Option<&str>,
    domain: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let mut pos = write_domain_name_zero_heap(mname_prefix, domain, out)?;
    pos += write_domain_name_zero_heap(rname_prefix, domain, &mut out[pos..])?;
    if pos + 20 > out.len() {
        return Err("SOA RDATA 20-byte timers exceed buffer");
    }
    out[pos..pos + 4].copy_from_slice(&serial.to_be_bytes());
    out[pos + 4..pos + 8].copy_from_slice(&refresh.to_be_bytes());
    out[pos + 8..pos + 12].copy_from_slice(&retry.to_be_bytes());
    out[pos + 12..pos + 16].copy_from_slice(&expire.to_be_bytes());
    out[pos + 16..pos + 20].copy_from_slice(&minimum.to_be_bytes());
    Ok(pos + 20)
}

/// Encode RFC 1035 §3.3.13 `SOA` RDATA (`MNAME`, `RNAME`, `SERIAL`, `REFRESH`, `RETRY`, `EXPIRE`, `MINIMUM`).
pub fn encode_soa_rdata(
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    encode_domain_name_wire(mname, &mut out);
    encode_domain_name_wire(rname, &mut out);
    out.extend_from_slice(&serial.to_be_bytes());
    out.extend_from_slice(&refresh.to_be_bytes());
    out.extend_from_slice(&retry.to_be_bytes());
    out.extend_from_slice(&expire.to_be_bytes());
    out.extend_from_slice(&minimum.to_be_bytes());
    out
}

/// Decode RFC 1035 §3.3.13 `SOA` RDATA starting at `rdata_offset` inside `packet`.
pub fn decode_soa_rdata(packet: &[u8], rdata_offset: usize) -> Option<SoaRdata> {
    let (mname, off1) = decode_domain_name_wire(packet, rdata_offset)?;
    let (rname, off2) = decode_domain_name_wire(packet, off1)?;
    if off2 + 20 > packet.len() {
        return None;
    }
    let serial = u32::from_be_bytes(packet[off2..off2 + 4].try_into().ok()?);
    let refresh = u32::from_be_bytes(packet[off2 + 4..off2 + 8].try_into().ok()?);
    let retry = u32::from_be_bytes(packet[off2 + 8..off2 + 12].try_into().ok()?);
    let expire = u32::from_be_bytes(packet[off2 + 12..off2 + 16].try_into().ok()?);
    let minimum = u32::from_be_bytes(packet[off2 + 16..off2 + 20].try_into().ok()?);
    Some(SoaRdata {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

/// Encode RFC 1035 §3.3.11 `NS` RDATA (`NSDNAME`).
pub fn encode_ns_rdata(ns_host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(ns_host.len() + 2);
    encode_domain_name_wire(ns_host, &mut out);
    out
}

/// Encode RFC 1035 §3.3.1 `CNAME` RDATA (`CNAME`).
pub fn encode_cname_rdata(target_host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_host.len() + 2);
    encode_domain_name_wire(target_host, &mut out);
    out
}

/// Zero-heap RFC 1035 `MX` RDATA writer into caller-supplied buffer.
#[inline]
pub fn write_mx_rdata_zero_heap(
    preference: u16,
    exchange_prefix: Option<&str>,
    domain: &str,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    if out.len() < 3 {
        return Err("MX RDATA buffer too small");
    }
    out[0..2].copy_from_slice(&preference.to_be_bytes());
    let name_len = write_domain_name_zero_heap(exchange_prefix, domain, &mut out[2..])?;
    Ok(2 + name_len)
}

/// Encode RFC 1035 §3.3.9 `MX` RDATA (`PREFERENCE` + `EXCHANGE` domain-name).
pub fn encode_mx_rdata(preference: u16, exchange_host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(exchange_host.len() + 4);
    out.extend_from_slice(&preference.to_be_bytes());
    encode_domain_name_wire(exchange_host, &mut out);
    out
}

/// Decode RFC 1035 §3.3.9 `MX` RDATA starting at `rdata_offset` inside `packet`.
pub fn decode_mx_rdata(packet: &[u8], rdata_offset: usize) -> Option<(u16, String)> {
    if rdata_offset + 2 > packet.len() {
        return None;
    }
    let preference = u16::from_be_bytes([packet[rdata_offset], packet[rdata_offset + 1]]);
    let (exchange, _) = decode_domain_name_wire(packet, rdata_offset + 2)?;
    Some((preference, exchange))
}

/// Zero-heap RFC 1035 `TXT` RDATA writer (`<= 255`-byte `<character-string>` chunks).
#[inline]
pub fn write_txt_rdata_zero_heap(txt_bytes: &[u8], out: &mut [u8]) -> Result<usize, &'static str> {
    if txt_bytes.is_empty() {
        if out.is_empty() {
            return Err("TXT RDATA buffer too small");
        }
        out[0] = 0;
        return Ok(1);
    }
    let mut pos = 0usize;
    for chunk in txt_bytes.chunks(255) {
        if pos + 1 + chunk.len() > out.len() {
            return Err("TXT RDATA exceeds output buffer");
        }
        out[pos] = chunk.len() as u8;
        out[pos + 1..pos + 1 + chunk.len()].copy_from_slice(chunk);
        pos += 1 + chunk.len();
    }
    Ok(pos)
}

/// Encode RFC 1035 §3.3.14 `TXT` RDATA as one or more `<= 255`-byte `<character-string>` chunks.
pub fn encode_txt_rdata(txt_value: &str) -> Vec<u8> {
    let bytes = txt_value.as_bytes();
    if bytes.is_empty() {
        return vec![0u8];
    }
    let mut out = Vec::with_capacity(bytes.len() + (bytes.len() / 255) + 1);
    for chunk in bytes.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}

/// Decode RFC 1035 §3.3.14 `TXT` RDATA by concatenating all `<character-string>` chunks.
pub fn decode_txt_rdata(rdata: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut out = String::new();
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        pos += 1;
        if pos + len > rdata.len() {
            return None;
        }
        let s = core::str::from_utf8(&rdata[pos..pos + len]).ok()?;
        out.push_str(s);
        pos += len;
    }
    Some(out)
}

/// Zero-heap RFC 8659 `CAA` RDATA writer into caller-supplied buffer.
#[inline]
pub fn write_caa_rdata_zero_heap(
    flags: u8,
    tag: &str,
    value: &str,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let tag_bytes = tag.as_bytes();
    let val_bytes = value.as_bytes();
    if tag_bytes.is_empty() || tag_bytes.len() > 255 {
        return Err("Invalid RFC 8659 CAA tag length");
    }
    let total = 2 + tag_bytes.len() + val_bytes.len();
    if total > out.len() {
        return Err("CAA RDATA exceeds output buffer");
    }
    out[0] = flags;
    out[1] = tag_bytes.len() as u8;
    out[2..2 + tag_bytes.len()].copy_from_slice(tag_bytes);
    out[2 + tag_bytes.len()..total].copy_from_slice(val_bytes);
    Ok(total)
}

/// Encode RFC 8659 §4.1 `CAA` RDATA (`flags: u8`, `tag_len: u8`, `tag`, `value`).
pub fn encode_caa_rdata(flags: u8, tag: &str, value: &str) -> Vec<u8> {
    let tag_bytes = tag.as_bytes();
    let tag_len = tag_bytes.len().min(255);
    let val_bytes = value.as_bytes();
    let mut out = Vec::with_capacity(2 + tag_len + val_bytes.len());
    out.push(flags);
    out.push(tag_len as u8);
    out.extend_from_slice(&tag_bytes[..tag_len]);
    out.extend_from_slice(val_bytes);
    out
}

/// Decode RFC 8659 §4.1 `CAA` RDATA slice.
pub fn decode_caa_rdata(rdata: &[u8]) -> Option<CaaRdata> {
    if rdata.len() < 2 {
        return None;
    }
    let flags = rdata[0];
    let tag_len = rdata[1] as usize;
    if tag_len == 0 || 2 + tag_len > rdata.len() {
        return None;
    }
    let tag = core::str::from_utf8(&rdata[2..2 + tag_len]).ok()?.to_string();
    let value = core::str::from_utf8(&rdata[2 + tag_len..]).ok()?.to_string();
    Some(CaaRdata { flags, tag, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp15_domain_wire_codec_and_compression_pointer() {
        let mut wire = Vec::new();
        encode_domain_name_wire("webcivics.net.", &mut wire);
        let (decoded, end) = decode_domain_name_wire(&wire, 0).expect("decode uncompressed");
        assert_eq!(decoded, "webcivics.net");
        assert_eq!(end, wire.len());

        // Append `ns1` + pointer to offset 0 (0xC000)
        let ptr_start = wire.len();
        wire.extend_from_slice(b"\x03ns1\xC0\x00");
        let (compressed, ptr_end) =
            decode_domain_name_wire(&wire, ptr_start).expect("decode 0xC0 pointer");
        assert_eq!(compressed, "ns1.webcivics.net");
        assert_eq!(ptr_end, wire.len());
    }

    #[test]
    fn wp15_soa_ns_cname_mx_txt_caa_rdata_roundtrip() {
        let soa_bytes = encode_soa_rdata(
            "ns1.webcivics.net",
            "hostmaster.webcivics.net",
            2026102701,
            3600,
            600,
            604800,
            300,
        );
        let soa = decode_soa_rdata(&soa_bytes, 0).expect("decode SOA");
        assert_eq!(soa.mname, "ns1.webcivics.net");
        assert_eq!(soa.rname, "hostmaster.webcivics.net");
        assert_eq!(soa.serial, 2026102701);
        assert_eq!(soa.refresh, 3600);
        assert_eq!(soa.retry, 600);
        assert_eq!(soa.expire, 604800);
        assert_eq!(soa.minimum, 300);

        let ns = encode_ns_rdata("ns1.webcivics.net");
        assert_eq!(decode_domain_name_wire(&ns, 0).unwrap().0, "ns1.webcivics.net");

        let cname = encode_cname_rdata("target.webcivics.net");
        assert_eq!(
            decode_domain_name_wire(&cname, 0).unwrap().0,
            "target.webcivics.net"
        );

        let mx = encode_mx_rdata(10, "mail.webcivics.net");
        let (pref, exch) = decode_mx_rdata(&mx, 0).expect("decode MX");
        assert_eq!(pref, 10);
        assert_eq!(exch, "mail.webcivics.net");

        // Short TXT (< 255 bytes)
        let txt_short = encode_txt_rdata("v=spf1 mx -all");
        assert_eq!(txt_short[0], 14);
        assert_eq!(decode_txt_rdata(&txt_short).as_deref(), Some("v=spf1 mx -all"));

        // Long TXT (> 255 bytes -> multi-chunk character-strings)
        let long_str = "k=".to_string() + &"A".repeat(300);
        let txt_long = encode_txt_rdata(&long_str);
        assert_eq!(txt_long[0], 255);
        assert_eq!(txt_long[256], 47);
        assert_eq!(decode_txt_rdata(&txt_long).as_deref(), Some(long_str.as_str()));

        // RFC 8659 CAA
        let caa = encode_caa_rdata(0, "issue", "letsencrypt.org");
        let parsed_caa = decode_caa_rdata(&caa).expect("decode CAA");
        assert_eq!(parsed_caa.flags, 0);
        assert_eq!(parsed_caa.tag, "issue");
        assert_eq!(parsed_caa.value, "letsencrypt.org");
    }
}
