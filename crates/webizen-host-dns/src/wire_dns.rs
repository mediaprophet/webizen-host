//! WP-09 (D1.1) & WP-15 (Swarm 2A): RFC 1035 Binary DNS Wire-Packet Parser, Zero-Heap Serializer,
//! and Live UDP + RFC 7766 TCP Socket Servers over [`NQuinDnsZoneRing`].
//!
//! Adheres strictly to `AGENTS.md`:
//! - Tier-1 `HotZeroHeap` packet handling (`handle_rfc1035_packet_zero_heap`)
//! - Standards-compliant RFC 1035 (`A`, `AAAA`, `SOA`, `NS`, `MX`, `CNAME`, `TXT`) and RFC 8659 (`CAA`) RDATA
//! - Consent-gated `QPolicy` split-horizon resolution (`NoError` vs `NXDOMAIN` / `Refused`)
//! - Real `std::net::UdpSocket` and RFC 7766 `std::net::TcpListener` / `TcpStream` wire transport

use crate::rdata_codec::{
    write_caa_rdata_zero_heap, write_domain_name_zero_heap, write_mx_rdata_zero_heap,
    write_soa_rdata_zero_heap, write_txt_rdata_zero_heap,
};
use crate::{DnsQueryContext, DnsRcode, DnsRrType, NQuinDnsZoneRing};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Parsed RFC 1035 DNS Question header and first question entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsWireQuestion {
    pub tx_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end_offset: usize,
}

/// Zero-heap internal RFC 1035 query parser writing normalized QNAME into a stack buffer.
#[inline]
pub fn parse_rfc1035_query_zero_heap<'a>(
    packet: &[u8],
    qname_buf: &'a mut [u8; 256],
) -> Result<(u16, &'a str, u16, u16, usize), &'static str> {
    if packet.len() < 12 {
        return Err("RFC 1035 DNS packet shorter than 12-byte header");
    }
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err("RFC 1035 DNS query has QDCOUNT == 0");
    }

    let (mut pos, mut out_len) = (12usize, 0usize);
    loop {
        if pos >= packet.len() {
            return Err("Truncated RFC 1035 QNAME label length byte");
        }
        let label_len = packet[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if (label_len & 0xC0) != 0 {
            return Err("Pointer compression not permitted in single-question query QNAME");
        }
        if label_len > 63 || pos + label_len > packet.len() {
            return Err("Invalid or truncated RFC 1035 QNAME label");
        }
        if out_len > 0 {
            if out_len >= qname_buf.len() {
                return Err("QNAME exceeds 255-byte RFC 1035 limit");
            }
            qname_buf[out_len] = b'.';
            out_len += 1;
        }
        if out_len + label_len > qname_buf.len() {
            return Err("QNAME exceeds 255-byte RFC 1035 limit");
        }
        for i in 0..label_len {
            qname_buf[out_len + i] = packet[pos + i].to_ascii_lowercase();
        }
        out_len += label_len;
        pos += label_len;
    }

    if pos + 4 > packet.len() {
        return Err("Truncated RFC 1035 QTYPE/QCLASS fields");
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    let question_end_offset = pos + 4;
    let qname_str = core::str::from_utf8(&qname_buf[..out_len])
        .map_err(|_| "RFC 1035 QNAME is not valid ASCII/UTF-8")?;

    Ok((tx_id, qname_str, qtype, qclass, question_end_offset))
}

/// Parse an RFC 1035 binary DNS query packet into [`DnsWireQuestion`].
pub fn parse_rfc1035_query(packet: &[u8]) -> Result<DnsWireQuestion, &'static str> {
    let mut stack_buf = [0u8; 256];
    let (tx_id, qname, qtype, qclass, question_end_offset) =
        parse_rfc1035_query_zero_heap(packet, &mut stack_buf)?;
    Ok(DnsWireQuestion {
        tx_id,
        qname: qname.to_string(),
        qtype,
        qclass,
        question_end_offset,
    })
}

/// Build a standard RFC 1035 DNS query packet (`RD=1`, `QDCOUNT=1`, `QCLASS=1 IN`).
pub fn build_rfc1035_query_packet(tx_id: u16, domain: &str, rr_type: DnsRrType) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&[0u8; 6]); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0

    let trimmed = domain.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            pkt.push(len as u8);
            pkt.extend_from_slice(&bytes[..len]);
        }
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&(rr_type as u16).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

/// Map a 16-bit wire QTYPE code to [`DnsRrType`].
#[inline]
pub fn map_qtype(qtype: u16) -> Option<DnsRrType> {
    match qtype {
        1 => Some(DnsRrType::A),
        2 => Some(DnsRrType::NS),
        5 => Some(DnsRrType::CNAME),
        6 => Some(DnsRrType::SOA),
        15 => Some(DnsRrType::MX),
        16 => Some(DnsRrType::TXT),
        28 => Some(DnsRrType::AAAA),
        52 => Some(DnsRrType::TLSA),
        65 => Some(DnsRrType::HTTPS),
        257 => Some(DnsRrType::CAA),
        65280 => Some(DnsRrType::DID),
        _ => None,
    }
}

/// Zero-heap RFC 1035 packet handler over [`NQuinDnsZoneRing`].
pub fn handle_rfc1035_packet_zero_heap(
    ring: &NQuinDnsZoneRing,
    query_ctx: &DnsQueryContext,
    req_packet: &[u8],
    out_resp: &mut [u8; 512],
) -> Result<usize, &'static str> {
    let mut qname_buf = [0u8; 256];
    let (tx_id, qname, qtype, _qclass, question_end_offset) =
        parse_rfc1035_query_zero_heap(req_packet, &mut qname_buf)?;
    if question_end_offset > 380 {
        return Err("RFC 1035 question section exceeds UDP response buffer bounds");
    }

    let (rcode, found_quin, resolved_rr, custom_bytes) = match map_qtype(qtype) {
        Some(rr_type) => {
            let (rc, q, rdata) = ring.resolve_with_rdata_zero_heap(qname, rr_type, query_ctx);
            (rc, q, Some(rr_type), rdata)
        }
        None => (DnsRcode::NxDomain, None, None, &[][..]),
    };

    let has_answer = rcode == DnsRcode::NoError && found_quin.is_some();
    let flags: u16 = 0x8400u16 | (rcode as u16);
    let ancount: u16 = if has_answer { 1 } else { 0 };

    out_resp[0..2].copy_from_slice(&tx_id.to_be_bytes());
    out_resp[2..4].copy_from_slice(&flags.to_be_bytes());
    out_resp[4..6].copy_from_slice(&1u16.to_be_bytes());
    out_resp[6..8].copy_from_slice(&ancount.to_be_bytes());
    out_resp[8..12].copy_from_slice(&[0u8; 4]);
    out_resp[12..question_end_offset].copy_from_slice(&req_packet[12..question_end_offset]);
    let mut pos = question_end_offset;

    if let (DnsRcode::NoError, Some(quin), Some(rr_type)) = (rcode, found_quin, resolved_rr) {
        out_resp[pos..pos + 2].copy_from_slice(&[0xC0, 0x0C]);
        pos += 2;
        out_resp[pos..pos + 2].copy_from_slice(&(rr_type as u16).to_be_bytes());
        pos += 2;
        out_resp[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        pos += 2;
        let ttl = (quin.metadata & 0xFFFF_FFFF) as u32;
        out_resp[pos..pos + 4].copy_from_slice(&ttl.to_be_bytes());
        pos += 4;
        let custom_str = core::str::from_utf8(custom_bytes).ok().map(str::trim).filter(|s| !s.is_empty());

        match rr_type {
            DnsRrType::A => {
                out_resp[pos..pos + 2].copy_from_slice(&4u16.to_be_bytes());
                out_resp[pos + 2..pos + 6].copy_from_slice(&(quin.object as u32).to_be_bytes());
                pos += 6;
            }
            DnsRrType::AAAA => {
                out_resp[pos..pos + 2].copy_from_slice(&16u16.to_be_bytes());
                out_resp[pos + 2..pos + 10]
                    .copy_from_slice(&[0xfd, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x01]);
                out_resp[pos + 10..pos + 18].copy_from_slice(&quin.object.to_be_bytes());
                pos += 18;
            }
            DnsRrType::SOA => {
                let rdlen = write_soa_rdata_zero_heap(
                    Some("ns1"), Some("hostmaster"), qname, 2026102701, 3600, 600, 604800, 300, &mut out_resp[pos + 2..],
                )?;
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            DnsRrType::NS => {
                let rdlen = match custom_str {
                    Some(host) => write_domain_name_zero_heap(None, host, &mut out_resp[pos + 2..])?,
                    None => write_domain_name_zero_heap(Some("ns1"), qname, &mut out_resp[pos + 2..])?,
                };
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            DnsRrType::MX => {
                let rdlen = match custom_str {
                    Some(s) => match s.split_once(char::is_whitespace).and_then(|(p, ex)| p.trim().parse::<u16>().ok().map(|pr| (pr, ex.trim()))) {
                        Some((pref, exch)) if !exch.is_empty() => write_mx_rdata_zero_heap(pref, None, exch, &mut out_resp[pos + 2..])?,
                        _ => write_mx_rdata_zero_heap(10, None, s, &mut out_resp[pos + 2..])?,
                    },
                    None => write_mx_rdata_zero_heap(10, Some("mail"), qname, &mut out_resp[pos + 2..])?,
                };
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            DnsRrType::CNAME => {
                let target = custom_str.unwrap_or(qname);
                let rdlen = write_domain_name_zero_heap(None, target, &mut out_resp[pos + 2..])?;
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            DnsRrType::TXT => {
                let txt_payload = if custom_bytes.is_empty() { b"v=spf1 mx -all" as &[u8] } else { custom_bytes };
                let rdlen = write_txt_rdata_zero_heap(txt_payload, &mut out_resp[pos + 2..])?;
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            DnsRrType::CAA => {
                let issuer = custom_str.map(|s| s.strip_prefix("0 issue ").unwrap_or(s)).unwrap_or("letsencrypt.org");
                let rdlen = write_caa_rdata_zero_heap(0, "issue", issuer, &mut out_resp[pos + 2..])?;
                out_resp[pos..pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
                pos += 2 + rdlen;
            }
            _ => {
                out_resp[pos..pos + 2].copy_from_slice(&8u16.to_be_bytes());
                out_resp[pos + 2..pos + 10].copy_from_slice(&quin.object.to_be_bytes());
                pos += 10;
            }
        }
    }

    Ok(pos)
}

/// Bind a live local UDP socket (`127.0.0.1:0`) and serve up to `max_requests` RFC 1035 DNS queries.
pub fn serve_udp_dns_requests(
    ring: Arc<NQuinDnsZoneRing>,
    default_ctx: DnsQueryContext,
    max_requests: usize,
) -> std::io::Result<(SocketAddr, JoinHandle<usize>)> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let local_addr = socket.local_addr()?;

    let handle = thread::spawn(move || {
        let (mut req_buf, mut resp_buf, mut served) = ([0u8; 512], [0u8; 512], 0usize);
        while served < max_requests {
            match socket.recv_from(&mut req_buf) {
                Ok((n, peer)) => {
                    if let Ok(resp_len) = handle_rfc1035_packet_zero_heap(
                        &ring,
                        &default_ctx,
                        &req_buf[..n],
                        &mut resp_buf,
                    ) {
                        let _ = socket.send_to(&resp_buf[..resp_len], peer);
                    }
                    served += 1;
                }
                Err(_) => break,
            }
        }
        served
    });

    Ok((local_addr, handle))
}

/// Bind a live local RFC 7766 TCP socket (`127.0.0.1:0`) and serve up to `max_requests` length-prefixed DNS queries.
pub fn serve_tcp_dns_requests(
    ring: Arc<NQuinDnsZoneRing>,
    default_ctx: DnsQueryContext,
    max_requests: usize,
) -> std::io::Result<(SocketAddr, JoinHandle<usize>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;

    let handle = thread::spawn(move || {
        let (mut req_buf, mut resp_buf, mut served) = ([0u8; 512], [0u8; 512], 0usize);
        for mut stream in listener.incoming().flatten() {
            if served >= max_requests {
                break;
            }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            while served < max_requests {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len == 0
                    || msg_len > req_buf.len()
                    || stream.read_exact(&mut req_buf[..msg_len]).is_err()
                {
                    break;
                }
                if let Ok(resp_len) = handle_rfc1035_packet_zero_heap(
                    &ring,
                    &default_ctx,
                    &req_buf[..msg_len],
                    &mut resp_buf,
                ) {
                    let prefix = (resp_len as u16).to_be_bytes();
                    if stream.write_all(&prefix).is_err()
                        || stream.write_all(&resp_buf[..resp_len]).is_err()
                    {
                        break;
                    }
                    let _ = stream.flush();
                }
                served += 1;
            }
            if served >= max_requests {
                break;
            }
        }
        served
    });

    Ok((local_addr, handle))
}

/// Send an RFC 7766 TCP DNS query (2-byte big-endian length prefix) and return the unframed DNS response packet.
pub fn query_dns_over_tcp(
    server_addr: SocketAddr,
    query_packet: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&(query_packet.len() as u16).to_be_bytes())?;
    stream.write_all(query_packet)?;
    stream.flush()?;

    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf)?;
    let mut resp = vec![0u8; u16::from_be_bytes(resp_len_buf) as usize];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata_codec::{
        decode_caa_rdata, decode_domain_name_wire, decode_mx_rdata, decode_soa_rdata,
        decode_txt_rdata,
    };
    use webizen_host_core::{q_hash, SensitivityClass};

    #[test]
    fn wp20_custom_rdata_txt_cname_mx_served_over_tcp_and_udp_dns() {
        let mut ring = NQuinDnsZoneRing::new();
        let zone_did = q_hash("did:qi:webcivics_steward");
        ring.upsert_record_with_rdata("_dmarc.civics.au", DnsRrType::TXT, q_hash("dmarc"), b"v=DMARC1; p=reject; rua=mailto:postmaster@civics.au", zone_did, SensitivityClass::Public, 600, 1);
        ring.upsert_record_with_rdata("docs.civics.au", DnsRrType::CNAME, q_hash("docs"), b"portal.webcivics.net", zone_did, SensitivityClass::Public, 600, 2);
        ring.upsert_record_with_rdata("civics.au", DnsRrType::MX, q_hash("mx"), b"20 mx-relay.civics.au", zone_did, SensitivityClass::Public, 600, 3);

        let ctx = DnsQueryContext { has_valid_dni_cookie: false, has_webizen_id_tls_session: false, requester_jurisdiction_hash: q_hash("AU") };
        let (tcp_addr, tcp_handle) = serve_tcp_dns_requests(Arc::new(ring), ctx, 3).unwrap();

        let r_txt = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x3001, "_dmarc.civics.au", DnsRrType::TXT)).unwrap();
        let off_txt = parse_rfc1035_query(&r_txt).unwrap().question_end_offset + 12;
        assert_eq!(decode_txt_rdata(&r_txt[off_txt..]).as_deref(), Some("v=DMARC1; p=reject; rua=mailto:postmaster@civics.au"));

        let r_cname = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x3002, "docs.civics.au", DnsRrType::CNAME)).unwrap();
        let off_cname = parse_rfc1035_query(&r_cname).unwrap().question_end_offset + 12;
        assert_eq!(decode_domain_name_wire(&r_cname, off_cname).unwrap().0, "portal.webcivics.net");

        let r_mx = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x3003, "civics.au", DnsRrType::MX)).unwrap();
        let off_mx = parse_rfc1035_query(&r_mx).unwrap().question_end_offset + 12;
        assert_eq!(decode_mx_rdata(&r_mx, off_mx).unwrap(), (20, "mx-relay.civics.au".to_string()));
        assert_eq!(tcp_handle.join().unwrap(), 3);
    }

    #[test]
    fn wp09_rfc1035_udp_wire_dns_server_resolves_public_and_gates_restricted() {
        let mut ring = NQuinDnsZoneRing::new();
        let zone_did = q_hash("did:qi:webcivics_steward");
        let pub_ipv4 = u32::from_be_bytes([203, 0, 113, 42]) as u64;
        ring.upsert_record("ns.webcivics.net", DnsRrType::A, pub_ipv4, zone_did, SensitivityClass::Public, 300, 1);
        ring.upsert_record("mylaptop.family.civics.au", DnsRrType::AAAA, 0x1122_3344_5566_7788u64, zone_did, SensitivityClass::Restricted, 60, 2);

        let public_ctx = DnsQueryContext {
            has_valid_dni_cookie: false,
            has_webizen_id_tls_session: false,
            requester_jurisdiction_hash: q_hash("AU"),
        };
        let (server_addr, server_handle) =
            serve_udp_dns_requests(Arc::new(ring), public_ctx, 2).expect("bind UDP DNS server");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind UDP DNS client");
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let q1 = build_rfc1035_query_packet(0x1337, "ns.webcivics.net", DnsRrType::A);
        client.send_to(&q1, server_addr).expect("send q1");
        let mut resp1 = [0u8; 512];
        let (n1, _) = client.recv_from(&mut resp1).expect("recv resp1");
        assert!(n1 > 16 && u16::from_be_bytes([resp1[0], resp1[1]]) == 0x1337);
        assert_eq!(resp1[3] & 0x0F, DnsRcode::NoError as u8);
        assert_eq!(&resp1[n1 - 4..n1], &[203, 0, 113, 42]);

        let q2 = build_rfc1035_query_packet(0x4242, "mylaptop.family.civics.au", DnsRrType::AAAA);
        client.send_to(&q2, server_addr).expect("send q2");
        let mut resp2 = [0u8; 512];
        let (n2, _) = client.recv_from(&mut resp2).expect("recv resp2");
        assert!(n2 >= 12 && (resp2[3] & 0x0F) == DnsRcode::NxDomain as u8);
        assert_eq!(server_handle.join().expect("join DNS server thread"), 2);
    }

    #[test]
    fn wp15_rfc1035_soa_mx_txt_caa_and_rfc7766_tcp_dns_server() {
        let mut ring = NQuinDnsZoneRing::new();
        let zone_did = q_hash("did:qi:webcivics_steward");
        for &rr in &[DnsRrType::SOA, DnsRrType::MX, DnsRrType::TXT, DnsRrType::CAA] {
            ring.upsert_record("webcivics.net", rr, q_hash("webcivics.net"), zone_did, SensitivityClass::Public, 300, 1);
        }
        let ctx = DnsQueryContext {
            has_valid_dni_cookie: false,
            has_webizen_id_tls_session: false,
            requester_jurisdiction_hash: q_hash("AU"),
        };
        let (tcp_addr, tcp_handle) =
            serve_tcp_dns_requests(Arc::new(ring), ctx, 4).expect("bind TCP DNS server");

        let q_soa = build_rfc1035_query_packet(0x2001, "webcivics.net", DnsRrType::SOA);
        let r_soa = query_dns_over_tcp(tcp_addr, &q_soa).expect("TCP SOA query");
        let rdata_off = parse_rfc1035_query(&r_soa).unwrap().question_end_offset + 12;
        let soa = decode_soa_rdata(&r_soa, rdata_off).expect("decode SOA RDATA");
        assert_eq!((soa.mname.as_str(), soa.rname.as_str(), soa.serial), ("ns1.webcivics.net", "hostmaster.webcivics.net", 2026102701));

        let r_mx = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x2002, "webcivics.net", DnsRrType::MX)).unwrap();
        assert_eq!(decode_mx_rdata(&r_mx, rdata_off).unwrap(), (10, "mail.webcivics.net".to_string()));

        let r_txt = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x2003, "webcivics.net", DnsRrType::TXT)).unwrap();
        assert_eq!(decode_txt_rdata(&r_txt[rdata_off..]).as_deref(), Some("v=spf1 mx -all"));

        let r_caa = query_dns_over_tcp(tcp_addr, &build_rfc1035_query_packet(0x2004, "webcivics.net", DnsRrType::CAA)).unwrap();
        let caa = decode_caa_rdata(&r_caa[rdata_off..]).expect("decode CAA RDATA");
        assert_eq!((caa.flags, caa.tag.as_str(), caa.value.as_str()), (0, "issue", "letsencrypt.org"));

        assert_eq!(tcp_handle.join().expect("join TCP DNS thread"), 4);
    }
}
