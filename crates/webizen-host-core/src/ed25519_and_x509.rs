//! Pure-Rust RFC 8032 Twisted-Edwards Ed25519 signatures over $\mathbb{F}_{2^{255}-19}$
//! (`OID 1.3.101.112`) and RFC 5280 ASN.1 DER X.509 v3 Certificate & RFC 5958 PKCS#8 v1
//! Private Key encoding and verification for `webizen-host`.

use crate::crypto::sha256;
use crate::sha512_and_ed25519_curve::{
    rfc8032_ed25519_pubkey_from_seed, rfc8032_ed25519_sign, rfc8032_ed25519_verify,
};

/// ASN.1 DER `AlgorithmIdentifier` for Ed25519 (`OID 1.3.101.112` = `06 03 2B 65 70`).
pub const ED25519_ALG_ID_DER: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];

/// Deterministically derive the 32-byte RFC 8032 Ed25519 public key from a 32-byte private key seed.
#[inline]
pub fn ed25519_public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    rfc8032_ed25519_pubkey_from_seed(seed)
}

/// Produce a deterministic 64-byte RFC 8032 Ed25519 detached signature (`R || S`) over `message`.
#[inline]
pub fn ed25519_sign_detached(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    rfc8032_ed25519_sign(seed, message)
}

/// Verify a 64-byte RFC 8032 Ed25519 detached signature over `message` using **only** `public_key`.
#[inline]
pub fn ed25519_verify_detached(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    rfc8032_ed25519_verify(public_key, message, signature)
}

fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]);
    }
}

fn wrap_der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(tag);
    push_der_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn read_der_tlv(input: &[u8]) -> Option<(u8, usize, usize)> {
    if input.len() < 2 { return None; }
    let (tag, first) = (input[0], input[1] as usize);
    let (hdr_len, content_len) = if (first & 0x80) == 0 {
        (2usize, first)
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || num_bytes > 2 || input.len() < 2 + num_bytes { return None; }
        let mut len = 0usize;
        for i in 0..num_bytes { len = (len << 8) | (input[2 + i] as usize); }
        (2 + num_bytes, len)
    };
    if hdr_len + content_len > input.len() { return None; }
    Some((tag, hdr_len, content_len))
}

fn encode_rdn_common_name(common_name: &str) -> Vec<u8> {
    let mut attr_tv = Vec::new();
    attr_tv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID 2.5.4.3 (id-at-commonName)
    attr_tv.extend_from_slice(&wrap_der_tlv(0x0C, common_name.as_bytes()));
    wrap_der_tlv(0x30, &wrap_der_tlv(0x31, &wrap_der_tlv(0x30, &attr_tv)))
}

/// Build and sign a standards-compliant RFC 5280 ASN.1 DER X.509 v3 Certificate (`OID 1.3.101.112`)
/// with `SubjectPublicKeyInfo` and `subjectAltName` (`dNSName` + `uniformResourceIdentifier`).
pub fn encode_x509_v3_ed25519_der(
    domain: &str,
    steward_did_qi: &str,
    seed: &[u8; 32],
) -> (Vec<u8>, [u8; 32], [u8; 64]) {
    let public_key = ed25519_public_key_from_seed(seed);
    let serial_digest = sha256(domain.as_bytes());
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&serial_digest[0..16]);
    serial[0] = (serial[0] & 0x7F) | 0x01;

    let mut tbs_body = Vec::with_capacity(320);
    tbs_body.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]); // [0] EXPLICIT Version v3
    tbs_body.extend_from_slice(&wrap_der_tlv(0x02, &serial));
    tbs_body.extend_from_slice(&ED25519_ALG_ID_DER);
    tbs_body.extend_from_slice(&encode_rdn_common_name(domain));

    let mut validity_body = Vec::with_capacity(30);
    validity_body.extend_from_slice(&wrap_der_tlv(0x17, b"260101000000Z"));
    validity_body.extend_from_slice(&wrap_der_tlv(0x17, b"360101000000Z"));
    tbs_body.extend_from_slice(&wrap_der_tlv(0x30, &validity_body));
    tbs_body.extend_from_slice(&encode_rdn_common_name(domain));

    let mut spki_body = Vec::with_capacity(44);
    spki_body.extend_from_slice(&ED25519_ALG_ID_DER);
    let mut spki_bitstring = Vec::with_capacity(33);
    spki_bitstring.push(0x00);
    spki_bitstring.extend_from_slice(&public_key);
    spki_body.extend_from_slice(&wrap_der_tlv(0x03, &spki_bitstring));
    tbs_body.extend_from_slice(&wrap_der_tlv(0x30, &spki_body));

    let mut general_names_body = Vec::new();
    general_names_body.extend_from_slice(&wrap_der_tlv(0x82, domain.as_bytes()));
    general_names_body.extend_from_slice(&wrap_der_tlv(0x86, steward_did_qi.as_bytes()));
    let general_names_seq = wrap_der_tlv(0x30, &general_names_body);

    let mut san_ext_body = Vec::new();
    san_ext_body.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11]); // OID 2.5.29.17
    san_ext_body.extend_from_slice(&wrap_der_tlv(0x04, &general_names_seq));
    let extensions_seq = wrap_der_tlv(0x30, &wrap_der_tlv(0x30, &san_ext_body));
    tbs_body.extend_from_slice(&wrap_der_tlv(0xA3, &extensions_seq));

    let tbs_der = wrap_der_tlv(0x30, &tbs_body);
    let signature = ed25519_sign_detached(seed, &tbs_der);

    let mut cert_body = Vec::with_capacity(tbs_der.len() + 80);
    cert_body.extend_from_slice(&tbs_der);
    cert_body.extend_from_slice(&ED25519_ALG_ID_DER);
    let mut sig_bitstring = Vec::with_capacity(65);
    sig_bitstring.push(0x00);
    sig_bitstring.extend_from_slice(&signature);
    cert_body.extend_from_slice(&wrap_der_tlv(0x03, &sig_bitstring));

    (wrap_der_tlv(0x30, &cert_body), public_key, signature)
}

/// Parse an ASN.1 DER X.509 v3 certificate, confirm its `SubjectPublicKeyInfo` contains
/// `expected_public_key`, and cryptographically verify its `TBSCertificate` signature.
pub fn verify_x509_v3_ed25519_der(cert_der: &[u8], expected_public_key: &[u8; 32]) -> bool {
    let Some((outer_tag, outer_hdr, outer_len)) = read_der_tlv(cert_der) else { return false; };
    if outer_tag != 0x30 || outer_hdr + outer_len != cert_der.len() { return false; }
    let body = &cert_der[outer_hdr..];

    let Some((tbs_tag, tbs_hdr, tbs_len)) = read_der_tlv(body) else { return false; };
    if tbs_tag != 0x30 { return false; }
    let tbs_total = tbs_hdr + tbs_len;
    let tbs_der = &body[..tbs_total];

    let mut spki_pattern = [0u8; 35];
    spki_pattern[0..3].copy_from_slice(&[0x03, 0x21, 0x00]);
    spki_pattern[3..35].copy_from_slice(expected_public_key);
    if !tbs_der.windows(35).any(|w| w == spki_pattern)
        || !tbs_der.windows(ED25519_ALG_ID_DER.len()).any(|w| w == ED25519_ALG_ID_DER)
    {
        return false;
    }

    let rest = &body[tbs_total..];
    if rest.len() != ED25519_ALG_ID_DER.len() + 67 || &rest[..ED25519_ALG_ID_DER.len()] != &ED25519_ALG_ID_DER {
        return false;
    }
    let sig_tlv = &rest[ED25519_ALG_ID_DER.len()..];
    if sig_tlv[0..3] != [0x03, 0x41, 0x00] { return false; }
    let signature: [u8; 64] = sig_tlv[3..67].try_into().unwrap();
    ed25519_verify_detached(expected_public_key, tbs_der, &signature)
}

/// Encode a 32-byte Ed25519 seed as an RFC 5958 / RFC 8410 PKCS#8 v1 `OneAsymmetricKey` DER structure.
pub fn encode_pkcs8_ed25519_private_key_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    der.extend_from_slice(seed);
    der
}

/// RFC 4648 standard Base64 encoder.
pub fn base64_encode_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    for chunk in bytes.chunks(3) {
        let (b0, b1, b2) = (chunk[0] as u32, if chunk.len() > 1 { chunk[1] as u32 } else { 0 }, if chunk.len() > 2 { chunk[2] as u32 } else { 0 });
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((triple >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(triple & 0x3F) as usize] as char } else { '=' });
    }
    out
}

/// RFC 4648 standard Base64 decoder (ignores ASCII whitespace).
pub fn base64_decode_standard(encoded: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = encoded.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || clean.len() % 4 != 0 { return None; }
    let decode_val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks(4) {
        let (v0, v1) = (decode_val(chunk[0])?, decode_val(chunk[1])?);
        let v2 = if chunk[2] == b'=' { 0 } else { decode_val(chunk[2])? };
        let v3 = if chunk[3] == b'=' { 0 } else { decode_val(chunk[3])? };
        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' { out.push(((triple >> 8) & 0xFF) as u8); }
        if chunk[3] != b'=' { out.push((triple & 0xFF) as u8); }
    }
    Some(out)
}

/// Wrap ASN.1 DER bytes in an RFC 7468 PEM block (`-----BEGIN <label>-----`).
pub fn der_to_pem(label: &str, der_bytes: &[u8]) -> String {
    let b64 = base64_encode_standard(der_bytes);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(core::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Decode an RFC 7468 PEM block back into raw ASN.1 DER bytes.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let b64_body: String = pem.lines().map(str::trim).filter(|l| !l.starts_with("-----BEGIN ") && !l.starts_with("-----END ")).collect();
    base64_decode_standard(&b64_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_public_key_only_verification_and_tamper_rejection() {
        let seed = [0x42u8; 32];
        let msg = b"webizen-host asymmetric Ed25519 signature over F_{2^255-19}";
        let pubkey = ed25519_public_key_from_seed(&seed);
        let sig = ed25519_sign_detached(&seed, msg);

        assert!(ed25519_verify_detached(&pubkey, msg, &sig));

        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 0x01;
        assert!(!ed25519_verify_detached(&pubkey, &bad_msg, &sig));

        let mut bad_sig = sig;
        bad_sig[10] ^= 0x01;
        assert!(!ed25519_verify_detached(&pubkey, msg, &bad_sig));

        let mut bad_sig_z = sig;
        bad_sig_z[45] ^= 0x01;
        assert!(!ed25519_verify_detached(&pubkey, msg, &bad_sig_z));

        let mut bad_pub = pubkey;
        bad_pub[3] ^= 0x01;
        assert!(!ed25519_verify_detached(&bad_pub, msg, &sig));
    }

    #[test]
    fn x509_v3_der_and_pkcs8_der_generation_and_verification() {
        let seed = [0x77u8; 32];
        let (cert_der, pubkey, _sig) =
            encode_x509_v3_ed25519_der("commons.example.org", "did:qi:steward-alice", &seed);
        assert_eq!(cert_der[0], 0x30);
        assert!(verify_x509_v3_ed25519_der(&cert_der, &pubkey));

        let mut tampered_cert = cert_der.clone();
        let mid = tampered_cert.len() / 2;
        tampered_cert[mid] ^= 0x01;
        assert!(!verify_x509_v3_ed25519_der(&tampered_cert, &pubkey));

        let pkcs8 = encode_pkcs8_ed25519_private_key_der(&seed);
        assert_eq!(pkcs8.len(), 48);
        assert_eq!(&pkcs8[0..2], &[0x30, 0x2E]);
        assert_eq!(&pkcs8[16..48], &seed);

        let pem = der_to_pem("CERTIFICATE", &cert_der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let decoded_der = pem_to_der(&pem).expect("decode PEM");
        assert_eq!(decoded_der, cert_der);
    }
}
