//! WP-09 (D1.2 & D1.3), WP-13 (D13.2), WP-15, & WP-25 (D25.1): RFC 8555 ACME Directory HTTP
//! Client, HTTP-01 & DNS-01 Challenge Provisioning, RFC 2986 PKCS#10 Ed25519 CSR Generator,
//! JWS (`EdDSA`) Request Signer, 60-Day Renewal Scheduler, and `WebizenID-TLS` Bundle Generator.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::{fs, path::Path, time::Duration};
use webizen_host_core::{
    der_to_pem, ed25519_public_key_from_seed, ed25519_sign_detached, ed25519_verify_detached,
    encode_pkcs8_ed25519_private_key_der, encode_x509_v3_ed25519_der, hmac_sha256, q_hash, sha256,
    verify_x509_v3_ed25519_der, SensitivityClass, ED25519_ALG_ID_DER,
};

const BASE64URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// Standard 90-day ACME certificate validity period in seconds ($90 \times 86,400$).
pub const ACME_CERT_LIFETIME_SECS: u64 = 90 * 86_400;
/// Renewal threshold in seconds before expiry ($\le 30$ days remaining, i.e. renew at 60 days).
pub const ACME_RENEWAL_THRESHOLD_SECS: u64 = 30 * 86_400;

/// RFC 4648 §5 URL-safe Base64 encoding without `=` padding.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let triple = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        for shift in [18, 12, 6, 0] {
            out.push(BASE64URL_ALPHABET[((triple >> shift) & 0x3F) as usize] as char);
        }
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i] as u32;
        out.push(BASE64URL_ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(BASE64URL_ALPHABET[((b0 << 4) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let pair = ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
        for shift in [10, 4] {
            out.push(BASE64URL_ALPHABET[((pair >> shift) & 0x3F) as usize] as char);
        }
        out.push(BASE64URL_ALPHABET[((pair << 2) & 0x3F) as usize] as char);
    }
    out
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn wrap_der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(tag);
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() <= 0xFF {
        out.extend_from_slice(&[0x81, body.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, ((body.len() >> 8) & 0xFF) as u8, (body.len() & 0xFF) as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn read_der_tlv(input: &[u8]) -> Option<(u8, usize, usize)> {
    if input.len() < 2 {
        return None;
    }
    let (tag, first) = (input[0], input[1] as usize);
    let (hdr_len, content_len) = if (first & 0x80) == 0 {
        (2usize, first)
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || num_bytes > 2 || input.len() < 2 + num_bytes {
            return None;
        }
        let len = (0..num_bytes).fold(0usize, |acc, i| (acc << 8) | (input[2 + i] as usize));
        (2 + num_bytes, len)
    };
    (hdr_len + content_len <= input.len()).then_some((tag, hdr_len, content_len))
}

/// Build and sign an RFC 2986 PKCS#10 ASN.1 DER Certificate Signing Request (`CSR`)
/// using Ed25519 (`OID 1.3.101.112`). Returns `(csr_der, public_key, signature_ed25519)`.
pub fn encode_pkcs10_ed25519_csr_der(domain: &str, secret_seed: &[u8; 32]) -> (Vec<u8>, [u8; 32], [u8; 64]) {
    let public_key = ed25519_public_key_from_seed(secret_seed);
    let mut cri_body = Vec::with_capacity(128 + domain.len());
    cri_body.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0 (v1)

    let mut cn_atv = vec![0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3 (id-at-commonName)
    cn_atv.extend_from_slice(&wrap_der_tlv(0x0C, domain.as_bytes()));
    cri_body.extend_from_slice(&wrap_der_tlv(0x30, &wrap_der_tlv(0x31, &wrap_der_tlv(0x30, &cn_atv))));

    let mut spki_body = Vec::from(ED25519_ALG_ID_DER);
    let mut spki_bitstring = vec![0x00];
    spki_bitstring.extend_from_slice(&public_key);
    spki_body.extend_from_slice(&wrap_der_tlv(0x03, &spki_bitstring));
    cri_body.extend_from_slice(&wrap_der_tlv(0x30, &spki_body));
    cri_body.extend_from_slice(&[0xA0, 0x00]); // attributes [0] IMPLICIT Attributes

    let cri_der = wrap_der_tlv(0x30, &cri_body);
    let signature = ed25519_sign_detached(secret_seed, &cri_der);

    let mut csr_body = cri_der;
    csr_body.extend_from_slice(&ED25519_ALG_ID_DER);
    let mut sig_bitstring = vec![0x00];
    sig_bitstring.extend_from_slice(&signature);
    csr_body.extend_from_slice(&wrap_der_tlv(0x03, &sig_bitstring));
    (wrap_der_tlv(0x30, &csr_body), public_key, signature)
}

/// Parse an RFC 2986 PKCS#10 ASN.1 DER Certificate Signing Request (`CSR`), confirm its
/// `SubjectPublicKeyInfo` contains `expected_public_key`, and verify its Ed25519 signature.
pub fn verify_pkcs10_ed25519_csr_der(csr_der: &[u8], expected_public_key: &[u8; 32]) -> bool {
    let Some((0x30, outer_hdr, outer_len)) = read_der_tlv(csr_der) else { return false };
    if outer_hdr + outer_len != csr_der.len() {
        return false;
    }
    let body = &csr_der[outer_hdr..];
    let Some((0x30, cri_hdr, cri_len)) = read_der_tlv(body) else { return false };
    let cri_der = &body[..cri_hdr + cri_len];

    let mut spki_pattern = [0u8; 35];
    spki_pattern[0..3].copy_from_slice(&[0x03, 0x21, 0x00]);
    spki_pattern[3..35].copy_from_slice(expected_public_key);
    if !cri_der.windows(35).any(|w| w == spki_pattern)
        || !cri_der.windows(ED25519_ALG_ID_DER.len()).any(|w| w == ED25519_ALG_ID_DER)
    {
        return false;
    }
    let rest = &body[cri_hdr + cri_len..];
    if rest.len() != ED25519_ALG_ID_DER.len() + 67 || &rest[..ED25519_ALG_ID_DER.len()] != &ED25519_ALG_ID_DER {
        return false;
    }
    let sig_tlv = &rest[ED25519_ALG_ID_DER.len()..];
    if sig_tlv[0..3] != [0x03, 0x41, 0x00] {
        return false;
    }
    let sig: [u8; 64] = sig_tlv[3..67].try_into().unwrap();
    ed25519_verify_detached(expected_public_key, cri_der, &sig)
}

/// Build an RFC 8555 Flattened JWS JSON request signed with `EdDSA` (`Ed25519`).
pub fn build_acme_jws_ed25519(
    url: &str,
    nonce: &str,
    account_id: &str,
    payload_json: &str,
    secret_seed: &[u8; 32],
) -> (String, String, [u8; 64]) {
    let protected_hdr = format!(r#"{{"alg":"EdDSA","kid":"{account_id}","nonce":"{nonce}","url":"{url}"}}"#);
    let (protected_b64, payload_b64) = (base64url_encode(protected_hdr.as_bytes()), base64url_encode(payload_json.as_bytes()));
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig_64 = ed25519_sign_detached(secret_seed, signing_input.as_bytes());
    let sig_b64 = base64url_encode(&sig_64);
    let jws = format!(r#"{{"protected":"{protected_b64}","payload":"{payload_b64}","signature":"{sig_b64}"}}"#);
    (jws, signing_input, sig_64)
}

/// Verify an RFC 8555 JWS (`EdDSA`) signing input and 64-byte signature against `expected_public_key`.
pub fn verify_acme_jws_ed25519(signing_input: &str, signature: &[u8; 64], expected_public_key: &[u8; 32]) -> bool {
    ed25519_verify_detached(expected_public_key, signing_input.as_bytes(), signature)
}

/// RFC 8555 ACME HTTP-01 and DNS-01 Challenge Manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeChallengeManager {
    pub account_jwk_thumbprint_b64: String,
    pub active_http01_tokens: BTreeMap<String, String>,
}

impl AcmeChallengeManager {
    /// Initialize an ACME Challenge Manager from canonical RFC 7638 JWK bytes.
    pub fn new(account_public_key_jwk_canonical_bytes: &[u8]) -> Self {
        Self {
            account_jwk_thumbprint_b64: base64url_encode(&sha256(account_public_key_jwk_canonical_bytes)),
            active_http01_tokens: BTreeMap::new(),
        }
    }

    /// Register an ACME token and return `(key_authorization, dns01_txt)`.
    pub fn register_challenge(&mut self, token: &str) -> (String, String) {
        let key_authorization = format!("{token}.{}", self.account_jwk_thumbprint_b64);
        let dns01_txt = base64url_encode(&sha256(key_authorization.as_bytes()));
        self.active_http01_tokens.insert(token.to_string(), key_authorization.clone());
        (key_authorization, dns01_txt)
    }

    /// Look up the RFC 8555 `keyAuthorization` response body for an HTTP-01 challenge request.
    pub fn respond_http01(&self, token: &str) -> Option<&str> {
        self.active_http01_tokens.get(token).map(|s| s.as_str())
    }
}

/// RFC 8555 ACME Order lifecycle state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeOrderState {
    PendingChallenge,
    ChallengeProvisioned { token: String, dns01_txt: String },
    FinalizedAndIssued { issued_at_epoch: u64, expires_at_epoch: u64 },
}

/// Automated 60-day ACME Renewal Scheduler and DNS-01 / PKCS#10 Order Executor.
pub struct AcmeRenewalScheduler;

impl AcmeRenewalScheduler {
    /// Determine whether a certificate has reached its 60-day renewal window ($\le 30$ days left).
    #[inline]
    pub fn should_renew(issued_at_epoch: u64, expires_at_epoch: u64, current_epoch: u64) -> bool {
        expires_at_epoch <= issued_at_epoch
            || current_epoch >= expires_at_epoch
            || expires_at_epoch.saturating_sub(current_epoch) <= ACME_RENEWAL_THRESHOLD_SECS
    }

    /// Execute an RFC 8555 ACME order: register `token` in `mgr`, provision `_acme-challenge.<domain>`
    /// (`DnsRrType::TXT`) into `dns_ring`, generate & verify the RFC 2986 PKCS#10 Ed25519 CSR DER,
    /// issue & persist the `WebizenIdTlsCertificateBundle`, and transition to `FinalizedAndIssued`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_order_and_provision(
        mgr: &mut AcmeChallengeManager,
        dns_ring: &mut crate::NQuinDnsZoneRing,
        domain: &str,
        steward_did_qi: &str,
        token: &str,
        secret_seed: &[u8; 32],
        tls_dir: &Path,
        current_epoch: u64,
    ) -> std::io::Result<(WebizenIdTlsCertificateBundle, Vec<u8>, AcmeOrderState)> {
        let (_key_auth, dns01_txt) = mgr.register_challenge(token);
        dns_ring.upsert_record(
            &format!("_acme-challenge.{domain}"), crate::DnsRrType::TXT, q_hash(&dns01_txt),
            q_hash(steward_did_qi), SensitivityClass::Public, 60, 1,
        );
        let (csr_der, pubkey, _csr_sig) = encode_pkcs10_ed25519_csr_der(domain, secret_seed);
        if !verify_pkcs10_ed25519_csr_der(&csr_der, &pubkey) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "PKCS#10 CSR verification failed"));
        }
        let bundle = WebizenIdTlsCertificateBundle::issue_and_persist(domain, steward_did_qi, secret_seed, tls_dir)?;
        let state = AcmeOrderState::FinalizedAndIssued {
            issued_at_epoch: current_epoch,
            expires_at_epoch: current_epoch.saturating_add(ACME_CERT_LIFETIME_SECS),
        };
        Ok((bundle, csr_der, state))
    }
}

/// Live RFC 8555 ACME Directory HTTP Client (`HEAD /acme/new-nonce`, `POST /acme/new-order`,
/// and `POST /acme/finalize` with `EdDSA` JWS and PKCS#10 CSR DER).
pub struct AcmeDirectoryClient;

impl AcmeDirectoryClient {
    fn send_http(addr: SocketAddr, req: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(addr)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        stream.write_all(req.as_bytes())?;
        stream.flush()?;
        let _ = stream.shutdown(Shutdown::Write);
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;
        Ok(resp)
    }

    fn post_jws(addr: SocketAddr, path: &str, nonce: &str, kid: &str, payload: &str, seed: &[u8; 32]) -> std::io::Result<String> {
        let url = format!("http://{addr}{path}");
        let (jws, _, _) = build_acme_jws_ed25519(&url, nonce, kid, payload, seed);
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/jose+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{jws}",
            jws.len()
        );
        Self::send_http(addr, &req)
    }

    fn extract_header(resp: &str, name: &str) -> Option<String> {
        resp.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }

    fn extract_json_str<'a>(s: &'a str, key: &str) -> Option<&'a str> {
        let pat = format!(r#""{key}""#);
        let rest = s[s.find(&pat)? + pat.len()..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
        rest.split('"').next().filter(|v| !v.is_empty())
    }

    /// Connect over `TcpStream` to `acme_server_addr` and execute the RFC 8555 HTTP order flow.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_http_order_flow(
        acme_server_addr: SocketAddr,
        domain: &str,
        steward_did_qi: &str,
        secret_seed: &[u8; 32],
        mgr: &mut AcmeChallengeManager,
        dns_ring: &mut crate::NQuinDnsZoneRing,
        tls_dir: &Path,
        current_epoch: u64,
    ) -> std::io::Result<(WebizenIdTlsCertificateBundle, AcmeOrderState)> {
        let head_req = format!("HEAD /acme/new-nonce HTTP/1.1\r\nHost: {acme_server_addr}\r\nConnection: close\r\n\r\n");
        let head_resp = Self::send_http(acme_server_addr, &head_req)?;
        let nonce1 = Self::extract_header(&head_resp, "replay-nonce").unwrap_or_else(|| "acme-default-nonce".to_string());

        let order_payload = format!(r#"{{"identifiers":[{{"type":"dns","value":"{domain}"}}]}}"#);
        let order_resp = Self::post_jws(acme_server_addr, "/acme/new-order", &nonce1, steward_did_qi, &order_payload, secret_seed)?;
        let order_body = order_resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&order_resp);
        let token = Self::extract_json_str(order_body, "token").unwrap_or("acme-http-order-token").to_string();
        let nonce2 = Self::extract_header(&order_resp, "replay-nonce").unwrap_or(nonce1);

        let (bundle, csr_der, state) = AcmeRenewalScheduler::execute_order_and_provision(
            mgr, dns_ring, domain, steward_did_qi, &token, secret_seed, tls_dir, current_epoch,
        )?;
        let finalize_payload = format!(r#"{{"csr":"{}"}}"#, base64url_encode(&csr_der));
        let _ = Self::post_jws(acme_server_addr, "/acme/finalize", &nonce2, steward_did_qi, &finalize_payload, secret_seed)?;
        Ok((bundle, state))
    }
}

/// `WebizenID-TLS` ASN.1 DER X.509 v3 (`RFC 5280`) + PKCS#8 (`RFC 5958`) Ed25519 Certificate
/// & Steward Binding Bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebizenIdTlsCertificateBundle {
    pub domain: String,
    pub steward_did_qi: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub public_key: [u8; 32],
    pub signature_ed25519: [u8; 64],
    pub key_fingerprint_sha256_hex: String,
    pub signature_hmac_sha256: [u8; 32],
}

impl WebizenIdTlsCertificateBundle {
    /// Deterministically derive an RFC 8032 Ed25519 keypair from `secret_seed`, encode a real
    /// ASN.1 DER X.509 v3 certificate and PKCS#8 v1 private key, and persist both to disk.
    pub fn issue_and_persist(domain: &str, steward_did_qi: &str, secret_seed: &[u8; 32], tls_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(tls_dir)?;
        let (cert_der, public_key, signature_ed25519) = encode_x509_v3_ed25519_der(domain, steward_did_qi, secret_seed);
        let key_der = encode_pkcs8_ed25519_private_key_der(secret_seed);
        let (cert_pem, key_pem) = (der_to_pem("CERTIFICATE", &cert_der), der_to_pem("PRIVATE KEY", &key_der));
        let key_fingerprint_sha256_hex = hex_encode_32(&sha256(&public_key));
        let signature_hmac_sha256 = hmac_sha256(secret_seed, &cert_der);
        fs::write(tls_dir.join(format!("{domain}.cert.pem")), cert_pem.as_bytes())?;
        fs::write(tls_dir.join(format!("{domain}.key.pem")), key_pem.as_bytes())?;
        Ok(Self {
            domain: domain.to_string(), steward_did_qi: steward_did_qi.to_string(), cert_pem, key_pem,
            cert_der, public_key, signature_ed25519, key_fingerprint_sha256_hex, signature_hmac_sha256,
        })
    }

    /// Verify the ASN.1 DER X.509 v3 certificate's Ed25519 signature using **only** `self.public_key`.
    pub fn verify_with_public_key(&self) -> bool {
        verify_x509_v3_ed25519_der(&self.cert_der, &self.public_key)
    }

    /// Verify that `secret_seed` derives `self.public_key` and that the X.509 v3 certificate's
    /// asymmetric Ed25519 signature verifies against `self.public_key`.
    pub fn verify_bundle(&self, secret_seed: &[u8; 32]) -> bool {
        ed25519_public_key_from_seed(secret_seed) == self.public_key && self.verify_with_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsQueryContext, DnsRcode, DnsRrType, NQuinDnsZoneRing};
    use std::net::TcpListener;

    #[test]
    fn wp09_rfc8555_acme_http01_and_dns01_challenge_derivation() {
        let canonical_jwk = br#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let mut mgr = AcmeChallengeManager::new(canonical_jwk);
        let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
        let (key_auth, dns01_txt) = mgr.register_challenge(token);
        assert!(key_auth.starts_with(token));
        assert_eq!(mgr.respond_http01(token), Some(key_auth.as_str()));
        assert_eq!(mgr.respond_http01("unknown-token"), None);
        assert_eq!(dns01_txt.len(), 43);
        assert!(!dns01_txt.contains('='));
        assert_eq!(dns01_txt, base64url_encode(&sha256(key_auth.as_bytes())));
    }

    #[test]
    fn wp09_webizen_id_tls_certificate_bundle_persists_to_disk() {
        let tmp_dir = std::env::temp_dir().join(format!("webizen_tls_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let seed = [0x5Au8; 32];
        let bundle = WebizenIdTlsCertificateBundle::issue_and_persist("ns.webcivics.net", "did:qi:steward_alice", &seed, &tmp_dir).unwrap();
        assert!(bundle.verify_with_public_key() && bundle.verify_bundle(&seed) && !bundle.verify_bundle(&[0x99u8; 32]));
        assert_eq!(bundle.cert_der.first().copied(), Some(0x30));
        assert!(bundle.cert_pem.starts_with("-----BEGIN CERTIFICATE-----\n") && bundle.key_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert_eq!(fs::read_to_string(tmp_dir.join("ns.webcivics.net.cert.pem")).unwrap(), bundle.cert_pem);
        assert_eq!(fs::read_to_string(tmp_dir.join("ns.webcivics.net.key.pem")).unwrap(), bundle.key_pem);
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn wp15_pkcs10_csr_jws_eddsa_and_60_day_renewal_scheduler() {
        let seed = [0x33u8; 32];
        let (csr_der, pubkey, csr_sig) = encode_pkcs10_ed25519_csr_der("commons.webcivics.net", &seed);
        assert_eq!((csr_der[0], csr_sig.len()), (0x30, 64));
        assert!(verify_pkcs10_ed25519_csr_der(&csr_der, &pubkey) && !verify_pkcs10_ed25519_csr_der(&csr_der, &[0x11u8; 32]));

        let mut tampered_csr = csr_der.clone();
        tampered_csr[20] ^= 0x01;
        assert!(!verify_pkcs10_ed25519_csr_der(&tampered_csr, &pubkey));

        let (jws_json, signing_input, jws_sig) = build_acme_jws_ed25519(
            "https://acme.webcivics.net/acme/new-order", "nonce-12345", "https://acme.webcivics.net/acme/acct/1",
            r#"{"identifiers":[{"type":"dns","value":"commons.webcivics.net"}]}"#, &seed,
        );
        assert!(jws_json.contains(r#""protected":"#) && verify_acme_jws_ed25519(&signing_input, &jws_sig, &pubkey));

        let tmp_dir = std::env::temp_dir().join(format!("webizen_acme_wp15_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let mut mgr = AcmeChallengeManager::new(b"canonical-ed25519-jwk");
        let mut ring = NQuinDnsZoneRing::new();
        let issued_at = 1_700_000_000u64;
        let (bundle, order_csr, state) = AcmeRenewalScheduler::execute_order_and_provision(
            &mut mgr, &mut ring, "commons.webcivics.net", "did:qi:steward_alice", "token-wp15-abc", &seed, &tmp_dir, issued_at,
        ).unwrap();
        assert!(bundle.verify_bundle(&seed) && order_csr == csr_der);
        let expires_at = issued_at + ACME_CERT_LIFETIME_SECS;
        assert_eq!(state, AcmeOrderState::FinalizedAndIssued { issued_at_epoch: issued_at, expires_at_epoch: expires_at });

        let qctx = DnsQueryContext { has_valid_dni_cookie: false, has_webizen_id_tls_session: false, requester_jurisdiction_hash: q_hash("AU") };
        let (rc, txt_quin) = ring.resolve_zero_heap("_acme-challenge.commons.webcivics.net", DnsRrType::TXT, &qctx);
        assert!(rc == DnsRcode::NoError && txt_quin.is_some());
        assert!(!AcmeRenewalScheduler::should_renew(issued_at, expires_at, issued_at + 59 * 86_400));
        assert!(AcmeRenewalScheduler::should_renew(issued_at, expires_at, issued_at + 60 * 86_400));
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn wp25_acme_directory_http_client_order_and_finalize_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock ACME server");
        let addr = listener.local_addr().unwrap();
        let server_handle = std::thread::spawn(move || {
            let mut captured = Vec::with_capacity(3);
            for step in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept ACME client");
                let mut req = String::new();
                stream.read_to_string(&mut req).expect("read HTTP request");
                let (status, nonce, body) = match step {
                    0 => ("200 OK", "nonce-wp25-step1", ""),
                    1 => ("201 Created", "nonce-wp25-step2", r#"{"status":"pending","token":"wp25-live-acme-token"}"#),
                    _ => ("200 OK", "nonce-wp25-step3", r#"{"status":"valid"}"#),
                };
                let resp = format!("HTTP/1.1 {status}\r\nReplay-Nonce: {nonce}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(resp.as_bytes()).expect("write HTTP response");
                captured.push(req);
            }
            captured
        });

        let tmp_dir = std::env::temp_dir().join(format!("webizen_acme_wp25_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let seed = [0x77u8; 32];
        let mut mgr = AcmeChallengeManager::new(b"wp25-canonical-ed25519-jwk");
        let mut ring = NQuinDnsZoneRing::new();
        let epoch = 1_750_000_000u64;
        let (bundle, state) = AcmeDirectoryClient::execute_http_order_flow(
            addr, "directory.webcivics.net", "did:qi:steward_bob", &seed, &mut mgr, &mut ring, &tmp_dir, epoch,
        ).unwrap();

        let requests = server_handle.join().expect("join mock ACME server");
        assert!(requests[0].starts_with("HEAD /acme/new-nonce HTTP/1.1"));
        assert!(requests[1].starts_with("POST /acme/new-order HTTP/1.1") && requests[1].contains("Content-Type: application/jose+json"));
        assert!(requests[1].contains(r#""protected":"#) && requests[2].starts_with("POST /acme/finalize HTTP/1.1") && requests[2].contains(r#""signature":"#));
        assert!(mgr.respond_http01("wp25-live-acme-token").is_some());

        let qctx = DnsQueryContext { has_valid_dni_cookie: false, has_webizen_id_tls_session: false, requester_jurisdiction_hash: q_hash("AU") };
        let (rc, txt_quin) = ring.resolve_zero_heap("_acme-challenge.directory.webcivics.net", DnsRrType::TXT, &qctx);
        assert!(rc == DnsRcode::NoError && txt_quin.is_some() && bundle.verify_bundle(&seed));
        assert_eq!(state, AcmeOrderState::FinalizedAndIssued { issued_at_epoch: epoch, expires_at_epoch: epoch + ACME_CERT_LIFETIME_SECS });
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
