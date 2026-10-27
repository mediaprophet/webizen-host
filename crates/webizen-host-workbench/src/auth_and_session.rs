//! WP-10 (D10.1 & D10.2): Cryptographic Steward Session & CSRF Token Manager (`StewardSessionGuard`)
//! and Zero-Heap (`HotZeroHeap`) 256-Slot Per-IP Token-Bucket Rate Limiter (`IpRateLimiterRing`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use webizen_host_core::{
    hmac_sha256, pbkdf2_hmac_sha256, q_hash, sha256, validate_human_centric_nomenclature,
};

/// Authentication and CSRF enforcement policy for the Poet Host Admin Workbench.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthEnforcementMode {
    #[default]
    PermissiveTest,
    StrictRetail,
}

/// Return the current real-time UNIX epoch timestamp in seconds (falling back to `1_700_000_000`
/// only if the system clock is set prior to 1970).
#[inline]
pub fn current_unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000)
}

#[inline]
fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX_LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX_LUT[(b >> 4) as usize] as char);
        out.push(HEX_LUT[(b & 0x0F) as usize] as char);
    }
    out
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Cryptographic Steward Session & CSRF Token Manager for the Poet Host Admin Workbench.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StewardSessionGuard {
    pub session_secret: [u8; 32],
    pub steward_did_qi: String,
}

impl StewardSessionGuard {
    /// Load `<data_dir>/tls/session_secret.key` (32 bytes) if present, or deterministically derive
    /// and persist a new 32-byte key from `sha256("webizen.session.v1|<steward_did_qi>|<data_dir>")`.
    pub fn load_or_create(data_dir: &Path, steward_did_qi: &str) -> std::io::Result<Self> {
        validate_human_centric_nomenclature(steward_did_qi)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

        let tls_dir = data_dir.join("tls");
        fs::create_dir_all(&tls_dir)?;
        let secret_path = tls_dir.join("session_secret.key");

        let derive_and_store = || -> std::io::Result<[u8; 32]> {
            let derived = sha256(
                format!("webizen.session.v1|{steward_did_qi}|{}", data_dir.display()).as_bytes(),
            );
            fs::write(&secret_path, &derived)?;
            Ok(derived)
        };

        let session_secret = if secret_path.exists() {
            let raw = fs::read(&secret_path)?;
            if raw.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw[..32]);
                key
            } else {
                derive_and_store()?
            }
        } else {
            derive_and_store()?
        };

        Ok(Self {
            session_secret,
            steward_did_qi: steward_did_qi.to_string(),
        })
    }

    /// Issue a signed `DNI_SESSION` cookie header value with `HttpOnly; SameSite=Strict`.
    pub fn issue_session_cookie(&self, expiry_epoch: u64) -> String {
        let payload = format!("{expiry_epoch}|{}", self.steward_did_qi);
        let mac_hex = hex_encode_32(&hmac_sha256(&self.session_secret, payload.as_bytes()));
        format!(
            "DNI_SESSION={expiry_epoch}|{}|{mac_hex}; Path=/; HttpOnly; SameSite=Strict",
            self.steward_did_qi
        )
    }

    /// Issue a domain-separated `HMAC-SHA256` CSRF token bound to `expiry_epoch` and `steward_did_qi`.
    pub fn issue_csrf_token(&self, expiry_epoch: u64) -> String {
        let payload = format!("csrf|{expiry_epoch}|{}", self.steward_did_qi);
        hex_encode_32(&hmac_sha256(&self.session_secret, payload.as_bytes()))
    }

    /// Verify a `Cookie` or `Set-Cookie` header containing `DNI_SESSION=<expiry>|<did>|<mac_hex>`
    /// against `current_epoch` and the steward's `HMAC-SHA256` key in constant time.
    pub fn verify_session_cookie(
        &self,
        cookie_header: &str,
        current_epoch: u64,
    ) -> Result<String, &'static str> {
        let raw_val = cookie_header
            .split(';')
            .map(str::trim)
            .find_map(|segment| segment.strip_prefix("DNI_SESSION="))
            .ok_or("Missing DNI_SESSION steward authentication cookie")?;

        let mut parts = raw_val.splitn(3, '|');
        let expiry_str = parts.next().ok_or("Malformed DNI_SESSION expiry field")?;
        let did_str = parts.next().ok_or("Malformed DNI_SESSION steward DID field")?;
        let mac_hex = parts.next().ok_or("Malformed DNI_SESSION MAC field")?;

        let expiry_epoch = expiry_str
            .parse::<u64>()
            .map_err(|_| "Invalid DNI_SESSION expiry epoch")?;
        if expiry_epoch < current_epoch {
            return Err("Expired DNI_SESSION steward authentication cookie");
        }
        if !constant_time_eq(did_str.as_bytes(), self.steward_did_qi.as_bytes()) {
            return Err("DNI_SESSION steward DID mismatch");
        }

        let expected_payload = format!("{expiry_epoch}|{}", self.steward_did_qi);
        let expected_mac_hex =
            hex_encode_32(&hmac_sha256(&self.session_secret, expected_payload.as_bytes()));
        if !constant_time_eq(mac_hex.as_bytes(), expected_mac_hex.as_bytes()) {
            return Err("Invalid DNI_SESSION HMAC-SHA256 signature");
        }

        Ok(did_str.to_string())
    }

    /// Verify a CSRF token in constant time against `issue_csrf_token(expiry_epoch)`.
    pub fn verify_csrf_token(&self, token: &str, expiry_epoch: u64) -> bool {
        let expected = self.issue_csrf_token(expiry_epoch);
        constant_time_eq(token.trim().as_bytes(), expected.as_bytes())
    }

    /// Derive a 16-byte deterministic salt from `sha256("webizen.salt.v1|<steward_did_qi>")[0..16]`,
    /// compute `pbkdf2_hmac_sha256(passphrase, salt, 4_096)`, and write `[salt (16B) || hash (32B)]`
    /// (48 bytes) to `<data_dir>/tls/steward_auth.verifier`.
    pub fn set_passphrase(&self, data_dir: &Path, passphrase: &str) -> std::io::Result<()> {
        let tls_dir = data_dir.join("tls");
        fs::create_dir_all(&tls_dir)?;
        let salt_digest = sha256(format!("webizen.salt.v1|{}", self.steward_did_qi).as_bytes());
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_digest[0..16]);
        let mut hash = [0u8; 32];
        pbkdf2_hmac_sha256(passphrase.as_bytes(), &salt, 4_096, &mut hash);
        let mut verifier = [0u8; 48];
        verifier[0..16].copy_from_slice(&salt);
        verifier[16..48].copy_from_slice(&hash);
        fs::write(tls_dir.join("steward_auth.verifier"), verifier)
    }

    /// Verify `candidate_passphrase` against `<data_dir>/tls/steward_auth.verifier` in constant time.
    /// If `<data_dir>/tls/steward_auth.verifier` does not exist, returns `true` (permissive bootstrap).
    pub fn verify_passphrase(&self, data_dir: &Path, candidate_passphrase: &str) -> bool {
        let verifier_path = data_dir.join("tls").join("steward_auth.verifier");
        if !verifier_path.exists() {
            return true;
        }
        let Ok(raw) = fs::read(&verifier_path) else {
            return false;
        };
        if raw.len() != 48 {
            return false;
        }
        let salt = &raw[0..16];
        let expected_hash = &raw[16..48];
        let mut candidate_hash = [0u8; 32];
        pbkdf2_hmac_sha256(
            candidate_passphrase.as_bytes(),
            salt,
            4_096,
            &mut candidate_hash,
        );
        constant_time_eq(&candidate_hash, expected_hash)
    }

    /// Verify an inbound request's CSRF token via either the `X-Webizen-Csrf-Token` header or a form field.
    pub fn verify_request_csrf(
        &self,
        header_csrf: &str,
        form_csrf: Option<&str>,
        expiry_epoch: u64,
    ) -> bool {
        self.verify_csrf_token(header_csrf, expiry_epoch)
            || form_csrf.is_some_and(|f| self.verify_csrf_token(f, expiry_epoch))
    }
}

#[inline]
fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) =
                    (decode_hex_nibble(bytes[i + 1]), decode_hex_nibble(bytes[i + 2]))
                {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an `application/x-www-form-urlencoded` body (`key1=val1&key2=val2`) into a `BTreeMap`.
pub fn parse_urlencoded_form(body: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in body.trim().split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode_str(k), percent_decode_str(v));
    }
    map
}

/// Fixed slot count for the `HotZeroHeap` per-IP token-bucket rate limiter ring.
pub const RATE_LIMIT_SLOTS: usize = 256;

/// Single per-IP token-bucket slot inside `IpRateLimiterRing`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpBucketSlot {
    pub ip_hash: u64,
    pub window_epoch: u64,
    pub request_count: u32,
    pub occupied: bool,
}

impl IpBucketSlot {
    pub const EMPTY: Self = Self {
        ip_hash: 0,
        window_epoch: 0,
        request_count: 0,
        occupied: false,
    };
}

/// Zero-Heap (`HotZeroHeap`) 64-byte cache-line-aligned 256-slot per-IP rate limiter ring.
#[repr(align(64))]
pub struct IpRateLimiterRing {
    slots: [IpBucketSlot; RATE_LIMIT_SLOTS],
    pub max_requests_per_window: u32,
}

impl IpRateLimiterRing {
    /// Construct a new 256-slot zero-heap rate limiter ring with `max_requests_per_window`.
    pub const fn new(max_requests_per_window: u32) -> Self {
        Self {
            slots: [IpBucketSlot::EMPTY; RATE_LIMIT_SLOTS],
            max_requests_per_window,
        }
    }

    /// Check and record an inbound request from `client_ip` at `current_window_epoch` with zero heap allocation.
    #[inline]
    pub fn check_and_record_zero_heap(
        &mut self,
        client_ip: &str,
        current_window_epoch: u64,
    ) -> Result<u32, &'static str> {
        let ip_hash = q_hash(client_ip);
        let start_idx = (ip_hash as usize) & (RATE_LIMIT_SLOTS - 1);
        let mut target_idx = start_idx;
        let mut fallback_idx: Option<usize> = None;

        let mut step = 0usize;
        while step < RATE_LIMIT_SLOTS {
            let idx = (start_idx + step) & (RATE_LIMIT_SLOTS - 1);
            let slot = &self.slots[idx];
            if slot.occupied && slot.ip_hash == ip_hash {
                target_idx = idx;
                fallback_idx = None;
                break;
            }
            if !slot.occupied || slot.window_epoch != current_window_epoch {
                if fallback_idx.is_none() {
                    fallback_idx = Some(idx);
                }
                if !slot.occupied {
                    break;
                }
            }
            step += 1;
        }

        if let Some(free_idx) = fallback_idx {
            target_idx = free_idx;
        }

        let slot = &mut self.slots[target_idx];
        if !slot.occupied || slot.ip_hash != ip_hash || slot.window_epoch != current_window_epoch {
            slot.ip_hash = ip_hash;
            slot.window_epoch = current_window_epoch;
            slot.request_count = 0;
            slot.occupied = true;
        }

        slot.request_count = slot.request_count.saturating_add(1);
        if slot.request_count > self.max_requests_per_window {
            return Err("HTTP 429 Too Many Requests: per-IP rate limit exceeded");
        }

        Ok(self.max_requests_per_window - slot.request_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steward_session_guard_cookie_csrf_and_urlencoded_form_verification() {
        let temp_dir =
            std::env::temp_dir().join(format!("webizen_wp10_session_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);

        let guard = StewardSessionGuard::load_or_create(&temp_dir, "did:qi:steward_alice").unwrap();
        let reloaded =
            StewardSessionGuard::load_or_create(&temp_dir, "did:qi:steward_alice").unwrap();
        assert_eq!(guard.session_secret, reloaded.session_secret);

        let cookie = guard.issue_session_cookie(2_000_000_000);
        assert!(cookie.contains("HttpOnly; SameSite=Strict"));
        assert_eq!(
            guard.verify_session_cookie(&cookie, 1_900_000_000).unwrap(),
            "did:qi:steward_alice"
        );
        assert!(guard.verify_session_cookie(&cookie, 2_000_000_001).is_err());

        let tampered_cookie = if cookie.contains("a; Path=/") {
            cookie.replacen("a; Path=/", "b; Path=/", 1)
        } else {
            cookie.replacen("; Path=/", "a; Path=/", 1)
        };
        assert!(guard.verify_session_cookie(&tampered_cookie, 1_900_000_000).is_err());

        let csrf = guard.issue_csrf_token(2_000_000_000);
        assert!(guard.verify_csrf_token(&csrf, 2_000_000_000));
        assert!(!guard.verify_csrf_token(&csrf, 2_000_000_001));
        assert!(!guard.verify_csrf_token("0000", 2_000_000_000));

        let parsed =
            parse_urlencoded_form("domain=alice.tld&note=Human+Centric+%26+Rights&csrf=abc%3D123");
        assert_eq!(parsed.get("domain").map(String::as_str), Some("alice.tld"));
        assert_eq!(parsed.get("note").map(String::as_str), Some("Human Centric & Rights"));
        assert_eq!(parsed.get("csrf").map(String::as_str), Some("abc=123"));
        assert!(current_unix_epoch_secs() >= 1_700_000_000);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn ip_rate_limiter_ring_enforces_window_cap_and_resets_cleanly_zero_heap() {
        let mut limiter = IpRateLimiterRing::new(3);
        assert_eq!(limiter.check_and_record_zero_heap("203.0.113.7", 100), Ok(2));
        assert_eq!(limiter.check_and_record_zero_heap("203.0.113.7", 100), Ok(1));
        assert_eq!(limiter.check_and_record_zero_heap("203.0.113.7", 100), Ok(0));
        assert!(limiter.check_and_record_zero_heap("203.0.113.7", 100).is_err());
        assert_eq!(limiter.check_and_record_zero_heap("198.51.100.42", 100), Ok(2));
        assert_eq!(limiter.check_and_record_zero_heap("203.0.113.7", 101), Ok(2));
    }

    #[test]
    fn steward_passphrase_verifier_and_dual_request_csrf_verification() {
        let temp_dir = std::env::temp_dir().join(format!(
            "webizen_wp23_passphrase_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        assert_eq!(AuthEnforcementMode::default(), AuthEnforcementMode::PermissiveTest);
        assert_ne!(AuthEnforcementMode::PermissiveTest, AuthEnforcementMode::StrictRetail);

        let guard = StewardSessionGuard::load_or_create(&temp_dir, "did:qi:steward_alice").unwrap();
        assert!(guard.verify_passphrase(&temp_dir, "any-bootstrap-passphrase"));

        guard
            .set_passphrase(&temp_dir, "HumanRightsSteward2026!")
            .unwrap();
        let verifier_bytes = fs::read(temp_dir.join("tls").join("steward_auth.verifier")).unwrap();
        assert_eq!(verifier_bytes.len(), 48);
        assert!(guard.verify_passphrase(&temp_dir, "HumanRightsSteward2026!"));
        assert!(!guard.verify_passphrase(&temp_dir, "WrongPassphrase2026!"));

        let csrf = guard.issue_csrf_token(2_000_000_000);
        assert!(guard.verify_request_csrf(&csrf, None, 2_000_000_000));
        assert!(guard.verify_request_csrf("", Some(&csrf), 2_000_000_000));
        assert!(!guard.verify_request_csrf("invalid", Some("invalid"), 2_000_000_000));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
