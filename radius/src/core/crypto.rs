//! Unified cryptographic primitives shared by the RADIUS protocol implementation.
//!
//! MD5 and HMAC-MD5 delegate unconditionally to the in-tree [`fast_md5`](crate::core::fast_md5)
//! implementation.  All other operations delegate to whichever backend feature is active
//! (`aws-lc`, `openssl`, or `rust-crypto`).  Exactly one backend feature must be enabled.
//!
//! # Public API
//!
//! | Function | Purpose |
//! |---|---|
//! | [`md5`] | Raw MD5 digest (used for RADIUS authenticator and password obfuscation) |
//! | [`md5_of`] | Scatter-gather MD5 — digest of concatenated slices, zero-copy |
//! | [`hmac_md5`] | HMAC-MD5 keyed MAC (used for `Message-Authenticator`, RFC 3579) |
//! | [`fill_random`] | Fill a byte slice with cryptographically secure random bytes |
//! | [`random_bytes`] | Allocate and return `n` cryptographically secure random bytes |
//! | [`verify_chap_password`] | Verify a CHAP challenge-response (RFC 1994 / RFC 2865) |
//! | [`verify_mschap_nt_response`] | Verify an MS-CHAP NT-Response (RFC 2433) |
//! | [`verify_mschapv2_nt_response`] | Verify an MS-CHAPv2 NT-Response (RFC 2759) |
//! | [`generate_mschapv2_authenticator_response`] | Generate the MS-CHAPv2 `AuthenticatorResponse` (RFC 2759 §8.7) |

/// Compute the MD5 digest of `data`, returning a 16-byte result.
///
/// Used internally for RADIUS authenticator calculation and
/// `User-Password` / `Tunnel-Password` obfuscation.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    crate::core::fast_md5::md5(data)
}

// ── Multi-part MD5 (scatter-gather, zero heap allocation) ────────────────────

/// Compute the MD5 digest of the concatenation of `parts` without allocating
/// an intermediate buffer.  Equivalent to `md5(&parts.concat())` but faster.
#[must_use]
#[inline]
pub fn md5_of(parts: &[&[u8]]) -> [u8; 16] {
    crate::core::fast_md5::md5_of(parts)
}

// ── Random bytes ─────────────────────────────────────────────────────────────

/// Allocate a `Box<[u8]>` of length `n` filled with cryptographically secure random bytes.
#[cfg(feature = "aws-lc")]
#[must_use]
pub fn random_bytes(n: usize) -> Box<[u8]> {
    crate::core::aws_lc::random_bytes(n)
}

/// Fill `buf` with cryptographically secure random bytes in-place.
#[cfg(feature = "aws-lc")]
pub fn fill_random(buf: &mut [u8]) {
    crate::core::aws_lc::rand_bytes(buf);
}

/// Allocate a `Box<[u8]>` of length `n` filled with cryptographically secure random bytes.
#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
#[must_use]
pub fn random_bytes(n: usize) -> Box<[u8]> {
    crate::core::openssl::random_bytes(n)
}

/// Fill `buf` with cryptographically secure random bytes in-place.
#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
pub fn fill_random(buf: &mut [u8]) {
    crate::core::openssl::fill_random(buf);
}

/// Allocate a `Box<[u8]>` of length `n` filled with cryptographically secure random bytes.
#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
#[must_use]
pub fn random_bytes(n: usize) -> Box<[u8]> {
    let mut buf = vec![0u8; n];
    fill_random(&mut buf);
    buf.into_boxed_slice()
}

/// Fill `buf` with cryptographically secure random bytes in-place.
#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngExt;
    rand::rng().fill(buf);
}

// ── HMAC-MD5 ─────────────────────────────────────────────────────────────────

/// Compute HMAC-MD5 over `data` keyed with `key`, returning a 16-byte MAC.
///
/// Required for the `Message-Authenticator` attribute (RFC 3579) used with EAP.
#[must_use]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    crate::core::fast_md5::hmac_md5(key, data)
}

// ── Backend-specific MD4, SHA-1, and DES-ECB primitives ──────────────────────
//
// These are private helpers used by the CHAP / MS-CHAP authentication
// functions below.  Each backend provides identical signatures; exactly one
// set of definitions is compiled at a time.

// ── aws-lc backend ───────────────────────────────────────────────────────────

#[cfg(feature = "aws-lc")]
fn md4(data: &[u8]) -> [u8; 16] {
    crate::core::aws_lc::md4(data)
}

#[cfg(feature = "aws-lc")]
fn sha1(data: &[u8]) -> [u8; 20] {
    crate::core::aws_lc::sha1(data)
}

#[cfg(feature = "aws-lc")]
#[allow(clippy::trivially_copy_pass_by_ref)]
fn des_ecb_encrypt(key8: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    crate::core::aws_lc::des_ecb_encrypt(key8, block)
}

// ── openssl backend ──────────────────────────────────────────────────────────

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
fn md4(data: &[u8]) -> [u8; 16] {
    crate::core::openssl::md4(data)
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
fn sha1(data: &[u8]) -> [u8; 20] {
    crate::core::openssl::sha1(data)
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
#[allow(clippy::trivially_copy_pass_by_ref)]
fn des_ecb_encrypt(key8: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    crate::core::openssl::des_ecb_encrypt(key8, block)
}

// ── pure-Rust (RustCrypto crates) backend ───────────────────────────────────

/// MD4 (RFC 1320) – used for NT password hashing in MS-CHAP.
#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
fn md4(data: &[u8]) -> [u8; 16] {
    use md4::{Digest, Md4};
    Md4::digest(data).into()
}

/// SHA-1 (FIPS 180-4) – used for MS-CHAPv2 challenge hashing and authenticator response.
#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).into()
}

/// DES ECB encrypt via the `des` crate (pure-Rust backend only).
#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
#[allow(clippy::trivially_copy_pass_by_ref)]
fn des_ecb_encrypt(key8: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    use des::cipher::{Block, BlockCipherEncrypt, KeyInit};
    let cipher = des::Des::new_from_slice(key8).expect("DES key is always 8 bytes; qed");
    let mut blk = Block::<des::Des>::default();
    blk.copy_from_slice(block);
    cipher.encrypt_block(&mut blk);
    let mut out = [0u8; 8];
    out.copy_from_slice(&blk);
    out
}

// ── Shared MS-CHAP helpers ────────────────────────────────────────────────────

/// Expand a 7-byte (56-bit) DES key to the 8-byte form expected by DES
/// (RFC 2433 §A.1 `MakeKey`).
fn des_expand_key(key7: [u8; 7]) -> [u8; 8] {
    [
        key7[0] >> 1,
        ((key7[0] & 0x01) << 6) | (key7[1] >> 2),
        ((key7[1] & 0x03) << 5) | (key7[2] >> 3),
        ((key7[2] & 0x07) << 4) | (key7[3] >> 4),
        ((key7[3] & 0x0F) << 3) | (key7[4] >> 5),
        ((key7[4] & 0x1F) << 2) | (key7[5] >> 6),
        ((key7[5] & 0x3F) << 1) | (key7[6] >> 7),
        key7[6] & 0x7F,
    ]
    .map(|b| b << 1)
}

/// NT password hash: MD4 of the UTF-16LE encoding of `password`.
fn nt_password_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    md4(&utf16)
}

/// Three-key DES challenge response (RFC 2433 §A.3 `ChallengeResponse`).
///
/// Pads `password_hash` to 21 bytes, splits into three 7-byte keys,
/// and returns the concatenation of three DES-ECB encryptions of `challenge`.
fn challenge_response(challenge: [u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(password_hash);

    let k1 = des_expand_key(padded[0..7].try_into().unwrap());
    let k2 = des_expand_key(padded[7..14].try_into().unwrap());
    let k3 = des_expand_key(padded[14..21].try_into().unwrap());

    let mut response = [0u8; 24];
    response[0..8].copy_from_slice(&des_ecb_encrypt(&k1, &challenge));
    response[8..16].copy_from_slice(&des_ecb_encrypt(&k2, &challenge));
    response[16..24].copy_from_slice(&des_ecb_encrypt(&k3, &challenge));
    response
}

/// Derive the 8-byte MS-CHAPv2 challenge hash (RFC 2759 §8.2).
fn mschapv2_challenge_hash(
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &[u8],
) -> [u8; 8] {
    let mut data = Vec::with_capacity(32 + username.len());
    data.extend_from_slice(peer_challenge);
    data.extend_from_slice(authenticator_challenge);
    data.extend_from_slice(username);
    let hash = sha1(&data);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

/// Constant-time byte-slice equality check.
#[cfg(feature = "aws-lc")]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    crate::core::aws_lc::ct_eq(a, b)
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    crate::core::openssl::ct_eq(a, b)
}

#[cfg(all(
    feature = "rust-crypto",
    not(feature = "aws-lc"),
    not(feature = "openssl")
))]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Public authentication helpers ─────────────────────────────────────────────

/// Verify a CHAP challenge-response (RFC 1994 / RFC 2865 §5.3).
///
/// `chap_id` is the CHAP Identifier byte; `plaintext_password` is the
/// user's cleartext password; `challenge` is the CHAP Challenge value
/// (typically 16 bytes, but any length is accepted); `chap_response` must
/// be the 16-byte MD5 response extracted from the CHAP-Password AVP.
///
/// Returns `true` if the response is correct.
#[must_use]
pub fn verify_chap_password(
    chap_id: u8,
    plaintext_password: &[u8],
    challenge: &[u8],
    chap_response: &[u8; 16],
) -> bool {
    let mut data = Vec::with_capacity(1 + plaintext_password.len() + challenge.len());
    data.push(chap_id);
    data.extend_from_slice(plaintext_password);
    data.extend_from_slice(challenge);
    let expected = md5(&data);
    ct_eq(&expected, chap_response)
}

/// Verify an MS-CHAP NT-Response (RFC 2433).
///
/// `challenge` is the 8-byte authenticator challenge; `plaintext_password`
/// is the user's cleartext password (Unicode-aware); `nt_response` is the
/// 24-byte NT-Response field from the MS-CHAP-Response AVP.
///
/// Returns `true` if the response is correct.
#[must_use]
pub fn verify_mschap_nt_response(
    challenge: &[u8; 8],
    plaintext_password: &str,
    nt_response: &[u8; 24],
) -> bool {
    let hash = nt_password_hash(plaintext_password);
    let expected = challenge_response(*challenge, &hash);
    ct_eq(&expected, nt_response)
}

/// Verify an MS-CHAPv2 NT-Response (RFC 2759 §8.4).
///
/// `authenticator_challenge` is the 16-byte server challenge;
/// `peer_challenge` is the 16-byte client challenge (from MS-CHAP2-Response);
/// `username` is the NT-domain user name (just the bare user name, not
/// `DOMAIN\user`); `plaintext_password` is the cleartext password;
/// `nt_response` is the 24-byte NT-Response field.
///
/// Returns `true` if the response is correct.
#[must_use]
pub fn verify_mschapv2_nt_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &[u8],
    plaintext_password: &str,
    nt_response: &[u8; 24],
) -> bool {
    let ch = mschapv2_challenge_hash(peer_challenge, authenticator_challenge, username);
    let hash = nt_password_hash(plaintext_password);
    let expected = challenge_response(ch, &hash);
    ct_eq(&expected, nt_response)
}

/// Generate the MS-CHAPv2 `AuthenticatorResponse` string (RFC 2759 §8.7).
///
/// Returns the 42-byte ASCII string `S=<40 uppercase hex digits>` that the
/// RADIUS server sends back to the peer inside the MS-CHAP2-Success message.
///
/// All parameters are the same as [`verify_mschapv2_nt_response`].
#[must_use]
pub fn generate_mschapv2_authenticator_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &[u8],
    plaintext_password: &str,
    nt_response: &[u8; 24],
) -> [u8; 42] {
    // Magic constants from RFC 2759 §8.7
    const MAGIC1: &[u8] = b"Magic server to client signing constant";
    const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
    // Hex digits for formatting the authenticator response.
    const HEX: &[u8] = b"0123456789ABCDEF";

    let pw_hash = nt_password_hash(plaintext_password);
    let pw_hash_hash = md4(&pw_hash);

    // Digest = SHA1(NtPasswordHashHash || NTResponse || Magic1)
    let mut d1 = Vec::with_capacity(16 + 24 + MAGIC1.len());
    d1.extend_from_slice(&pw_hash_hash);
    d1.extend_from_slice(nt_response);
    d1.extend_from_slice(MAGIC1);
    let digest = sha1(&d1);

    // ChallengeHash
    let ch = mschapv2_challenge_hash(peer_challenge, authenticator_challenge, username);

    // Response = SHA1(Digest || ChallengeHash || Magic2)
    let mut d2 = Vec::with_capacity(20 + 8 + MAGIC2.len());
    d2.extend_from_slice(&digest);
    d2.extend_from_slice(&ch);
    d2.extend_from_slice(MAGIC2);
    let response = sha1(&d2);

    // Format as "S=<40 uppercase hex chars>"
    let mut out = [0u8; 42];
    out[0] = b'S';
    out[1] = b'=';
    for (i, &byte) in response.iter().enumerate() {
        out[2 + i * 2] = HEX[(byte >> 4) as usize];
        out[2 + i * 2 + 1] = HEX[(byte & 0x0F) as usize];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // Test vectors from RFC 2759 Appendix C.
    fn auth_challenge() -> [u8; 16] {
        from_hex("5B5D7C7D7B3F2F3E 3C2C602132262628")
            .try_into()
            .unwrap()
    }
    fn peer_challenge() -> [u8; 16] {
        from_hex("21402324255E262A 28295F2B3A337C7E")
            .try_into()
            .unwrap()
    }
    fn nt_response() -> [u8; 24] {
        from_hex("82309ECD8D708B5E A08FAA3981CD8354 4233114A3D85D6DF")
            .try_into()
            .unwrap()
    }
    // The 8-byte challenge hash produced from the above by ChallengeHash().
    fn challenge_hash() -> [u8; 8] {
        from_hex("D02E4386BCE91226").try_into().unwrap()
    }

    const PASSWORD: &str = "clientPass";
    const USERNAME: &[u8] = b"User";

    #[test]
    fn test_nt_password_hash() {
        // MD4(UTF-16LE("clientPass")).
        // Note: the intermediate PasswordHash printed in RFC 2759 Appendix C
        // is incorrect (known errata); this value is consistent with the
        // NT-Response and AuthenticatorResponse vectors in that same appendix.
        let expected: [u8; 16] = from_hex("44EBBA8D5312B8D611474411F56989AE")
            .try_into()
            .unwrap();
        assert_eq!(nt_password_hash(PASSWORD), expected);
    }

    #[test]
    fn test_mschap_nt_response() {
        // Uses the ChallengeHash as the MS-CHAPv1 challenge.
        assert!(verify_mschap_nt_response(
            &challenge_hash(),
            PASSWORD,
            &nt_response()
        ));
        assert!(!verify_mschap_nt_response(
            &challenge_hash(),
            "wrongPassword",
            &nt_response()
        ));
    }

    #[test]
    fn test_mschapv2_nt_response() {
        assert!(verify_mschapv2_nt_response(
            &auth_challenge(),
            &peer_challenge(),
            USERNAME,
            PASSWORD,
            &nt_response()
        ));
        assert!(!verify_mschapv2_nt_response(
            &auth_challenge(),
            &peer_challenge(),
            USERNAME,
            "wrongPassword",
            &nt_response()
        ));
    }

    #[test]
    fn test_mschapv2_authenticator_response() {
        let response = generate_mschapv2_authenticator_response(
            &auth_challenge(),
            &peer_challenge(),
            USERNAME,
            PASSWORD,
            &nt_response(),
        );
        assert_eq!(&response, b"S=407A5589115FD0D6209F510FE9C04566932CDA56");
    }

    #[test]
    fn test_verify_chap_password() {
        let challenge = b"radius01";
        let password = b"secret";
        let chap_id = 1u8;
        let mut data = vec![chap_id];
        data.extend_from_slice(password);
        data.extend_from_slice(challenge);
        let expected: [u8; 16] = md5(&data);
        assert!(verify_chap_password(
            chap_id, password, challenge, &expected
        ));
        assert!(!verify_chap_password(
            chap_id, b"wrong", challenge, &expected
        ));
    }
}
