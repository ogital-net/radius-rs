/// Unified crypto wrappers that delegate to whichever feature is active.
///
/// Exactly one of `aws-lc`, `openssl`, or `md5` must be enabled.

// ── MD5 ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "aws-lc")]
pub fn md5(data: &[u8]) -> [u8; 16] {
    crate::core::aws_lc::md5(data)
}

#[cfg(feature = "openssl")]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::md5(), data)
        .expect("openssl MD5 hash failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

#[cfg(feature = "md5")]
pub fn md5(data: &[u8]) -> [u8; 16] {
    *::md5::compute(data)
}

// ── Random bytes ─────────────────────────────────────────────────────────────

#[cfg(feature = "aws-lc")]
pub fn random_bytes(n: usize) -> Vec<u8> {
    crate::core::aws_lc::random_bytes(n)
}

#[cfg(feature = "aws-lc")]
pub fn random_u8() -> u8 {
    crate::core::aws_lc::random_u8()
}

#[cfg(any(feature = "md5", feature = "openssl"))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random()).collect()
}

#[cfg(any(feature = "md5", feature = "openssl"))]
pub fn random_u8() -> u8 {
    use rand::RngExt;
    rand::rng().random()
}
