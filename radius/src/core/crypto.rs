/// Unified crypto wrappers that delegate to whichever feature is active.
///
/// Priority order when multiple features are present: aws-lc > openssl > md5.
/// Exactly one of `aws-lc`, `openssl`, or `md5` should be enabled.
#[cfg(feature = "aws-lc")]
pub fn md5(data: &[u8]) -> [u8; 16] {
    crate::core::aws_lc::md5(data)
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let digest = openssl_crate::hash::hash(openssl_crate::hash::MessageDigest::md5(), data)
        .expect("openssl MD5 hash failed");
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

#[cfg(all(feature = "md5", not(feature = "aws-lc"), not(feature = "openssl")))]
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

#[cfg(all(any(feature = "md5", feature = "openssl"), not(feature = "aws-lc")))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random()).collect()
}

#[cfg(all(any(feature = "md5", feature = "openssl"), not(feature = "aws-lc")))]
pub fn random_u8() -> u8 {
    use rand::RngExt;
    rand::rng().random()
}
