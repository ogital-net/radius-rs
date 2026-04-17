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
pub fn fill_random(buf: &mut [u8]) {
    crate::core::aws_lc::rand_bytes(buf);
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    fill_random(&mut buf);
    buf
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
pub fn fill_random(buf: &mut [u8]) {
    openssl_crate::rand::rand_bytes(buf).expect("openssl RAND_bytes failed");
}

#[cfg(all(feature = "md5", not(feature = "aws-lc"), not(feature = "openssl")))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    fill_random(&mut buf);
    buf
}

#[cfg(all(feature = "md5", not(feature = "aws-lc"), not(feature = "openssl")))]
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngExt;
    rand::rng().fill(buf);
}
