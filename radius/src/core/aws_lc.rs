/// Safe wrapper functions around aws-lc-sys crypto primitives.
///
/// This module is only available when the `aws-lc` feature is enabled.
/// Compute the MD5 hash of `data`, returning a 16-byte digest.
///
/// # Safety
/// The underlying `aws_lc_sys::MD5` function is infallible for any input
/// length, so this wrapper is unconditionally safe to call.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut digest = [0u8; 16];
    // SAFETY: `data` is a valid slice, `digest` has exactly 16 bytes as
    // required by MD5_DIGEST_LENGTH in AWS-LC.
    unsafe {
        aws_lc_sys::MD5(data.as_ptr(), data.len(), digest.as_mut_ptr());
    }
    digest
}

/// Fill `buf` with cryptographically secure random bytes using AWS-LC's
/// `RAND_bytes`.
///
/// # Panics
/// Panics if the underlying RNG fails (which should not happen in practice
/// with a correctly initialised AWS-LC build).
pub fn rand_bytes(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: `buf` is a valid mutable slice. `RAND_bytes` returns 1 on
    // success and 0 on failure. We assert success to surface any platform
    // issues immediately rather than silently producing zeroed output.
    let ret = unsafe { aws_lc_sys::RAND_bytes(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(ret, 1, "aws-lc RAND_bytes failed");
}

/// Return a `Vec<u8>` of `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf);
    buf
}
