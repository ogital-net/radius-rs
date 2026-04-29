/// Safe wrapper functions around aws-lc-sys crypto primitives.
///
/// This module is only available when the `aws-lc` feature is enabled.
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

/// Return a `Box<[u8]>` of `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Box<[u8]> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf);
    buf.into_boxed_slice()
}

/// Compare two byte slices in constant time, returning `true` if they are equal.
///
/// Uses `CRYPTO_memcmp` from AWS-LC, which is guaranteed not to be optimised
/// away by the compiler.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    // SAFETY: a and b are valid slices of the same (non-zero) length.
    let ret = unsafe { aws_lc_sys::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    ret == 0
}

/// Compute the MD4 digest of `data`, returning a 16-byte result.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut digest = [0u8; 16];
    // SAFETY: `data` is a valid slice; `digest` has exactly 16 bytes as required by MD4.
    unsafe {
        aws_lc_sys::MD4(data.as_ptr(), data.len(), digest.as_mut_ptr());
    }
    digest
}

/// Compute the SHA-1 digest of `data`, returning a 20-byte result.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut digest = [0u8; 20];
    // SAFETY: `data` is a valid slice; `digest` has exactly 20 bytes as required by SHA1.
    unsafe {
        aws_lc_sys::SHA1(data.as_ptr(), data.len(), digest.as_mut_ptr());
    }
    digest
}

/// Encrypt a single DES block (8 bytes) using an 8-byte key in ECB mode.
///
/// The key must be 8 bytes (64-bit DES key with parity bits included).
pub fn des_ecb_encrypt(key8: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    use aws_lc_sys::{DES_cblock_st, DES_key_schedule, DES_ENCRYPT};
    use std::mem::MaybeUninit;

    let key_cb = DES_cblock_st { bytes: *key8 };
    let in_cb = DES_cblock_st { bytes: *block };
    let mut out_cb = DES_cblock_st { bytes: [0u8; 8] };
    let mut ks = MaybeUninit::<DES_key_schedule>::uninit();

    // SAFETY: key_cb and ks are valid pointers; DES_set_key_unchecked initialises ks.
    // DES_ecb_encrypt reads in_cb and ks (initialised above) and writes out_cb.
    unsafe {
        aws_lc_sys::DES_set_key_unchecked(std::ptr::addr_of!(key_cb), ks.as_mut_ptr());
        aws_lc_sys::DES_ecb_encrypt(
            std::ptr::addr_of!(in_cb),
            std::ptr::addr_of_mut!(out_cb),
            ks.as_ptr(),
            DES_ENCRYPT,
        );
    }
    out_cb.bytes
}
