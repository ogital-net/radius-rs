/// Safe wrapper functions around openssl-sys crypto primitives.
///
/// This module is only available when the `openssl` feature is enabled.
/// All operations use the EVP API, which is the stable interface in OpenSSL 3.x.
use std::ffi::c_int;

// ── Internal EVP digest helper ───────────────────────────────────────────────

/// Run a one-shot EVP digest over `data`, writing the result into `out`.
///
/// # Safety
/// `md` must be a valid `*const EVP_MD` whose digest size equals `out.len()`.
unsafe fn evp_digest(md: *const openssl_sys::EVP_MD, data: &[u8], out: &mut [u8]) {
    let ctx = openssl_sys::EVP_MD_CTX_new();
    assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
    assert_eq!(
        openssl_sys::EVP_DigestInit_ex(ctx, md, std::ptr::null_mut()),
        1,
        "EVP_DigestInit_ex failed"
    );
    assert_eq!(
        openssl_sys::EVP_DigestUpdate(ctx, data.as_ptr().cast(), data.len()),
        1,
        "EVP_DigestUpdate failed"
    );
    let mut out_len: u32 = out.len() as u32;
    assert_eq!(
        openssl_sys::EVP_DigestFinal_ex(ctx, out.as_mut_ptr(), &mut out_len),
        1,
        "EVP_DigestFinal_ex failed"
    );
    openssl_sys::EVP_MD_CTX_free(ctx);
}

// ── Constant-time comparison ────────────────────────────────────────────────

/// Compare two byte slices in constant time, returning `true` if they are equal.
///
/// Uses `CRYPTO_memcmp` from OpenSSL, which is guaranteed not to be optimised
/// away by the compiler.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    // SAFETY: a and b are valid slices of the same (non-zero) length.
    let ret = unsafe { openssl_sys::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    ret == 0
}

// ── Hash functions ───────────────────────────────────────────────────────────

/// Compute the MD4 digest of `data`, returning a 16-byte result.
///
/// Requires the MD4 algorithm to be available (legacy provider in OpenSSL 3.x).
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut digest = [0u8; 16];
    // SAFETY: EVP_get_digestbyname returns a valid pointer or null; we assert non-null.
    unsafe {
        let md = openssl_sys::EVP_get_digestbyname(b"md4\0".as_ptr().cast());
        assert!(
            !md.is_null(),
            "MD4 digest unavailable (is the legacy provider loaded?)"
        );
        evp_digest(md, data, &mut digest);
    }
    digest
}

/// Compute the SHA-1 digest of `data`, returning a 20-byte result.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut digest = [0u8; 20];
    // SAFETY: EVP_sha1() returns a valid static EVP_MD pointer; digest is 20 bytes.
    unsafe { evp_digest(openssl_sys::EVP_sha1(), data, &mut digest) }
    digest
}

// ── Random bytes ─────────────────────────────────────────────────────────────

/// Fill `buf` with cryptographically secure random bytes using OpenSSL's `RAND_bytes`.
///
/// # Panics
/// Panics if the underlying RNG fails.
pub fn fill_random(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: `buf` is a valid mutable slice. `RAND_bytes` returns 1 on success.
    let ret = unsafe { openssl_sys::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int) };
    assert_eq!(ret, 1, "openssl RAND_bytes failed");
}

/// Return a `Box<[u8]>` of `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Box<[u8]> {
    let mut buf = vec![0u8; n];
    fill_random(&mut buf);
    buf.into_boxed_slice()
}

// ── DES-ECB ──────────────────────────────────────────────────────────────────

/// Encrypt a single DES block (8 bytes) using an 8-byte key in ECB mode.
///
/// The key must be 8 bytes (64-bit DES key with parity bits included).
pub fn des_ecb_encrypt(key8: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut out_len: c_int = 0;
    // SAFETY: all pointers are valid; EVP_des_ecb() returns a valid static cipher pointer.
    unsafe {
        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        assert!(!ctx.is_null(), "EVP_CIPHER_CTX_new failed");
        assert_eq!(
            openssl_sys::EVP_CipherInit_ex(
                ctx,
                openssl_sys::EVP_des_ecb(),
                std::ptr::null_mut(),
                key8.as_ptr(),
                std::ptr::null(),
                1, // encrypt
            ),
            1,
            "EVP_CipherInit_ex failed"
        );
        // Disable padding so a single 8-byte block is processed as-is.
        assert_eq!(
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx, 0),
            1,
            "EVP_CIPHER_CTX_set_padding failed"
        );
        assert_eq!(
            openssl_sys::EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut out_len, block.as_ptr(), 8),
            1,
            "EVP_CipherUpdate failed"
        );
        debug_assert_eq!(out_len, 8);
        openssl_sys::EVP_CIPHER_CTX_free(ctx);
    }
    out
}
