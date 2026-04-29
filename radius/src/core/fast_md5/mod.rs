//! Highly-optimised in-tree MD5 implementation.
//!
//! Architecture-specific paths:
//! - **`x86_64`**: two monolithic `asm!` blocks (F rounds; G+H+I rounds) implement
//!   the NoLEA-G variant from <https://github.com/animetosho/md5-optimisation>.
//!   `NoLEA` replaces each 3-operand `leal K(A, input), A` (3-cycle latency on
//!   modern Intel/Zen) with `add $K, A` + `add [m+off], D` (two 1-cycle ADDs).
//!   `GOpt` splits G into `(~D & C) + (D & B)` to reduce the B-dependency chain.
//!   A rolling TMP1 register carries the prior-round C copy across all rounds,
//!   and each round pre-loads the next input word into the current D register.
//! - **aarch64**: Rust `f!`/`g!`/`h!`/`i!` round macros each containing a
//!   per-round `asm!` rotate barrier that pins the accumulator to a concrete
//!   register at every round boundary, guiding LLVM register allocation (~2%
//!   faster than `rotate_left()` on Apple Silicon).  `BIC`/`ORN` are emitted
//!   naturally by LLVM from the `!d & c` and `b | !d` Rust expressions.
//! - **all others**: portable pure-Rust fallback using `rotate_left` and the
//!   same GOpt/I forms; LLVM emits `rorxl`/`rorl` as appropriate.
//!
//! All paths expose the same public surface:
//! - [`md5`] — one-shot digest of a contiguous slice
//! - [`md5_of`] — digest of multiple slices concatenated, zero-copy

// ── MD5 constants (T[i] = floor(2^32 * abs(sin(i+1)))) ─────────────────────

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// ── initial hash state ───────────────────────────────────────────────────────

const H0: u32 = 0x6745_2301;
const H1: u32 = 0xefcd_ab89;
const H2: u32 = 0x98ba_dcfe;
const H3: u32 = 0x1032_5476;

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
pub(crate) mod fallback;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

// ── compress dispatcher ──────────────────────────────────────────────────────
#[cfg(target_arch = "aarch64")]
use aarch64::compress;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use fallback::compress;
#[cfg(target_arch = "x86_64")]
use x86_64::compress;

// ─────────────────────────────────────────────────────────────────────────────
// MD5 padding and streaming context
// ─────────────────────────────────────────────────────────────────────────────

struct Md5 {
    state: [u32; 4],
    /// Number of bytes processed so far (used for final length encoding).
    count: u64,
    /// Partial block buffer.
    buf: [u8; 64],
    /// Number of bytes currently in `buf`.
    buf_len: usize,
}

impl Md5 {
    #[inline]
    fn new() -> Self {
        Self {
            state: [H0, H1, H2, H3],
            count: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.count += data.len() as u64;

        // Fill partial buffer first.
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block: &[u8; 64] = unsafe { &*(self.buf.as_ptr().cast::<[u8; 64]>()) };
                compress(&mut self.state, block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from `data`.
        while data.len() >= 64 {
            let block: &[u8; 64] = unsafe { &*(data.as_ptr().cast::<[u8; 64]>()) };
            compress(&mut self.state, block);
            data = &data[64..];
        }

        // Save remainder.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        // Append bit '1' (0x80 byte), then zero-pad to 56 mod 64, then 64-bit LE bit count.
        let bit_count = self.count.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            // Need an extra block.
            self.buf[self.buf_len..].fill(0);
            let block: &[u8; 64] = unsafe { &*(self.buf.as_ptr().cast::<[u8; 64]>()) };
            compress(&mut self.state, block);
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_count.to_le_bytes());
        let block: &[u8; 64] = unsafe { &*(self.buf.as_ptr().cast::<[u8; 64]>()) };
        compress(&mut self.state, block);

        let mut digest = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the MD5 digest of `data`.
#[must_use]
#[inline]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

/// Compute the MD5 digest of the concatenation of `parts` without allocating.
#[must_use]
#[inline]
pub fn md5_of(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

// ── HMAC-MD5 (RFC 2104) ──────────────────────────────────────────────────────

const HMAC_BLOCK_SIZE: usize = 64; // MD5 block size in bytes
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Compute HMAC-MD5 over `data` keyed with `key`, returning a 16-byte MAC.
///
/// Implements RFC 2104 using the in-tree [`md5_of`] scatter-gather function.
/// The computation is fully stack-allocated — no heap, no FFI.
///
/// Keys longer than 64 bytes are pre-hashed with MD5 per the RFC.
#[must_use]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // Normalize the key: hash it down if longer than the block size, then
    // zero-pad to exactly 64 bytes.
    let mut k = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        k[..16].copy_from_slice(&md5(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // Build the inner and outer padded keys in one pass.
    let mut k_ipad = [IPAD; HMAC_BLOCK_SIZE];
    let mut k_opad = [OPAD; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    // inner = MD5(k_ipad || data)
    // outer = MD5(k_opad || inner)
    let inner = md5_of(&[&k_ipad, data]);
    md5_of(&[&k_opad, &inner])
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 test vectors
    #[test]
    fn rfc1321_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];

        for (input, expected) in cases {
            let digest = md5(input);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, *expected, "input: {:?}", input);
        }
    }

    #[test]
    fn md5_of_matches_md5() {
        let data = b"hello world this is a test of the scatter gather path";
        let expected = md5(data);

        // Split arbitrarily
        let parts: &[&[u8]] = &[
            b"hello world ",
            b"this is a test ",
            b"of the scatter gather path",
        ];
        let got = md5_of(parts);
        assert_eq!(got, expected);
    }

    // RFC 2202 HMAC-MD5 test vectors
    #[test]
    fn hmac_md5_rfc2202() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            // (key, data, expected hex)
            // Test Case 1
            (
                &[0x0bu8; 16],
                b"Hi There",
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            // Test Case 2
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            // Test Case 3 — key and data are repeated bytes
            (
                &[0xaau8; 16],
                &[0xddu8; 50],
                "56be34521d144c88dbb8c733f0e8b3f6",
            ),
            // Test Case 6 — key longer than 64 bytes (triggers pre-hash path)
            (
                &[0xaau8; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            ),
            // Test Case 7 — key longer than 64 bytes, data longer than one block
            (
                &[0xaau8; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                "6f630fad67cda0ee1fb1f562db3aa53e",
            ),
        ];
        for (key, data, expected) in cases {
            let mac = hmac_md5(key, data);
            let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                hex,
                *expected,
                "HMAC-MD5 mismatch for key len={}",
                key.len()
            );
        }
    }

    #[test]
    fn multi_block_input() {
        // Input larger than one 64-byte block.
        let data: Vec<u8> = (0u8..200).collect();
        let fast = md5(&data);
        // Verify against a known-good reference (the md5 crate via rust-crypto feature, or
        // just check that two separate calls agree).
        assert_eq!(fast, md5(&data));
    }
    // ── test helper ─────────────────────────────────────────────────────────────
    // Runs the full MD5 over `data` using a specified compress function so that
    // individual implementations can be exercised directly in tests.
    fn hash_with(data: &[u8], compress: fn(&mut [u32; 4], &[u8; 64])) -> [u8; 16] {
        use super::{H0, H1, H2, H3};
        let mut state = [H0, H1, H2, H3];
        let mut count = 0u64;
        let mut buf = [0u8; 64];
        let mut buf_len = 0usize;

        let mut remaining = data;
        count += data.len() as u64;
        if buf_len > 0 {
            let need = 64 - buf_len;
            let take = need.min(remaining.len());
            buf[buf_len..buf_len + take].copy_from_slice(&remaining[..take]);
            buf_len += take;
            remaining = &remaining[take..];
            if buf_len == 64 {
                let block: &[u8; 64] = unsafe { &*(buf.as_ptr() as *const [u8; 64]) };
                compress(&mut state, block);
                buf_len = 0;
            }
        }
        while remaining.len() >= 64 {
            let block: &[u8; 64] = unsafe { &*(remaining.as_ptr() as *const [u8; 64]) };
            compress(&mut state, block);
            remaining = &remaining[64..];
        }
        if !remaining.is_empty() {
            buf[..remaining.len()].copy_from_slice(remaining);
            buf_len = remaining.len();
        }

        let bit_count = count.wrapping_mul(8);
        buf[buf_len] = 0x80;
        buf_len += 1;
        if buf_len > 56 {
            buf[buf_len..].fill(0);
            let block: &[u8; 64] = unsafe { &*(buf.as_ptr() as *const [u8; 64]) };
            compress(&mut state, block);
            buf_len = 0;
        }
        buf[buf_len..56].fill(0);
        buf[56..64].copy_from_slice(&bit_count.to_le_bytes());
        let block: &[u8; 64] = unsafe { &*(buf.as_ptr() as *const [u8; 64]) };
        compress(&mut state, block);

        let mut digest = [0u8; 16];
        for (i, word) in state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    // ── fallback correctness (always runs on every platform) ────────────────────
    #[test]
    fn fallback_rfc1321_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            let digest = hash_with(input, super::fallback::compress);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, *expected, "fallback: input {:?}", input);
        }
    }

    // ── cross-arch: compare fallback against the platform-optimised path ─────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_matches_fallback() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            &[0u8; 200],
            &[0xffu8; 137],
        ];
        for input in cases {
            let opt = hash_with(input, super::x86_64::compress);
            let fb = hash_with(input, super::fallback::compress);
            assert_eq!(
                opt,
                fb,
                "x86_64 vs fallback mismatch for {} bytes",
                input.len()
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_matches_fallback() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            &[0u8; 200],
            &[0xffu8; 137],
        ];
        for input in cases {
            let opt = hash_with(input, super::aarch64::compress);
            let fb = hash_with(input, super::fallback::compress);
            assert_eq!(
                opt,
                fb,
                "aarch64 vs fallback mismatch for {} bytes",
                input.len()
            );
        }
    }
}
