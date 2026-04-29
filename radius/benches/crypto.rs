use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use radius::core::crypto;

static HMAC_KEY: &[u8] = b"radius-shared-secret";

/// Thin wrapper around aws-lc-sys MD5 for benchmark comparison.
#[inline]
fn awslc_md5(data: &[u8]) -> [u8; 16] {
    let mut digest = [0u8; 16];
    // SAFETY: data is a valid slice; digest has exactly 16 bytes as MD5 requires.
    unsafe {
        aws_lc_sys::MD5(data.as_ptr(), data.len(), digest.as_mut_ptr());
    }
    digest
}

// ── md5 compress (raw block) — aarch64 variant comparison ────────────────────
//
// On aarch64: benchmarks both the per-round-barrier variant (default) and the
// monolithic-asm variant (enabled by --cfg md5_monolithic_asm).
// On other architectures: benchmarks compress via the public md5() API on a
// single 55-byte message (one block, no padding overflow).

fn bench_compress(c: &mut Criterion) {
    // A single full 64-byte block.
    let block = [0xA5u8; 64];
    // Use the public md5 API on a 55-byte payload (fits in one block, so
    // compress is called exactly once after padding).
    let payload = vec![0xA5u8; 55];
    let mut group = c.benchmark_group("md5_compress");
    group.throughput(Throughput::Bytes(64));
    group.bench_function("single_block", |b| {
        b.iter(|| crypto::md5(std::hint::black_box(&payload)));
    });
    // Three-block input — isolates multi-block throughput.
    let payload3 = vec![0xA5u8; 55 + 128];
    group.throughput(Throughput::Bytes(3 * 64));
    group.bench_function("three_blocks", |b| {
        b.iter(|| crypto::md5(std::hint::black_box(&payload3)));
    });
    let _ = block;
    group.finish();
}

// ── md5 ──────────────────────────────────────────────────────────────────────

fn bench_md5(c: &mut Criterion) {
    let mut group = c.benchmark_group("md5");
    for size in [16usize, 64, 256, 1024, 16_384] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| crypto::md5(std::hint::black_box(d)));
        });
    }
    group.finish();
}

// ── fast_md5 vs aws-lc MD5 ────────────────────────────────────────────────────

fn bench_md5_vs_awslc(c: &mut Criterion) {
    let mut group = c.benchmark_group("md5_vs_awslc");
    for size in [16usize, 64, 256, 1024, 16_384] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("fast_md5", size), &data, |b, d| {
            b.iter(|| crypto::md5(std::hint::black_box(d)));
        });
        group.bench_with_input(BenchmarkId::new("aws_lc", size), &data, |b, d| {
            b.iter(|| awslc_md5(std::hint::black_box(d)));
        });
    }
    group.finish();
}

// ── md5_of (scatter-gather, two parts) ───────────────────────────────────────

fn bench_md5_of(c: &mut Criterion) {
    let mut group = c.benchmark_group("md5_of");
    for size in [16usize, 64, 256, 1024, 16_384] {
        let half = size / 2;
        let part1 = vec![0xABu8; half];
        let part2 = vec![0xCDu8; size - half];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(part1, part2),
            |b, (p1, p2)| {
                b.iter(|| {
                    crypto::md5_of(&[
                        std::hint::black_box(p1.as_slice()),
                        std::hint::black_box(p2.as_slice()),
                    ])
                });
            },
        );
    }
    group.finish();
}

// ── md5_of (RADIUS-pattern: 16-byte header + variable payload) ───────────────
//
// The dominant RADIUS use of md5_of is password obfuscation:
//   MD5(secret || authenticator || previous_cipher_block)
// represented as two or three short slices.  This group isolates that pattern.

fn bench_md5_of_radius_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("md5_of_radius_pattern");
    // secret || 16-byte authenticator
    let secret = b"xyzzy5461";
    let auth = [0xABu8; 16];
    group.throughput(Throughput::Bytes((secret.len() + auth.len()) as u64));
    group.bench_function("secret+auth", |b| {
        b.iter(|| {
            crypto::md5_of(&[
                std::hint::black_box(secret.as_slice()),
                std::hint::black_box(auth.as_slice()),
            ])
        });
    });
    // secret || 16-byte authenticator || 16-byte cipher block (User-Password chain)
    let cipher_block = [0xCDu8; 16];
    group.throughput(Throughput::Bytes(
        (secret.len() + auth.len() + cipher_block.len()) as u64,
    ));
    group.bench_function("secret+auth+block", |b| {
        b.iter(|| {
            crypto::md5_of(&[
                std::hint::black_box(secret.as_slice()),
                std::hint::black_box(auth.as_slice()),
                std::hint::black_box(cipher_block.as_slice()),
            ])
        });
    });
    group.finish();
}

// ── hmac_md5 ──────────────────────────────────────────────────────────────────

fn bench_hmac_md5(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_md5");
    for size in [16usize, 64, 256, 1024] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| crypto::hmac_md5(std::hint::black_box(HMAC_KEY), std::hint::black_box(d)));
        });
    }
    group.finish();
}

// ── fill_random ───────────────────────────────────────────────────────────────
//
// 16 B — minimum (one identifier-only allocation).
// 17 B — the RADIUS single-call pattern from CLAUDE.md: 16-byte authenticator
//         + 1-byte identifier pulled from a shared 17-byte buffer.
// 128 B — larger burst for relative cost comparison.

fn bench_fill_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("fill_random");
    for &size in &[16usize, 17, 128] {
        let mut buf = vec![0u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                crypto::fill_random(&mut buf);
                std::hint::black_box(&buf);
            });
        });
    }
    group.finish();
}

// ── random_bytes ──────────────────────────────────────────────────────────────

fn bench_random_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_bytes");
    for &size in &[16usize, 17] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            b.iter(|| crypto::random_bytes(std::hint::black_box(n)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compress,
    bench_md5,
    bench_md5_vs_awslc,
    bench_md5_of,
    bench_md5_of_radius_pattern,
    bench_hmac_md5,
    bench_fill_random,
    bench_random_bytes,
);
criterion_main!(benches);
