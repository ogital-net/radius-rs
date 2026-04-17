use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use radius::core::avp::AVP;

static SECRET: &[u8] = b"s3cr3t-shared-key";
static REQUEST_AUTHENTICATOR: &[u8] = b"0123456789abcdef"; // exactly 16 bytes

fn bench_from_user_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("AVP::from_user_password");
    for password in [
        "",
        "short",
        "exactly-16-bytes",
        "a-longer-password-exceeding-16-bytes",
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", password.len())),
            password,
            |b, pw| {
                b.iter(|| {
                    AVP::from_user_password(
                        2,
                        std::hint::black_box(pw.as_bytes()),
                        std::hint::black_box(SECRET),
                        std::hint::black_box(REQUEST_AUTHENTICATOR),
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_encode_user_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("AVP::encode_user_password");
    for password in [
        "",
        "short",
        "exactly-16-bytes",
        "a-longer-password-exceeding-16-bytes",
    ] {
        let avp =
            AVP::from_user_password(2, password.as_bytes(), SECRET, REQUEST_AUTHENTICATOR).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", password.len())),
            &avp,
            |b, a| {
                b.iter(|| {
                    std::hint::black_box(a)
                        .encode_user_password(
                            std::hint::black_box(SECRET),
                            std::hint::black_box(REQUEST_AUTHENTICATOR),
                        )
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_from_tunnel_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("AVP::from_tunnel_password");
    for password in [
        "",
        "short",
        "exactly-16-bytes",
        "a-longer-password-exceeding-16-bytes",
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} bytes", password.len())),
            password,
            |b, pw| {
                b.iter(|| {
                    AVP::from_tunnel_password(
                        69,
                        None,
                        std::hint::black_box(pw.as_bytes()),
                        std::hint::black_box(SECRET),
                        std::hint::black_box(REQUEST_AUTHENTICATOR),
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_from_user_password,
    bench_encode_user_password,
    bench_from_tunnel_password,
);
criterion_main!(benches);
