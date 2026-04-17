use criterion::{criterion_group, criterion_main, Criterion};
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::rfc2865;

// A real Access-Request packet from RFC 2865 §7.1.
static RFC2865_REQUEST: &[u8] = &[
    0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb,
    0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12, 0x0d, 0xbe, 0x70, 0x8d,
    0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a, 0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8,
    0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
];
static SECRET: &[u8] = b"xyzzy5461";

fn bench_packet_decode(c: &mut Criterion) {
    c.bench_function("Packet::decode (Access-Request)", |b| {
        b.iter(|| Packet::decode(std::hint::black_box(RFC2865_REQUEST), SECRET).unwrap())
    });
}

fn bench_packet_encode(c: &mut Criterion) {
    let packet = Packet::decode(RFC2865_REQUEST, SECRET).unwrap();
    c.bench_function("Packet::encode (Access-Request)", |b| {
        b.iter(|| std::hint::black_box(&packet).encode().unwrap())
    });
}

fn bench_packet_encode_accounting(c: &mut Criterion) {
    // Build a minimal Accounting-Request so the authenticator-hash path is exercised.
    let mut pkt = Packet::new(Code::AccountingRequest, SECRET);
    rfc2865::add_user_name(&mut pkt, "testuser");
    c.bench_function("Packet::encode (Accounting-Request)", |b| {
        b.iter(|| std::hint::black_box(&pkt).encode().unwrap())
    });
}

fn bench_packet_new(c: &mut Criterion) {
    c.bench_function("Packet::new", |b| {
        b.iter(|| Packet::new(std::hint::black_box(Code::AccessRequest), std::hint::black_box(SECRET)))
    });
}

fn bench_is_authentic_response(c: &mut Criterion) {
    // Build a valid Access-Accept response to the RFC2865 request.
    let request = Packet::decode(RFC2865_REQUEST, SECRET).unwrap();
    let response_pkt = request.make_response_packet(Code::AccessAccept);
    let response_bytes = response_pkt.encode().unwrap();

    c.bench_function("Packet::is_authentic_response", |b| {
        b.iter(|| {
            Packet::is_authentic_response(
                std::hint::black_box(&response_bytes),
                std::hint::black_box(RFC2865_REQUEST),
                std::hint::black_box(SECRET),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_packet_new,
    bench_packet_decode,
    bench_packet_encode,
    bench_packet_encode_accounting,
    bench_is_authentic_response,
);
criterion_main!(benches);
