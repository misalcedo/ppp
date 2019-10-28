#[macro_use]
extern crate criterion;

use criterion::black_box;
use criterion::Criterion;

use ppp::model::*;
use ppp::{parse_header, to_bytes};

fn ipv6_input() -> Vec<u8> {
    let prefix = b"\r\n\r\n\0\r\nQUIT\n";
    let mut input: Vec<u8> = Vec::with_capacity(prefix.len());

    input.extend_from_slice(prefix);
    input.push(0x21);
    input.push(0x21);
    input.extend(&[0, 45]);
    input.extend(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF,
    ]);
    input.extend(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xF1,
    ]);
    input.extend(&[0, 80]);
    input.extend(&[1, 187]);
    input.extend(&[1, 0, 1, 5]);
    input.extend(&[2, 0, 2, 5, 5]);

    input
}

fn ipv4_input() -> Vec<u8> {
    let prefix = b"\r\n\r\n\0\r\nQUIT\n";
    let mut input: Vec<u8> = Vec::with_capacity(prefix.len());

    input.extend_from_slice(prefix);
    input.push(0x21);
    input.push(0x21);
    input.extend(&[0, 45]);
    input.extend(&[127, 0, 0, 1]);
    input.extend(&[198, 168, 1, 1]);
    input.extend(&[0, 80]);
    input.extend(&[1, 187]);
    input.extend(&[1, 0, 1, 5]);
    input.extend(&[2, 0, 2, 5, 5]);
    input.extend(&[2, 0, 2, 5, 5]);

    input
}

fn criterion_benchmark(c: &mut Criterion) {
    let ipv6 = ipv6_input();
    let ipv4 = ipv4_input();

    c.bench_function("ppp binary IPv6 without TLVs", |b| {
        b.iter(|| parse_header(black_box(ipv6.as_slice())))
    });

    c.bench_function("ppp binary IPv4 with TLVs", |b| {
        b.iter(|| parse_header(black_box(ipv4.as_slice())))
    });

    c.bench_function("ppp header to bytes binary IPv6 without TLVs", |b| {
        b.iter(|| {
            to_bytes(black_box(Header::new(
                Version::Two,
                Command::Proxy,
                Protocol::Stream,
                vec![],
                (
                    [
                        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF2,
                    ],
                    [
                        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                    ],
                    80,
                    443,
                )
                    .into(),
            )))
        })
    });

    c.bench_function("ppp header to bytes binary IPv4 with TLVs", |b| {
        b.iter(|| {
            to_bytes(black_box(Header::new(
                Version::Two,
                Command::Proxy,
                Protocol::Stream,
                vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
            )))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
