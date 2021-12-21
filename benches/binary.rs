use criterion::{black_box, criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};

use ppp::v2;

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
    input.push(0x11);
    input.extend(&[0, 26]);
    input.extend(&[127, 0, 0, 1]);
    input.extend(&[198, 168, 1, 1]);
    input.extend(&[0, 80]);
    input.extend(&[1, 187]);
    input.extend(&[1, 0, 1, 5]);
    input.extend(&[2, 0, 2, 5, 5]);
    input.extend(&[2, 0, 2, 5, 5]);

    input
}

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("PPP Binary");

    let inputs = [
        ("IPv4 with TLVs", ipv4_input()),
        ("IPv6 without TLVs", ipv6_input()),
    ];

    for (id, input) in inputs {
        group.bench_with_input(
            BenchmarkId::new("v2::Header::try_from", id),
            input.as_slice(),
            |b, i| {
                b.iter(|| v2::Header::try_from(i).unwrap());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("v2::Header::as_bytes", id),
            &v2::Header::try_from(input.as_slice()).unwrap(),
            |b, h| {
                b.iter(|| h.as_bytes());
            },
        );
    }

    let source_address = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xF2,
    ];
    let destination_address = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xF1,
    ];
    let addresses =
        v2::Addresses::IPv6(v2::IPv6::new(source_address, destination_address, 80, 443));

    group.bench_function(
        BenchmarkId::new("v2::Builder::build", "IPv6 with TLVs"),
        |b| {
            b.iter(|| {
                black_box(
                    v2::Builder::new(
                        v2::Version::Two | v2::Command::Local,
                        v2::AddressFamily::IPv6 | v2::Protocol::Unspecified,
                    )
                    .write_payload(addresses)
                    .unwrap()
                    .write_payloads(vec![(v2::Type::NoOp, [0].as_slice())])
                    .unwrap()
                    .write_tlv(v2::Type::NoOp, [42].as_slice())
                    .unwrap()
                    .build()
                    .unwrap(),
                );
            });
        },
    );

    group.bench_function(
        BenchmarkId::new("v2::Builder::build", "IPv6 with TLVs with length"),
        |b| {
            b.iter(|| {
                black_box(
                    v2::Builder::with_addresses(
                        v2::Version::Two | v2::Command::Local,
                        v2::Protocol::Unspecified,
                        addresses,
                    )
                    .reserve_capacity(8)
                    .write_payloads([
                        (v2::Type::NoOp, [0].as_slice()),
                        (v2::Type::NoOp, [42].as_slice()),
                    ])
                    .unwrap()
                    .build()
                    .unwrap(),
                );
            });
        },
    );

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmarks
}

criterion_main!(benches);
