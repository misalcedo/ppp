use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};

use ppp::{parse_header, v2};

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

fn benchmarks(c: &mut Criterion) {
    let ipv6 = ipv6_input();
    let ipv4 = ipv4_input();

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
                b.iter(|| v2::Header::try_from(i));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parse_header", id),
            input.as_slice(),
            |b, i| {
                b.iter(|| parse_header(i));
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmarks
}

criterion_main!(benches);
