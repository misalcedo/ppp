use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use ppp::v1;

#[cfg(unix)]
use pprof::criterion::{Output, PProfProfiler};

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("PPP Binary");

    let inputs = [
        ("UNKNOWN", "PROXY UNKNOWN\r\n"),
        ("TCP4", "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"),
        ("TCP6", "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"),
        ("TCP6 Compact", "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"),
        ("Worst Case", "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"),
    ];

    for (id, input) in inputs {
        group.bench_with_input(
            BenchmarkId::new("v1::Header::try_from", id),
            input.as_bytes(),
            |b, i| {
                b.iter(|| v1::Header::try_from(i).unwrap());
            },
        );
    }

    group.finish();
}

#[cfg(unix)]
criterion_group! {
    name = benches;
    config = {
        Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
    };
    targets = benchmarks
}

#[cfg(not(unix))]
criterion_group!(benches, benchmarks);

criterion_main!(benches);
