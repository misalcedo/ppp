use criterion::{black_box, criterion_group, criterion_main};
use criterion::Criterion;
use pprof::criterion::{Output, PProfProfiler};

use ppp::{parse_header, v1};

fn benchmarks(c: &mut Criterion) {
    c.bench_function("ppp v2 text tcp4", |b| {
        b.iter(|| {
            v1::Header::try_from(black_box(
                "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes(),
            ))
        })
    });

    c.bench_function("ppp v1 text tcp4", |b| {
        b.iter(|| {
            parse_header(black_box(
                "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes(),
            ))
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmarks
}

criterion_main!(benches);
