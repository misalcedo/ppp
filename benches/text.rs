use criterion::{BenchmarkId, Criterion};
use criterion::{black_box, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};

use ppp::model::*;
use ppp::{parse_header, to_string, v1};
use std::net::{Ipv4Addr, Ipv6Addr};

fn benchmarks(c: &mut Criterion) {
    c.bench_function("ppp text tcp4", |b| {
        b.iter(|| {
            parse_header(black_box(
                "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes(),
            ))
        })
    });

    c.bench_function("ppp text tcp6", |b| b.iter(|| parse_header(black_box("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()))));

    c.bench_function("ppp text tcp6 compact", |b| {
        b.iter(|| {
            parse_header(black_box(
                "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
                    .as_bytes(),
            ))
        })
    });

    c.bench_function("ppp header to text tcp4", |b| {
        b.iter(|| {
            to_string(black_box(Header::version_1(
                ([127, 0, 1, 2], [192, 168, 1, 101], 80, 443).into(),
            )))
        })
    });

    c.bench_function("ppp header to text tcp6", |b| {
        b.iter(|| {
            to_string(black_box(Header::version_1(
                (
                    [
                        0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321,
                    ],
                    [
                        0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,
                    ],
                    443,
                    65535,
                )
                    .into(),
            )))
        })
    });

    c.bench_function("ppp header to text unknown", |b| {
        b.iter(|| to_string(black_box(Header::unknown())))
    });
}

fn benchmarks_v2(c: &mut Criterion) {
    let mut group = c.benchmark_group("PPP Text");

    let inputs = [
        "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
        "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
        "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
    ];

    for input in inputs {
        group.bench_with_input(BenchmarkId::from_parameter(input), input.as_bytes(), |b, i| {
            b.iter(|| v1::Header::try_from(i));
        });
    }

    let headers = [
        v1::Header::new(
            "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
            v1::Addresses::new_tcp4(
                Ipv4Addr::new(127, 0, 1, 2),
                Ipv4Addr::new(192, 168, 1, 101),
                80,
                443,
            ),
        ),
        v1::Header::new(
            "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n",
            v1::Addresses::new_tcp6(
            Ipv6Addr::from([
                0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321,
            ]),
            Ipv6Addr::from([
                0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,
            ]),
            443,
            65535,
        )),
        v1::Header::new("PROXY UNKNOWN\r\n", v1::Addresses::default()),
    ];

    for header in headers {
        group.bench_with_input(BenchmarkId::from_parameter(&header), &header, |b, h| {
            b.iter(|| h.to_string());
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmarks, benchmarks_v2
}

criterion_main!(benches);
