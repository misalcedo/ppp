#[macro_use]
extern crate criterion;

use criterion::black_box;
use criterion::Criterion;
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

fn v2_benchmarks(c: &mut Criterion) {
    c.bench_function("ppp v2 text tcp4", |b| {
        b.iter(|| {
            v1::Header::try_from(black_box(
                "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes(),
            ))
        })
    });

    c.bench_function("ppp v2 text tcp6", |b| b.iter(|| v1::Header::try_from(black_box("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()))));

    c.bench_function("ppp v2 text tcp6 compact", |b| {
        b.iter(|| {
            v1::Header::try_from(black_box(
                "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
                    .as_bytes(),
            ))
        })
    });

    c.bench_function("ppp v2 header to text tcp4", |b| {
        b.iter(|| {
            black_box(
                v1::Header::new(
                    "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
                    v1::Addresses::new_tcp4(
                        Ipv4Addr::new(127, 0, 1, 2),
                        Ipv4Addr::new(192, 168, 1, 101),
                        80,
                        443,
                    ),
                )
                .to_string(),
            )
        })
    });

    c.bench_function("ppp v2 header to text tcp6", |b| {
        b.iter(|| {
            black_box(v1::Header::new(
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
            )).to_string())
        })
    });

    c.bench_function("ppp v2 header to text unknown", |b| {
        b.iter(|| {
            black_box(v1::Header::new("PROXY UNKNOWN\r\n", v1::Addresses::default()).to_string())
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmarks, v2_benchmarks
}

criterion_main!(benches);
