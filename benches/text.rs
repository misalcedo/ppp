use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};

use ppp::v1;
use std::net::{Ipv4Addr, Ipv6Addr};

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("PPP Text");

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
                b.iter(|| v1::Header::try_from(i));
            },
        );
    }

    let headers = [
        ("TCP4", v1::Header::new(
            "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
            v1::Addresses::new_tcp4(
                Ipv4Addr::new(127, 0, 1, 2),
                Ipv4Addr::new(192, 168, 1, 101),
                80,
                443,
            ),
        )),
        ("TCP6", v1::Header::new(
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
        ))),
        ("UNKNOWN", v1::Header::new("PROXY UNKNOWN\r\n", v1::Addresses::default())),
    ];

    for (id, header) in headers {
        group.bench_with_input(
            BenchmarkId::new("v1::Header::to_string", id),
            &header,
            |b, h| {
                b.iter(|| h.to_string());
            },
        );

        group.bench_with_input(
            BenchmarkId::new("v1::Addresses::to_string", id),
            &header.addresses,
            |b, a| {
                b.iter(|| a.to_string());
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
