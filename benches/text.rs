#[macro_use]
extern crate criterion;

use criterion::Criterion;
use criterion::black_box;

use ppp::parse_header;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ppp text tcp4", |b| b.iter(|| parse_header(black_box("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes()))));
   
    c.bench_function("ppp text tcp6", |b| b.iter(|| parse_header(black_box("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()))));

    c.bench_function("ppp text tcp6 compact", |b| b.iter(|| parse_header(black_box("PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);