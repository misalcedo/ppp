# ppp
A Proxy Protocol Parser written in Rust.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Benchmark
Ran `cargo bench` on a desktop with a hexa-core i7 processor with hyper-threading.

```bash
test binary::tests::bench_header_with_tlvs ... bench:         212 ns/iter (+/- 1)
test text::tests::bench_parse_tcp4         ... bench:         293 ns/iter (+/- 7)
test text::tests::bench_parse_tcp6         ... bench:         829 ns/iter (+/- 6)
test text::tests::bench_parse_tcp6_compact ... bench:         635 ns/iter (+/- 2)
```