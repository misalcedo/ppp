# ppp
A Proxy Protocol Parser written in Rust.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Benchmark
Ran `cargo bench` on a desktop with a hexa-core i7 processor with hyper-threading.
Both parsers pass the same set of tests.

```bash
test parser::tests::bench_parse ... bench:         181 ns/iter (+/- 2)
test text::tests::bench_parse   ... bench:         378 ns/iter (+/- 4)
```