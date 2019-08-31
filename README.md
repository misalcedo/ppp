# ppp
A Proxy Protocol Parser written in Rust.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Benchmark
Ran `cargo bench` on a desktop with a hexa-core i7 processor with hyper-threading.

```bash
test parser::tests::bench_parse ... bench:         178 ns/iter (+/- 1)
test text::tests::bench_parse   ... bench:         394 ns/iter (+/- 1)
```