# ppp
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![Crates.io Version](https://img.shields.io/crates/v/ppp.svg)](https://crates.io/crates/ppp)
[![Docs.rs Version](https://docs.rs/ppp/badge.svg)](https://docs.rs/ppp)

A Proxy Protocol Parser written in Rust. Supports both text and binary versions of the HAProxy header.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Usage
Add the following to your `Cargo.toml` as a dependency:

```toml
ppp = "2.3"
```

Then, you can use either the text or binary versions of the protocol.

To parse or generate the text version use:
```rust
use ppp::v1;
use std::net::SocketAddr;

let client_address: SocketAddr = ...;
let server_address: SocketAddr = ...;

// Create a v1 header
let header = v1::Addresses::from((client_address, server_address)).to_string();

assert_eq!(header, v1::Header::try_from(header.as_str()).unwrap().to_string());
```

To parse or generate the binary version use:
```rust
use ppp::v2;
use std::net::SocketAddr;

let client_address: SocketAddr = ...;
let server_address: SocketAddr = ...;

let header = v2::Builder::with_addresses(
    v2::Version::Two | v2::Command::Proxy,
    v2::Protocol::Stream,
    (client_address, server_address),
)
.write_tlv(v2::Type::NoOp, b"Hello, World!")
.unwrap()
.build()
.unwrap();

assert_eq!(
    header,
    v2::Header::try_from(header.as_slice()).unwrap().as_bytes()
);
```

To parse either version use:

```rust
use ppp::{HeaderResult, PartialResult, v1};

let input = "PROXY UNKNOWN\r\n";
let header = HeaderResult::parse(input.as_bytes());

assert_eq!(header, Ok(v1::Header::new(input, v1::Addresses::Unknown)).into());
```

## Examples
The [repository](https://github.com/misalcedo/ppp) contains examples for how to use both versions of the proxy protocol with streaming support. To run the examples, you will need to use 3 terminal windows.

### Proxy
The proxy Server that writes the proxy protocol header will be in its own terminal. The example takes an optional argument of which version of the header to write as `v1` or `v2`, with a default of `v2`.

Version 2:
```bash
cargo run --examples one_byte
```

Version 1:
```bash
cargo run --examples one_byte v1
```

### Server
A minimal HTTP server that reads the proxy protocol headers and responds to HTTP requests.

```bash
cargo run --examples server
```

### HTTP Client
We use `cURL` as the HTTP client for the examples, but any HTTP client will do.

```bash
curl -vvv http://localhost:8888/
```

## Profiling
Profiling a benchmark run is currently only supported on a *nix environment. The profiler outputs a flamegraph in the `target` directory. To run a profiling session use:

```bash
cargo bench -- --profile-time=60
```

## Benchmark
To run the benchmarks use:

```bash
cargo bench
```

### Results
The following are a snapshot of a benchmarking run on a desktop with a hexa-core i7 processor with hyper-threading.

#### Binary
```bash
PPP Binary/v2::Header::try_from/IPv4 with TLVs
                        time:   [51.357 ns 52.009 ns 52.722 ns]
PPP Binary/v2::Header::as_bytes/IPv4 with TLVs
                        time:   [515.38 ps 516.26 ps 517.48 ps]
PPP Binary/v2::Header::try_from/IPv6 without TLVs
                        time:   [48.939 ns 49.032 ns 49.147 ns]
PPP Binary/v2::Header::as_bytes/IPv6 without TLVs
                        time:   [514.61 ps 515.33 ps 516.42 ps]
PPP Binary/v2::Builder::build/IPv6 with TLVs
                        time:   [1.3795 us 1.3983 us 1.4194 us]
PPP Binary/v2::Builder::build/IPv6 with TLVs with length
                        time:   [136.72 ns 139.03 ns 141.54 ns]
```

#### Text
```bash
PPP Text/v1::Header::try_from/UNKNOWN
                        time:   [54.173 ns 54.247 ns 54.338 ns]
PPP Text/v1::Header::try_from/TCP4
                        time:   [217.13 ns 217.62 ns 218.33 ns]
PPP Text/v1::Header::try_from/TCP6
                        time:   [537.42 ns 537.92 ns 538.60 ns]
PPP Text/v1::Header::try_from/TCP6 Compact
                        time:   [395.83 ns 397.08 ns 398.96 ns]
PPP Text/v1::Header::try_from/Worst Case
                        time:   [209.62 ns 209.75 ns 209.89 ns]
PPP Text/v1::Header::to_string/TCP4
                        time:   [70.355 ns 70.432 ns 70.528 ns]
PPP Text/v1::Addresses::to_string/TCP4
                        time:   [413.55 ns 415.27 ns 418.09 ns]
PPP Text/v1::Header::to_string/TCP6
                        time:   [81.200 ns 81.421 ns 81.716 ns]
PPP Text/v1::Addresses::to_string/TCP6
                        time:   [851.04 ns 852.34 ns 853.91 ns]
PPP Text/v1::Header::to_string/UNKNOWN
                        time:   [72.256 ns 73.089 ns 73.979 ns]
PPP Text/v1::Addresses::to_string/UNKNOWN
                        time:   [66.237 ns 66.305 ns 66.391 ns]
```
