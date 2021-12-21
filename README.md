# ppp
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![Crates.io Version](https://img.shields.io/crates/v/ppp.svg)](https://crates.io/crates/ppp)
[![Docs.rs Version](https://docs.rs/ppp/badge.svg)](https://docs.rs/ppp)

A Proxy Protocol Parser written in Rust. Supports both text and binary versions of the HAProxy header.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Usage
Add the following to your `Cargo.toml` as a dependency:

```toml
ppp = "2.0"
```

Then, you can use either the text or binary versions of the protocol.

For the text version use:
```rust
use ppp::v1;
use std::net::SocketAddr;

let client_address: SocketAddr = ...;
let server_address: SocketAddr = ...;

// Create a v1 header
let header = v1::Addresses::from((client_address, server_address)).to_string();

assert_eq!(header, v1::Header::try_from(header.as_str()).unwrap().to_string());
```

For the binary version use:
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

```bash
TODO
```
