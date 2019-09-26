# ppp
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)  
[![Build Status](https://travis-ci.org/misalcedo/ppp.svg?branch=master)](https://travis-ci.org/misalcedo/ppp)
[![Build status](https://ci.appveyor.com/api/projects/status/mlr10t4o0l5300nw?svg=true)](https://ci.appveyor.com/project/misalcedo/ppp)
[![Coverage](https://codecov.io/gh/misalcedo/ppp/branch/master/graph/badge.svg)](https://codecov.io/gh/misalcedo/ppp)
[![Crates.io Version](https://img.shields.io/crates/v/ppp.svg)](https://crates.io/crates/ppp)
[![Docs.rs Version](https://docs.rs/ppp/badge.svg)](https://docs.rs/ppp)

A Proxy Protocol Parser written in Rust.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Benchmark
Ran `cargo bench` on a desktop with a hexa-core i7 processor with hyper-threading.

```bash
     Running target/release/deps/binary-2681142d001dfe3e
ppp binary IPv6 without TLVs                                                                            
                        time:   [273.48 ns 273.81 ns 274.14 ns]
                        change: [-0.2142% -0.0984% +0.0580%] (p = 0.15 > 0.05)
                        No change in performance detected.
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe

ppp binary IPv4 with TLVs                                                                            
                        time:   [84.828 ns 85.427 ns 86.234 ns]
                        change: [+0.0067% +0.7984% +1.7888%] (p = 0.08 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) high mild
  8 (8.00%) high severe

     Running target/release/deps/text-fb185ef299e3eb06
ppp text tcp4           time:   [381.03 ns 381.78 ns 382.64 ns]                          
                        change: [-0.2661% +0.0295% +0.3722%] (p = 0.86 > 0.05)
                        No change in performance detected.
Found 7 outliers among 100 measurements (7.00%)
  3 (3.00%) high mild
  4 (4.00%) high severe

ppp text tcp6           time:   [942.93 ns 943.65 ns 944.54 ns]                           
                        change: [-0.5574% -0.1831% +0.2057%] (p = 0.36 > 0.05)
                        No change in performance detected.
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe

ppp text tcp6 compact   time:   [746.44 ns 746.70 ns 746.98 ns]                                   
                        change: [+0.5250% +0.5866% +0.6479%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 11 outliers among 100 measurements (11.00%)
  2 (2.00%) low severe
  1 (1.00%) low mild
  5 (5.00%) high mild
  3 (3.00%) high severe
```
