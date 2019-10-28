# ppp
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)  
[![Build Status](https://travis-ci.org/misalcedo/ppp.svg?branch=master)](https://travis-ci.org/misalcedo/ppp)
[![Build status](https://ci.appveyor.com/api/projects/status/mlr10t4o0l5300nw?svg=true)](https://ci.appveyor.com/project/misalcedo/ppp)
[![Coverage](https://codecov.io/gh/misalcedo/ppp/branch/master/graph/badge.svg)](https://codecov.io/gh/misalcedo/ppp)
[![Crates.io Version](https://img.shields.io/crates/v/ppp.svg)](https://crates.io/crates/ppp)
[![Docs.rs Version](https://docs.rs/ppp/badge.svg)](https://docs.rs/ppp)

A Proxy Protocol Parser written in Rust. Supports both text and binary versions of the header.
See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Benchmark
Ran `cargo bench` on a desktop with a hexa-core i7 processor with hyper-threading.

```bash
     Running target/release/deps/binary-2681142d001dfe3e
ppp binary IPv6 without TLVs                                                                            
                        time:   [281.15 ns 282.12 ns 283.49 ns]
                        change: [-7.6818% -6.1635% -4.5902%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high severe

ppp binary IPv4 with TLVs                                                                            
                        time:   [84.356 ns 84.433 ns 84.505 ns]
                        change: [-1.6253% -0.7449% +0.0210%] (p = 0.08 > 0.05)
                        No change in performance detected.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) low mild

ppp header to bytes binary IPv6 without TLVs                                                                            
                        time:   [148.49 ns 148.53 ns 148.58 ns]
                        change: [-3.5002% -2.2646% -1.1667%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high severe

ppp header to bytes binary IPv4 with TLVs                                                                            
                        time:   [158.92 ns 160.10 ns 161.47 ns]
                        change: [-2.1441% -1.0137% +0.0999%] (p = 0.08 > 0.05)
                        No change in performance detected.
Found 7 outliers among 100 measurements (7.00%)
  2 (2.00%) high mild
  5 (5.00%) high severe

     Running target/release/deps/text-fb185ef299e3eb06
ppp text tcp4           time:   [368.56 ns 368.84 ns 369.27 ns]                          
                        change: [-6.0919% -4.1408% -2.4502%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  4 (4.00%) high mild
  6 (6.00%) high severe

ppp text tcp6           time:   [932.82 ns 940.16 ns 949.77 ns]                           
                        change: [-0.9088% -0.3712% +0.1755%] (p = 0.20 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  3 (3.00%) high mild
  13 (13.00%) high severe

ppp text tcp6 compact   time:   [731.10 ns 731.63 ns 732.36 ns]                                   
                        change: [-2.6089% -1.8543% -1.1878%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 22 outliers among 100 measurements (22.00%)
  1 (1.00%) low severe
  3 (3.00%) low mild
  3 (3.00%) high mild
  15 (15.00%) high severe

ppp header to text tcp4 time:   [236.54 ns 236.61 ns 236.68 ns]                                    
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe

ppp header to text tcp6 time:   [536.64 ns 539.69 ns 543.51 ns]                                     
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) high mild
  5 (5.00%) high severe

ppp header to text unknown                                                                            
                        time:   [51.601 ns 51.625 ns 51.651 ns]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe

```
