//! Models for storing IP v4 and v6 addresses and ports.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The source and destination IPv4 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IPv4 {
    pub source_address: Ipv4Addr,
    pub source_port: u16,
    pub destination_address: Ipv4Addr,
    pub destination_port: u16,
}

/// The source and destination IPv6 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IPv6 {
    pub source_address: Ipv6Addr,
    pub source_port: u16,
    pub destination_address: Ipv6Addr,
    pub destination_port: u16,
}
