//! Models for storing IP v4 and v6 addresses and ports.

use std::net::{SocketAddrV4, SocketAddrV6};

/// The source and destination IPv4 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IPv4 {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
}

impl IPv4 {
    /// Create a new IPv4 addresses.
    pub fn new<T: Into<SocketAddrV4>>(
        source: T,
        destination: T,
    ) -> Self {
        IPv4 {
            source: source.into(),
            destination: destination.into(),
        }
    }
}

/// The source and destination IPv6 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IPv6 {
    pub source: SocketAddrV6,
    pub destination: SocketAddrV6,
}

impl IPv6 {
    /// Create a new IPv6 addresses.
    pub fn new<T: Into<SocketAddrV6>>(
        source: T,
        destination: T,
    ) -> Self {
        IPv6 {
            source: source.into(),
            destination: destination.into(),
        }
    }
}
