use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PROTOCOL_SUFFIX: &str = "\r\n";
pub const PROTOCOL_PREFIX: &str = "PROXY";
pub const TCP4: &str = "TCP4";
pub const TCP6: &str = "TCP6";
pub const UNKNOWN: &str = "UNKNOWN";

/// The sperator of the header parts.
pub const SEPARATOR: char = ' ';

/// The offset from the start of the header until the portion of the header to be skipped.
/// Only applies when the protocol is UNKNOWN and there are bytes after the protocol.
pub const UNKNOWN_OFFSET: usize =
    PROTOCOL_PREFIX.len() + SEPARATOR.len_utf8() + UNKNOWN.len() + SEPARATOR.len_utf8();

/// A text PROXY protocol header.
#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a str,
    pub addresses: Addresses,
}

impl<'a> Header<'a> {
    /// Creates a new `Header` with the given addresses and a reference to the original input.
    pub fn new(header: &'a str, addresses: Addresses) -> Self {
        Header { header, addresses }
    }

    /// The protocol portion of this `Header`.
    pub fn protocol(&self) -> &str {
        match self.addresses {
            Addresses::Tcp4(..) => TCP4,
            Addresses::Tcp6(..) => TCP6,
            Addresses::Unknown => UNKNOWN,
        }
    }

    /// The source and destination addressses portion of this `Header`.
    pub fn addresses(&self) -> &'a str {
        let end = self.header.len() - PROTOCOL_SUFFIX.len();
        &self.header[UNKNOWN_OFFSET..end]
    }
}

/// The source and destination of a header.
/// Includes IP (v4 or v6) addresses and TCP ports.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Addresses {
    Tcp4(Tcp4),
    Tcp6(Tcp6),
    Unknown,
}

impl Addresses {
    /// Create a new IPv4 TCP address.
    pub fn new_tcp4(
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp4(Tcp4 {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }

    /// Create a new IPv6 TCP address.
    pub fn new_tcp6(
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp6(Tcp6 {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }
}

impl Default for Addresses {
    fn default() -> Self {
        Addresses::Unknown
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)
    }
}

/// The source and destination IPv4 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Tcp4 {
    pub source_address: Ipv4Addr,
    pub source_port: u16,
    pub destination_address: Ipv4Addr,
    pub destination_port: u16,
}

/// The source and destination IPv6 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Tcp6 {
    pub source_address: Ipv6Addr,
    pub source_port: u16,
    pub destination_address: Ipv6Addr,
    pub destination_port: u16,
}
