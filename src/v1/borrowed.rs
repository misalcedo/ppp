use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a str,
    pub addresses: Addresses<'a>,
}

impl<'a> Header<'a> {
    pub fn new(header: &'a str, addresses: Addresses<'a>) -> Self {
        Header { header, addresses }
    }
}

#[derive(Debug, PartialEq)]
pub enum Addresses<'a> {
    Tcp4(Tcp4),
    Tcp6(Tcp6),
    Unknown(Unknown<'a>),
}

impl<'a> Addresses<'a> {
    pub fn new_tcp4(
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp4(Tcp4 {
            source_address, source_port, destination_address, destination_port,
        })
    }

    pub fn new_tcp6(
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp6(Tcp6 {
            source_address, source_port, destination_address, destination_port,
        })
    }

    pub fn new_unknown(rest: &'a str) -> Self {
        Addresses::Unknown(Unknown { rest: Some(rest) })
    }
}

impl<'a> Default for Addresses<'a> {
    fn default() -> Self {
        Addresses::Unknown(Unknown { rest: None })
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)
    }
}

#[derive(Debug, PartialEq)]
pub struct Tcp4 {
    pub source_address: Ipv4Addr,
    pub source_port: u16,
    pub destination_address: Ipv4Addr,
    pub destination_port: u16,
}

#[derive(Debug, PartialEq)]
pub struct Tcp6 {
    pub source_address: Ipv6Addr,
    pub source_port: u16,
    pub destination_address: Ipv6Addr,
    pub destination_port: u16,
}

#[derive(Debug, PartialEq)]
pub struct Unknown<'a> {
    pub rest: Option<&'a str>,
}
