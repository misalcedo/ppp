use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a str,
    pub addresses: Addresses<'a>,
}

impl<'a> Header<'a> {
    #[cfg(test)]
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
            source: SocketAddrV4::new(source_address, source_port),
            destination: SocketAddrV4::new(destination_address, destination_port),
        })
    }

    pub fn new_tcp6(
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp6(Tcp6 {
            source: SocketAddrV6::new(source_address, source_port, 0, 0),
            destination: SocketAddrV6::new(destination_address, destination_port, 0, 0),
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

#[derive(Debug, PartialEq)]
pub struct Tcp4 {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
}

#[derive(Debug, PartialEq)]
pub struct Tcp6 {
    pub source: SocketAddrV6,
    pub destination: SocketAddrV6,
}

#[derive(Debug, PartialEq)]
pub struct Unknown<'a> {
    pub rest: Option<&'a str>,
}
