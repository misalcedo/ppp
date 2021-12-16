use std::convert::TryFrom;
use std::str::from_utf8;

#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    header: &'a str,
    addresses: Addresses<'a>,
}

impl<'a> Header<'a> {
    #[cfg(test)]
    fn new(header: &'a str, addresses: Addresses<'a>) -> Self {
        Header { header, addresses }
    }
}

#[derive(Debug, PartialEq)]
pub enum Addresses<'a> {
    Tcp4(Tcp<'a>),
    Tcp6(Tcp<'a>),
    Unknown(Unknown<'a>),
}

impl<'a> Addresses<'a> {
    #[cfg(test)]
    fn new_tcp4(
        source_address: &'a str,
        destination_address: &'a str,
        source_port: &'a str,
        destination_port: &'a str,
    ) -> Self {
        Addresses::Tcp4(Tcp {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }

    #[cfg(test)]
    fn new_tcp6(
        source_address: &'a str,
        destination_address: &'a str,
        source_port: &'a str,
        destination_port: &'a str,
    ) -> Self {
        Addresses::Tcp6(Tcp {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }

    #[cfg(test)]
    fn new_unknown(rest: &'a str) -> Self {
        Addresses::Unknown(Unknown { rest: Some(rest) })
    }
}

impl<'a> Default for Addresses<'a> {
    fn default() -> Self {
        Addresses::Unknown(Unknown { rest: None })
    }
}

#[derive(Debug, PartialEq)]
pub struct Tcp<'a> {
    source_address: &'a str,
    source_port: &'a str,
    destination_address: &'a str,
    destination_port: &'a str,
}

#[derive(Debug, PartialEq)]
pub struct Unknown<'a> {
    rest: Option<&'a str>,
}
