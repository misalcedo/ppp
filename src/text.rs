use std::io::Read;
use crate::error::Error;
use crate::error::ErrorKind::*;
use crate::text::Protocol::{TCP};
use crate::text::Family::{IPv4, IPv6};
use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;

trait Parser {
    fn parse(stream: &mut dyn Read) -> Result<Header, Error>;
}

const PROXY: &str = "PROXY";
const CRLF: &str = "\r\n";
const TCP4: &str = "TCP4";
const TCP6: &str = "TCP6";
const UNKNOWN: &str = "UNKNOWN";

#[derive(Debug)]
#[derive(PartialEq)]
enum Protocol {
    TCP,
    Unknown,
}

#[derive(Debug)]
#[derive(PartialEq)]
enum Family {
    IPv4,
    IPv6,
    Unknown,
}

#[derive(Debug)]
#[derive(PartialEq)]
struct ProtocolFamily {
    protocol: Protocol,
    family: Family,
}

impl ProtocolFamily {
    fn new(protocol: Protocol, family: Family) -> ProtocolFamily {
        ProtocolFamily { protocol, family }
    }

    fn unknown() -> ProtocolFamily {
        ProtocolFamily::new(Protocol::Unknown, Family::Unknown)
    }
}

impl TryFrom<&str> for ProtocolFamily {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if TCP4.eq_ignore_ascii_case(value) {
            Ok(ProtocolFamily::new(TCP, IPv4))
        } else if TCP6.eq_ignore_ascii_case(value) {
            Ok(ProtocolFamily::new(TCP, IPv6))
        } else if UNKNOWN.eq_ignore_ascii_case(value) {
            Ok(ProtocolFamily::unknown())
        } else {
            Err(format!("Invalid protocol and family. (Value: {})", value))
        }
    }
}

#[derive(Debug)]
struct Header {
    source: IpAddr,
    destination: IpAddr
}

impl Parser for Header {
    /// See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
    fn parse(stream: &mut dyn Read) -> Result<Header, Error> {
        let mut buffer: [u8; 108] = [0; 108];
        let result = stream.read(&mut buffer)?;
        let header = std::str::from_utf8(&buffer[..result])?;
        let mut parts = header.split_ascii_whitespace();

        match parts.next() {
            Some(part) => {
                if PROXY.eq_ignore_ascii_case(part) {
                    Ok(())
                } else {
                    Err(Error::from(InvalidHeader))
                }
            },
            None => Err(Error::from(MissingProxy))
        }?;

        let protocol_family = match parts.next() {
            Some(part) => Ok(ProtocolFamily::try_from(part)),
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        let source_address = match parts.next() {
            Some(part) => Ok(part),
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        let destination_address = match parts.next() {
            Some(part) => Ok(part),
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        let source_port = match parts.next() {
            Some(part) => Ok(part),
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        let destination_port = match parts.next() {
            Some(part) => Ok(part),
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        Ok(Header {
            source: IpAddr::from_str(source_address)?,
            destination: IpAddr::from_str(destination_address)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind::{EmptyStream, MissingCRLF};

    #[test]
    fn proxy() {}

    #[test]
    fn parse_empty() {
        let mut stream: [u8; 0] = [];

        assert_eq!(Header::parse(&mut &stream[..]).err(), Some(Error::from(EmptyStream)));
    }

    #[test]
    fn parse_tcp4() {
        let mut text = unsafe {
            "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes()
        };

        assert_eq!(Header::parse(&mut text).err(), None);
    }

    #[test]
    fn parse_tcp6() {
        let mut text = unsafe {
            "PROXY IPV6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()
        };

        assert_eq!(Header::parse(&mut text).err(), None);
    }

    #[test]
    fn parse_unknown_connection() {
        let mut text = unsafe {
            "PROXY UNKNOWN\r\n".as_bytes()
        };

        assert_eq!(Header::parse(&mut text).err(), None);
    }

    #[test]
    fn parse_worst_case() {
        let mut text = unsafe {
            "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes()
        };

        assert_eq!(Header::parse(&mut text).err(), None);
    }

    #[test]
    fn parse_too_long() {
        let mut text = unsafe {
            "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n".as_bytes()
        };

        assert_eq!(Header::parse(&mut text).err(), Some(Error::from(MissingCRLF)));
    }
}
