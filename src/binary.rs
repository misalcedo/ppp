use nom::IResult;
use nom::bytes::streaming::*;
use nom::number::streaming::*;
use nom::combinator::*;
use nom::sequence::*;
use nom::branch::alt;
use std::net::{Ipv4Addr, Ipv6Addr};

extern crate test;

const PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Debug, Eq, PartialEq)]
struct Header {
    version: Version,
    command: Command,
    protocol: TransportProtocol,
    address_family: AddressFamily,
    address: Vec<u8>
}

#[derive(Debug, Eq, PartialEq)]
enum AddressFamily {
    Unspec, IPv4, IPv6, Unix
}

#[derive(Debug, Eq, PartialEq)]
enum TransportProtocol {
    Unspec, Stream, Datagram
}

#[derive(Debug, Eq, PartialEq)]
enum Version {
    One,
    Two
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Local, Proxy
}

#[derive(Debug, Eq, PartialEq)]
enum InternetProtocol {
    TCP, UDP
}

#[derive(Debug, Eq, PartialEq)]
enum Address {
    Unspec(Vec<u8>),
    IPv4 {
        protocol: InternetProtocol,
        sourceAddress: Ipv4Addr,
        destinationAddress: Ipv4Addr,
        sourcePort: u16,
        destinationPort: u16
    },
    IPv6 {
        protocol: InternetProtocol,
        sourceAddress: Ipv6Addr,
        destinationAddress: Ipv6Addr,
        sourcePort: u16,
        destinationPort: u16
    },
    Unix {
        source: [u8; 32],
        destination: [u8; 32]
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        preceded(tag(PREFIX), tuple((parse_command, parse_protocol_family, flat_map(be_u16, take)))),
        |((version, command), (address_family, protocol), bytes)| {
            let mut address: Vec<u8> = Vec::with_capacity(bytes.len());
            
            address.extend_from_slice(bytes);
            
            Header {
                version,
                address_family,
                protocol,
                command,
                address 
            }
        }
    )(input)
}

fn parse_address(input: &[u8]) -> IResult<&[u8], Address> {
    Ok((input, Address::Unspec(Vec::new()))) 
}

fn parse_command(input: &[u8]) -> IResult<&[u8], (Version, Command)> {
    alt((
        map(tag(b"\x20"), |_| (Version::Two, Command::Local)), 
        map(tag(b"\x21"), |_| (Version::Two, Command::Proxy))
    ))(input)
}

fn parse_protocol_family(input: &[u8]) -> IResult<&[u8], (AddressFamily, TransportProtocol)> {
    alt((
        map(tag(b"\x00"), |_| (AddressFamily::Unspec, TransportProtocol::Unspec)), 
        map(tag(b"\x01"), |_| (AddressFamily::Unspec, TransportProtocol::Stream)), 
        map(tag(b"\x02"), |_| (AddressFamily::Unspec, TransportProtocol::Datagram)), 
        map(tag(b"\x10"), |_| (AddressFamily::IPv4, TransportProtocol::Unspec)),
        map(tag(b"\x11"), |_| (AddressFamily::IPv4, TransportProtocol::Stream)),
        map(tag(b"\x12"), |_| (AddressFamily::IPv4, TransportProtocol::Datagram)),
        map(tag(b"\x20"), |_| (AddressFamily::IPv6, TransportProtocol::Unspec)),
        map(tag(b"\x21"), |_| (AddressFamily::IPv6, TransportProtocol::Stream)),
        map(tag(b"\x22"), |_| (AddressFamily::IPv6, TransportProtocol::Datagram)),
        map(tag(b"\x30"), |_| (AddressFamily::Unix, TransportProtocol::Unspec)),
        map(tag(b"\x31"), |_| (AddressFamily::Unix, TransportProtocol::Stream)),
        map(tag(b"\x32"), |_| (AddressFamily::Unix, TransportProtocol::Datagram))
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_address_local() {
        let result = parse_header(b"\r\n\r\n\0\r\nQUIT\n\x20\x02\0\0");
        let expected = Header {
                version: Version::Two,
                command: Command::Local,
                protocol: TransportProtocol::Datagram,
                address_family: AddressFamily::Unspec,
                address: Vec::new()
        };

        assert_eq!(result, Ok((&[][..], expected)));
    }

    #[test]
    fn no_address_proxy() {
        let result = parse_header(b"\r\n\r\n\0\r\nQUIT\n\x21\x02\0\x01\xFF");
        let expected = Header {
                version: Version::Two,
                command: Command::Proxy,
                protocol: TransportProtocol::Datagram,
                address_family: AddressFamily::Unspec,
                address: vec![0xFF]
        };

        assert_eq!(result, Ok((&[][..], expected)));
    }

    #[test]
    fn wrong_version() {
        let result = parse_header(b"\r\n\r\n\0\r\nQUIT\n\x13\x02\0\x01\xFF");

        assert!(result.is_err());
    }

    #[test]
    fn not_prefixed() {
        let result = parse_header(b"\r\n\r\n\x01\r\nQUIT\n");

        assert!(result.is_err());
    }

    #[test]
    fn incomplete() {
        let bytes = [0x0D, 0x0A, 0x0D, 0x0A, 0x00];
        let result = parse_header(&bytes[..]);

        assert!(result.is_err());
    }
}