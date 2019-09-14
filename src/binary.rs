extern crate test;

use std::convert::TryFrom;

use nom::branch::alt;
use nom::bytes::streaming::*;
use nom::combinator::*;
use nom::IResult;
use nom::multi::{count, fold_many0};
use nom::number;
use nom::number::streaming::*;
use nom::sequence::*;

use crate::model::{Address, Command, Header, Protocol, Tlv, Version};

const PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// The address family of the source and destination addresses.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum AddressFamily {
    IPv4,
    IPv6,
    Unix,
    Unspecified,
}

/// The required portion of a version 2 header.
type RequiredHeader = ((Version, Command), (AddressFamily, Protocol), u16);
type Addresses = (Address, Address);
type OptionalHeader = ((Address, Address), Vec<Tlv>);

/// Parse the first 16 bytes of the protocol header; the only required payload.
/// The 12 byte signature and 4 bytes used to describe the connection and header information.
pub fn parse_v2_header(input: &[u8]) -> IResult<&[u8], Header> {
    flat_map(
        parse_required_header,
        parse_full_header,
    )(input)
}

fn parse_full_header(required_header: RequiredHeader) -> impl Fn(&[u8]) -> IResult<&[u8], Header>
{
    move |input: &[u8]| {
        let ((version, command), (address_family, protocol), address_length) = required_header;

        map(
            parse_optional_header(address_family, address_length),
            move |((source_address, destination_address), tlvs)| Header::new(version, command, protocol, tlvs, source_address, destination_address),
        )(input)
    }
}

fn parse_required_header(input: &[u8]) -> IResult<&[u8], RequiredHeader> {
    preceded(
        tag(PREFIX),
        tuple((parse_version_command, parse_family_protocol, be_u16)),
    )(input)
}

fn parse_optional_header(address_family: AddressFamily, address_length: u16) -> impl Fn(&[u8]) -> IResult<&[u8], OptionalHeader>
{
    move |input: &[u8]| {
        let (input, address) = take(address_length)(input)?;
        let (_, optional_header) = all_consuming(pair(parse_addresses(address_family, address_length), parse_tlvs))(address)?;

        Ok((input, optional_header))
    }
}

fn parse_addresses(address_family: AddressFamily, address_length: u16) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses> {
    move |input: &[u8]| {
        match address_family {
            AddressFamily::IPv4 => parse_ip_address_pair(parse_ipv4_address)(input),
            AddressFamily::IPv6 => parse_ip_address_pair(parse_ipv6_address)(input),
            AddressFamily::Unix => parse_unix_address_pairs(input),
            AddressFamily::Unspecified => parse_unspecified(address_length)(input)
        }
    }
}

fn parse_unspecified(address_length: u16) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses> {
    move |input: &[u8]| map(take(address_length), |_| (Address::None, Address::None))(input)
}

/// Parses multiple Type-Length-Value records.
fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Tlv>> {
    fold_many0(
        parse_tlv,
        Vec::new(),
        |mut acc: Vec<Tlv>, tlv| {
            acc.push(tlv);
            acc
        },
    )(input)
}

/// Parses a single Type-Length-Value record.
fn parse_tlv(input: &[u8]) -> IResult<&[u8], Tlv> {
    map(
        tuple((number::complete::be_u8, flat_map(map_res(number::complete::be_u16, usize::try_from), |l| count(number::complete::be_u8, l)))),
        |(value_type, value)| Tlv::new(value_type, value),
    )(input)
}

fn parse_unix_address(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    count(be_u8, 108)(input)
}

fn parse_unix_address_pairs(input: &[u8]) -> IResult<&[u8], Addresses> {
    map_res(
        pair(parse_unix_address, parse_unix_address),
        |(s, d)| Ok::<Addresses, &'static str>((Address::try_from(s)?, Address::try_from(d)?)),
    )(input)
}

/// Parse a 32-bit IPv4 address.
fn parse_ipv4_address(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    map(
        tuple((be_u8, be_u8, be_u8, be_u8)),
        |(a, b, c, d)| [a, b, c, d],
    )(input)
}

/// Parse a source and destination address.
fn parse_ip_address_pair<O, F>(parse_ip_address: F) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses>
    where
        F: Fn(&[u8]) -> IResult<&[u8], O>,
        (u16, O): Into<Address>
{
    move |input: &[u8]| {
        map(
            pair(pair(&parse_ip_address, &parse_ip_address), pair(parse_port, parse_port)),
            |((source_address, destination_address), (source_port, destination_port))| {
                ((source_port, source_address).into(), (destination_port, destination_address).into())
            },
        )(input)
    }
}

/// Parse a single TCP port.
fn parse_port(input: &[u8]) -> IResult<&[u8], u16> {
    be_u16(input)
}

/// Parse a 128-bit IPv6 address.
fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], [u16; 8]> {
    map(
        tuple((be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16)),
        |(a, b, c, d, e, f, g, h)| [a, b, c, d, e, f, g, h],
    )(input)
}

/// Take a single byte and extract the protocol version and command.
/// The higher 4 bits are the version.
/// The lowest 4 bits are the command.
fn parse_version_command(input: &[u8]) -> IResult<&[u8], (Version, Command)> {
    alt((
        map(tag(b"\x20"), |_| (Version::Two, Command::Local)),
        map(tag(b"\x21"), |_| (Version::Two, Command::Proxy))
    ))(input)
}

/// Take a single byte and extract the address family and transport protocol.
/// The higher 4 bits are the address family.
/// The lowest 4 bits are the transport protocol.
fn parse_family_protocol(input: &[u8]) -> IResult<&[u8], (AddressFamily, Protocol)> {
    alt((
        map(tag(b"\x00"), |_| (AddressFamily::Unspecified, Protocol::Unspecified)),
        map(tag(b"\x01"), |_| (AddressFamily::Unspecified, Protocol::Stream)),
        map(tag(b"\x02"), |_| (AddressFamily::Unspecified, Protocol::Datagram)),
        map(tag(b"\x10"), |_| (AddressFamily::IPv4, Protocol::Unspecified)),
        map(tag(b"\x11"), |_| (AddressFamily::IPv4, Protocol::Stream)),
        map(tag(b"\x12"), |_| (AddressFamily::IPv4, Protocol::Datagram)),
        map(tag(b"\x20"), |_| (AddressFamily::IPv6, Protocol::Unspecified)),
        map(tag(b"\x21"), |_| (AddressFamily::IPv6, Protocol::Stream)),
        map(tag(b"\x22"), |_| (AddressFamily::IPv6, Protocol::Datagram)),
        map(tag(b"\x30"), |_| (AddressFamily::Unix, Protocol::Unspecified)),
        map(tag(b"\x31"), |_| (AddressFamily::Unix, Protocol::Stream)),
        map(tag(b"\x32"), |_| (AddressFamily::Unix, Protocol::Datagram))
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tlvs() {
        assert_eq!(parse_tlvs(&[][..]), Ok((&[][..], Vec::new())));
    }

    #[test]
    fn parse_proxy() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert_eq!(parse_v2_header(&input[..]), Ok((&[][..], Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Stream,
            vec![],
            (80, [127, 0, 0, 1]).into(),
            (443, [127, 0, 0, 2]).into(),
        ))));
    }

    #[test]
    fn with_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x20);
        input.extend(&[0, 45]);
        input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF1]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(parse_v2_header(&input[..]), Ok((&[][..], Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Unspecified, // TODO: do not assume TCP with IP.
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            (80, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into(),
            (443, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1]).into(),
        ))))
    }

    #[test]
    fn partial_tlv() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 16]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn no_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend(&[0, 0]);
        input.extend(&[0, 80]);

        assert_eq!(parse_v2_header(&input[..]), Ok((&[0, 80][..], Header::new(
            Version::Two,
            Command::Local,
            Protocol::Datagram,
            vec![],
            Address::None,
            Address::None,
        ))));
    }

    #[test]
    fn unspecified_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[0xbb, 1]);

        assert_eq!(parse_v2_header(&input[..]), Ok((&[][..], Header::new(
            Version::Two,
            Command::Local,
            Protocol::Datagram,
            vec![],
            Address::None,
            Address::None,
        ))));
    }

    #[test]
    fn missing_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x20);
        input.push(0x22);
        input.extend(&[0, 0]);
        input.extend(&[0, 80]);

        assert!(parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn wrong_version() {
        let result = parse_v2_header(b"\r\n\r\n\0\r\nQUIT\n\x13\x02\0\x01\xFF");

        assert!(result.is_err());
    }

    #[test]
    fn not_prefixed() {
        let result = parse_v2_header(b"\r\n\r\n\x01\r\nQUIT\n");

        assert!(result.is_err());
    }

    #[test]
    fn incomplete() {
        let bytes = [0x0D, 0x0A, 0x0D, 0x0A, 0x00];
        let result = parse_v2_header(&bytes[..]);

        assert!(result.is_err());
    }
}