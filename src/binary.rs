use std::convert::TryFrom;

use nom::branch::alt;
use nom::bytes::streaming::*;
use nom::combinator::*;
use nom::multi::{count, fold_many0, fold_many_m_n};
use nom::number;
use nom::number::streaming::*;
use nom::sequence::*;
use nom::IResult;

use crate::model::{Addresses, Command, Header, Protocol, Tlv, Version};

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
type OptionalHeader = (Addresses, Vec<Tlv>);

/// Parse the first 16 bytes of the protocol header; the only required payload.
/// The 12 byte signature and 4 bytes used to describe the connection and header information.
pub fn parse_v2_header(input: &[u8]) -> IResult<&[u8], Header> {
    flat_map(parse_required_header, parse_full_header)(input)
}

/// Parse the entire header, required an optional parts.
fn parse_full_header(required_header: RequiredHeader) -> impl Fn(&[u8]) -> IResult<&[u8], Header> {
    move |input: &[u8]| {
        let ((version, command), (address_family, protocol), address_length) = required_header;

        map(
            parse_optional_header(protocol, address_family, address_length),
            move |(addresses, tlvs)| Header::new(version, command, protocol, tlvs, addresses),
        )(input)
    }
}

/// Parse the required portion of the header.
fn parse_required_header(input: &[u8]) -> IResult<&[u8], RequiredHeader> {
    preceded(
        tag(PREFIX),
        tuple((parse_version_command, parse_family_protocol, be_u16)),
    )(input)
}

/// Parse the optional extra bytes after the required portion of the header.
fn parse_optional_header(
    protocol: Protocol,
    address_family: AddressFamily,
    address_length: u16,
) -> impl Fn(&[u8]) -> IResult<&[u8], OptionalHeader> {
    move |input: &[u8]| {
        let (input, address) = take(address_length)(input)?;
        let (_, optional_header) = all_consuming(pair(
            parse_addresses(protocol, address_family, address_length),
            parse_tlvs,
        ))(address)?;

        Ok((input, optional_header))
    }
}

/// Create a parser that parses addresses from the input depending on the address family and address length.
fn parse_addresses(
    protocol: Protocol,
    address_family: AddressFamily,
    address_length: u16,
) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses> {
    move |input: &[u8]| match address_family {
        AddressFamily::IPv4 => parse_ip_address_pair(protocol, parse_ipv4_address)(input),
        AddressFamily::IPv6 => parse_ip_address_pair(protocol, parse_ipv6_address)(input),
        AddressFamily::Unix => parse_unix_address_pairs(input),
        AddressFamily::Unspecified => parse_unspecified(address_length)(input),
    }
}

/// Consume the specified bytes from the input, ignoring all consumed bytes.
fn parse_unspecified(address_length: u16) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses> {
    move |input: &[u8]| map(take(address_length), |_| Addresses::None)(input)
}

/// Parses multiple Type-Length-Value records.
fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Tlv>> {
    fold_many0(parse_tlv, Vec::new(), |mut acc: Vec<Tlv>, tlv| {
        acc.push(tlv);
        acc
    })(input)
}

/// Parses a single Type-Length-Value record.
fn parse_tlv(input: &[u8]) -> IResult<&[u8], Tlv> {
    map(
        tuple((
            number::complete::be_u8,
            flat_map(map_res(number::complete::be_u16, usize::try_from), |l| {
                count(number::complete::be_u8, l)
            }),
        )),
        |(value_type, value)| Tlv::new(value_type, value),
    )(input)
}

/// Parse a Unix address path of 108 bytes.
fn parse_unix_address(input: &[u8]) -> IResult<&[u8], [u32; 27]> {
    map(
        fold_many_m_n(
            27,
            27,
            be_u32,
            ([0; 27], 0),
            |acc: ([u32; 27], usize), item| {
                let (mut array, index) = acc;

                array[index] = item;

                (array, index + 1)
            },
        ),
        |(array, _)| array,
    )(input)
}

/// Parse a pair of Unix address paths.
fn parse_unix_address_pairs(input: &[u8]) -> IResult<&[u8], Addresses> {
    map(
        pair(parse_unix_address, parse_unix_address),
        Addresses::from,
    )(input)
}

/// Parse a 32-bit IPv4 address.
fn parse_ipv4_address(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    map(tuple((be_u8, be_u8, be_u8, be_u8)), |(a, b, c, d)| {
        [a, b, c, d]
    })(input)
}

/// Parse a source and destination address.
fn parse_ip_address_pair<O, F>(
    protocol: Protocol,
    parse_ip_address: F,
) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses>
where
    F: Fn(&[u8]) -> IResult<&[u8], O>,
    (O, O): Into<Addresses>,
    (O, O, u16, u16): Into<Addresses>,
{
    move |input: &[u8]| match protocol {
        Protocol::Unspecified => parse_ip_address_pair_without_port(&parse_ip_address)(input),
        _ => parse_ip_address_pair_with_port(&parse_ip_address)(input),
    }
}

/// Parses a pair of IP addresses without ports.
fn parse_ip_address_pair_without_port<F, O>(
    parse_ip_address: F,
) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses>
where
    F: Fn(&[u8]) -> IResult<&[u8], O>,
    (O, O): Into<Addresses>,
{
    move |input: &[u8]| {
        map(pair(&parse_ip_address, &parse_ip_address), |addresses| {
            addresses.into()
        })(input)
    }
}

/// Parses a pair of IP addresses with ports.
fn parse_ip_address_pair_with_port<F, O>(
    parse_ip_address: F,
) -> impl Fn(&[u8]) -> IResult<&[u8], Addresses>
where
    F: Fn(&[u8]) -> IResult<&[u8], O>,
    (O, O, u16, u16): Into<Addresses>,
{
    move |input: &[u8]| {
        map(
            tuple((&parse_ip_address, &parse_ip_address, parse_port, parse_port)),
            |addresses| addresses.into(),
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
        tuple((
            be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16, be_u16,
        )),
        |(a, b, c, d, e, f, g, h)| [a, b, c, d, e, f, g, h],
    )(input)
}

/// Take a single byte and extract the protocol version and command.
/// The higher 4 bits are the version.
/// The lowest 4 bits are the command.
fn parse_version_command(input: &[u8]) -> IResult<&[u8], (Version, Command)> {
    alt((
        map(tag(b"\x20"), |_| (Version::Two, Command::Local)),
        map(tag(b"\x21"), |_| (Version::Two, Command::Proxy)),
    ))(input)
}

/// Take a single byte and extract the address family and transport protocol.
/// The higher 4 bits are the address family.
/// The lowest 4 bits are the transport protocol.
fn parse_family_protocol(input: &[u8]) -> IResult<&[u8], (AddressFamily, Protocol)> {
    alt((
        map(tag(b"\x00"), |_| {
            (AddressFamily::Unspecified, Protocol::Unspecified)
        }),
        map(tag(b"\x01"), |_| {
            (AddressFamily::Unspecified, Protocol::Stream)
        }),
        map(tag(b"\x02"), |_| {
            (AddressFamily::Unspecified, Protocol::Datagram)
        }),
        map(tag(b"\x10"), |_| {
            (AddressFamily::IPv4, Protocol::Unspecified)
        }),
        map(tag(b"\x11"), |_| (AddressFamily::IPv4, Protocol::Stream)),
        map(tag(b"\x12"), |_| (AddressFamily::IPv4, Protocol::Datagram)),
        map(tag(b"\x20"), |_| {
            (AddressFamily::IPv6, Protocol::Unspecified)
        }),
        map(tag(b"\x21"), |_| (AddressFamily::IPv6, Protocol::Stream)),
        map(tag(b"\x22"), |_| (AddressFamily::IPv6, Protocol::Datagram)),
        map(tag(b"\x30"), |_| {
            (AddressFamily::Unix, Protocol::Unspecified)
        }),
        map(tag(b"\x31"), |_| (AddressFamily::Unix, Protocol::Stream)),
        map(tag(b"\x32"), |_| (AddressFamily::Unix, Protocol::Datagram)),
    ))(input)
}

/// Convert a version 2 header into a vector of bytes.
/// Version one headers return an error result.
pub fn to_bytes(header: Header) -> Result<Vec<u8>, ()> {
    match header {
        Header {
            version: Version::One,
            ..
        } => Err(()),
        Header {
            version,
            command,
            protocol,
            addresses:
                Addresses::IPv4 {
                    source_address,
                    destination_address,
                    source_port: Some(source_port),
                    destination_port: Some(destination_port),
                },
            ..
        } => {
            let tlv_size: usize = header.tlvs().map(|tlv| 3 + tlv.len()).sum();
            let address_length = 12 + tlv_size;
            let mut buffer = Vec::with_capacity(PREFIX.len() + 4 + address_length);

            let version_command_byte = ((version as u8) << 4) | (command as u8);
            let address_protocol_byte = (1 << 4) | (protocol as u8);

            buffer.extend_from_slice(PREFIX);
            buffer.push(version_command_byte);
            buffer.push(address_protocol_byte);
            buffer.extend_from_slice(&(address_length as u16).to_be_bytes()[..]);

            buffer.extend_from_slice(&source_address[..]);
            buffer.extend_from_slice(&destination_address[..]);
            buffer.extend_from_slice(&source_port.to_be_bytes()[..]);
            buffer.extend_from_slice(&destination_port.to_be_bytes()[..]);

            for tlv in header.tlvs() {
                buffer.push(tlv.value_type());
                buffer.extend_from_slice(&(tlv.len() as u16).to_be_bytes()[..]);
                buffer.extend_from_slice(tlv.value());
            }

            Ok(buffer)
        }
        Header {
            version,
            command,
            protocol,
            addresses:
                Addresses::IPv6 {
                    source_address,
                    destination_address,
                    source_port: Some(source_port),
                    destination_port: Some(destination_port),
                },
            ..
        } => {
            let tlv_size: usize = header.tlvs().map(|tlv| 3 + tlv.len()).sum();
            let address_length = 36 + tlv_size;
            let mut buffer = Vec::with_capacity(PREFIX.len() + 4 + address_length);

            let version_command_byte = ((version as u8) << 4) | (command as u8);
            let address_protocol_byte = (2 << 4) | (protocol as u8);

            buffer.extend_from_slice(PREFIX);
            buffer.push(version_command_byte);
            buffer.push(address_protocol_byte);
            buffer.extend_from_slice(&(address_length as u16).to_be_bytes()[..]);

            for byte in source_address.iter() {
                buffer.extend_from_slice(&byte.to_be_bytes()[..]);
            }

            for byte in destination_address.iter() {
                buffer.extend_from_slice(&byte.to_be_bytes()[..]);
            }

            buffer.extend_from_slice(&source_port.to_be_bytes()[..]);
            buffer.extend_from_slice(&destination_port.to_be_bytes()[..]);

            for tlv in header.tlvs() {
                buffer.push(tlv.value_type());
                buffer.extend_from_slice(&(tlv.len() as u16).to_be_bytes()[..]);
                buffer.extend_from_slice(tlv.value());
            }

            Ok(buffer)
        }
        Header {
            version,
            command,
            protocol,
            addresses:
                Addresses::Unix {
                    ref source_address,
                    ref destination_address,
                },
            ..
        } => {
            let tlv_size: usize = header.tlvs().map(|tlv| 3 + tlv.len()).sum();
            let address_length = 216 + tlv_size;
            let mut buffer = Vec::with_capacity(PREFIX.len() + 4 + address_length);

            let version_command_byte = ((version as u8) << 4) | (command as u8);
            let address_protocol_byte = (3 << 4) | (protocol as u8);

            buffer.extend_from_slice(PREFIX);
            buffer.push(version_command_byte);
            buffer.push(address_protocol_byte);
            buffer.extend_from_slice(&(address_length as u16).to_be_bytes()[..]);

            for byte in source_address.iter() {
                buffer.extend_from_slice(&byte.to_be_bytes()[..]);
            }

            for byte in destination_address.iter() {
                buffer.extend_from_slice(&byte.to_be_bytes()[..]);
            }

            for tlv in header.tlvs() {
                buffer.push(tlv.value_type());
                buffer.extend_from_slice(&(tlv.len() as u16).to_be_bytes()[..]);
                buffer.extend_from_slice(tlv.value());
            }

            Ok(buffer)
        }
        Header {
            version,
            command,
            protocol,
            addresses: Addresses::None,
            ..
        } => {
            let mut buffer = Vec::with_capacity(PREFIX.len() + 4);

            let version_command_byte = ((version as u8) << 4) | (command as u8);
            let address_protocol_byte = protocol as u8;

            buffer.extend_from_slice(PREFIX);
            buffer.push(version_command_byte);
            buffer.push(address_protocol_byte);
            buffer.push(0);
            buffer.push(0);

            Ok(buffer)
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
                )
            ))
        );
    }

    #[test]
    fn no_tlvs_unspec() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x00);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![],
                    Addresses::None,
                )
            ))
        );
    }

    #[test]
    fn no_tlvs_unspec_stream() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x01);
        input.extend(&[0, 8]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    Addresses::None,
                )
            ))
        );
    }

    #[test]
    fn no_tlvs_unspec_ipv4() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x10);
        input.extend(&[0, 8]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2]).into(),
                )
            ))
        );
    }

    #[test]
    fn invalid_version() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x11);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert!(!parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn invalid_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x51);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert!(!parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn invalid_command() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x23);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert!(!parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn invalid_protocol() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x20);
        input.push(0x17);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        assert!(!parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn proxy_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[42]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[42][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
                )
            ))
        );
    }

    #[test]
    fn with_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend(&[0, 45]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF2],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
                        80,
                        443
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn tlvs_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend(&[0, 45]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[2, 0, 2, 5, 5][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
                        80,
                        443
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn unix_tlvs_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x30);
        input.extend(&[0, 225]);
        input.extend(&[0xFFu8; 108][..]);
        input.extend(&[0xAAu8; 108][..]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[2, 0, 2, 5, 5][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    ([0xFFFFFFFFu32; 27], [0xAAAAAAAAu32; 27]).into(),
                )
            ))
        )
    }

    #[test]
    fn with_tlvs_without_ports() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x20);
        input.extend(&[0, 41]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1]
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn partial_tlv() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 15]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(!parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn missing_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PREFIX.len());

        input.extend_from_slice(PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 17]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(parse_v2_header(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn partial_address() {
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

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[0, 80][..],
                Header::new(
                    Version::Two,
                    Command::Local,
                    Protocol::Datagram,
                    vec![],
                    Addresses::None,
                )
            ))
        );
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

        assert_eq!(
            parse_v2_header(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Local,
                    Protocol::Datagram,
                    vec![],
                    Addresses::None,
                )
            ))
        );
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
    fn not_prefixed() {
        let result = parse_v2_header(b"\r\n\r\n\x01\r\nQUIT\n");

        assert!(!result.unwrap_err().is_incomplete());
    }

    #[test]
    fn incomplete() {
        let bytes = [0x0D, 0x0A, 0x0D, 0x0A, 0x00];
        let result = parse_v2_header(&bytes[..]);

        assert!(result.unwrap_err().is_incomplete());
    }

    #[test]
    fn to_bytes_ipv4_without_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Stream,
            vec![],
            ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PREFIX.len());

        output.extend_from_slice(PREFIX);
        output.push(0x21);
        output.push(0x11);
        output.extend(&[0, 12]);
        output.extend(&[127, 0, 0, 1]);
        output.extend(&[127, 0, 0, 2]);
        output.extend(&[0, 80]);
        output.extend(&[1, 187]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_unspec() {
        let header = Header::new(
            Version::Two,
            Command::Local,
            Protocol::Unspecified,
            vec![],
            Addresses::None,
        );
        let mut output: Vec<u8> = Vec::with_capacity(PREFIX.len());

        output.extend_from_slice(PREFIX);
        output.push(0x20);
        output.push(0x00);
        output.extend(&[0, 0]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_unix_with_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Unspecified,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            ([0xFFFFFFFFu32; 27], [0xAAAAAAAAu32; 27]).into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PREFIX.len());

        output.extend_from_slice(PREFIX);
        output.push(0x21);
        output.push(0x30);
        output.extend(&[0, 225]);
        output.extend(&[0xFFu8; 108][..]);
        output.extend(&[0xAAu8; 108][..]);
        output.extend(&[1, 0, 1, 5]);
        output.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_ipv6_with_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Stream,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF2,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
                80,
                443,
            )
                .into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PREFIX.len());

        output.extend_from_slice(PREFIX);
        output.push(0x21);
        output.push(0x21);
        output.extend(&[0, 45]);
        output.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ]);
        output.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        output.extend(&[0, 80]);
        output.extend(&[1, 187]);
        output.extend(&[1, 0, 1, 5]);
        output.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_verion_one() {
        let header = Header::unknown();
        assert!(to_bytes(header).is_err());
    }
}
