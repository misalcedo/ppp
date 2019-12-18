use nom::branch::alt;
use nom::bytes;
use nom::bytes::complete::{tag, take_while_m_n};
use nom::bytes::streaming::take_until;
use nom::character::complete::digit1;
use nom::combinator::{all_consuming, map, map_parser, map_res, verify};
use nom::sequence::{delimited, pair, preceded, terminated, tuple};
use nom::IResult;

use crate::model::*;

/// Parse a text IPv6 address.
fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], [u16; 8]> {
    map_res(map_res(take_until(" "), std::str::from_utf8), |s: &str| {
        let ip: std::net::Ipv6Addr = s.parse()?;
        Ok::<_, std::net::AddrParseError>(ip.segments())
    })(input)
}

/// Parse a header with the TCP protocol and a generic address family.
fn parse_tcp<O, F>(
    protocol_family: &'static str,
    parse_ip_address: F,
) -> impl Fn(&[u8]) -> IResult<&[u8], Header>
where
    F: Fn(&[u8]) -> IResult<&[u8], O>,
    (O, O, u16, u16): Into<Addresses>,
{
    move |input: &[u8]| {
        all_consuming(map(
            preceded(
                terminated(tag(protocol_family), tag(" ")),
                tuple((
                    terminated(&parse_ip_address, tag(" ")),
                    terminated(&parse_ip_address, tag(" ")),
                    terminated(parse_port, tag(" ")),
                    parse_port,
                )),
            ),
            |addresses| Header::version_1(addresses.into()),
        ))(input)
    }
}

/// Parse the a header with TCP protocol and IPv6 address family.
fn parse_tcp6(input: &[u8]) -> IResult<&[u8], Header> {
    parse_tcp("TCP6", parse_ipv6_address)(input)
}

/// Parse a decimal number as a string slice.
fn parse_decimal(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        verify(digit1, |i: &[u8]| i.len() == 1 || i[0] != 48),
        std::str::from_utf8,
    )(input)
}

/// Parse a TCP port.
fn parse_port(input: &[u8]) -> IResult<&[u8], u16> {
    map_res(parse_decimal, |s| s.parse::<u16>())(input)
}

/// Parse a single byte from a text IPv4 address.
fn parse_ipv4_byte(input: &[u8]) -> IResult<&[u8], u8> {
    map_res(parse_decimal, |s| s.parse::<u8>())(input)
}

/// Parse a text IPv4 address.
fn parse_ipv4_address(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    map(
        tuple((
            terminated(parse_ipv4_byte, tag(".")),
            terminated(parse_ipv4_byte, tag(".")),
            terminated(parse_ipv4_byte, tag(".")),
            parse_ipv4_byte,
        )),
        |(a, b, c, d)| [a, b, c, d],
    )(input)
}

/// Parse the a header with TCP protocol and IPv4 address family.
fn parse_tcp4(input: &[u8]) -> IResult<&[u8], Header> {
    parse_tcp("TCP4", parse_ipv4_address)(input)
}

/// Parse the a header with an unknown protocol and address family.
fn parse_unknown(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        preceded(tag("UNKNOWN"), take_while_m_n(0, 92, |_| true)),
        |_| Header::unknown(),
    )(input)
}

/// Parses a version 1 header of HAProxy's proxy protocol.
pub fn parse_v1_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_parser(
        delimited(
            pair(bytes::streaming::tag("PROXY"), bytes::streaming::tag(" ")),
            verify(take_until("\r\n"), |i: &[u8]| i.len() < 100),
            bytes::streaming::tag("\r\n"),
        ),
        alt((parse_tcp4, parse_tcp6, parse_unknown)),
    )(input)
}

/// Generates a `String` representing a valid text header.
/// If the header cannot be represented as a text header, for any reason, returns an `Err`.
/// Potential reasons a header may not be valid include:
/// * Must not have TLVs (Type-Length-Value entries)
/// * Must have a version of One
/// * Source and destination addresses must be None, IPv4 ports, or IPv6 with ports
/// * Transport protocol must be Stream or Unspecified
/// * Command must be Proxy
pub fn to_string(header: Header) -> Result<String, ()> {
    match header {
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: Addresses::IPv4 {
                source_address,
                destination_address,
                source_port: Some(source_port),
                destination_port: Some(destination_port),
            },
            ..
        } => {
            match header.tlvs().next() {
                Some(_) => Err(()),
                None => Ok(format!(
                    "PROXY TCP4 {}.{}.{}.{} {}.{}.{}.{} {} {}\r\n", 
                    source_address[0], source_address[1], source_address[2], source_address[3],
                    destination_address[0], destination_address[1], destination_address[2], destination_address[3],
                    source_port,
                    destination_port
                ))
            }
        },
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: Addresses::IPv6 {
                source_address,
                destination_address,
                source_port: Some(source_port),
                destination_port: Some(destination_port),
            },
            ..
        } => {
            match header.tlvs().next() {
                Some(_) => Err(()),
                None => Ok(format!(
                    "PROXY TCP6 {:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X} {:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X} {} {}\r\n",
                    source_address[0], source_address[1], source_address[2], source_address[3],
                    source_address[4], source_address[5], source_address[6], source_address[7],
                    destination_address[0], destination_address[1], destination_address[2], destination_address[3],
                    destination_address[4], destination_address[5], destination_address[6], destination_address[7],
                    source_port,
                    destination_port
                ))
            }
        },
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            addresses: Addresses::None,
            ..
        } => {
            Ok(String::from("PROXY UNKNOWN\r\n"))
        },
        _ => Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tcp4() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let expected =
            Header::version_1(([255, 255, 255, 255], [255, 255, 255, 255], 65535, 65535).into());

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn valid_tcp4() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nFoobar".as_bytes();
        let expected =
            Header::version_1(([255, 255, 255, 255], [255, 255, 255, 255], 65535, 65535).into());

        assert_eq!(parse_v1_header(text), Ok((&b"Foobar"[..], expected)));
    }

    #[test]
    fn parse_partial() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535".as_bytes();

        assert!(parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_invalid() {
        let text = "PROXY \r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_tcp4_invalid() {
        let text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\nTwo".as_bytes();

        assert_eq!(parse_v1_header(text), Ok((&b"Two"[..], Header::unknown())));
    }

    #[test]
    fn valid_tcp6() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!".as_bytes();
        let expected = Header::version_1(
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&b"Hi!"[..], expected)));

        let text =
            "PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!".as_bytes();
        let expected = Header::version_1(
            (
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&b"Hi!"[..], expected)));
    }

    #[test]
    fn parse_tcp6_invalid() {
        let text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
            .as_bytes();
        let expected = Header::version_1(
            (
                [0xFFFF, 0, 0, 0, 0, 0, 0, 0xFFFF],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_single_zero() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff::ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::version_1(
            (
                [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0xFFFF, 0xFFFF, 0xFFFF],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_wildcard() {
        let text =
            "PROXY TCP6 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        let expected = Header::version_1(
            (
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_implied() {
        let text =
            "PROXY TCP6 ffff:: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        let expected = Header::version_1(
            (
                [0xFFFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                65535,
                65535,
            )
                .into(),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert_eq!(parse_v1_header(text), Ok((&[][..], Header::unknown())));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_source_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_destination_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_lowercase_proxy() {
        let text = "proxy UNKNOWN\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let text = "PROXY tcp4\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_too_long() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space() {
        let text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n".as_bytes();

        assert!(!parse_v1_header(text).unwrap_err().is_incomplete());
    }

    #[test]
    fn tcp6_to_string() {
        let text = "PROXY TCP6 1234:5678:90AB:CDEF:FEDC:BA09:8765:4321 4321:8765:BA09:FEDC:CDEF:90AB:5678:1234 443 65535\r\n";
        let header = Header::version_1(
            (
                [
                    0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321,
                ],
                [
                    0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,
                ],
                443,
                65535,
            )
                .into(),
        );

        assert_eq!(to_string(header), Ok(String::from(text)));
    }

    #[test]
    fn tcp4_to_string() {
        let text = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
        let header = Header::version_1(([127, 0, 1, 2], [192, 168, 1, 101], 80, 443).into());

        assert_eq!(to_string(header), Ok(String::from(text)));
    }

    #[test]
    fn unknown_to_string() {
        let text = "PROXY UNKNOWN\r\n";
        let header = Header::unknown();

        assert_eq!(to_string(header), Ok(String::from(text)));
    }

    #[test]
    fn version_2_to_string() {
        let header = Header::no_address(Version::Two, Command::Proxy, Protocol::Unspecified);

        assert!(to_string(header).is_err());
    }

    #[test]
    fn datagram_to_string() {
        let header = Header::new(
            Version::One,
            Command::Proxy,
            Protocol::Datagram,
            vec![],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
                80,
                443,
            )
                .into(),
        );

        assert!(to_string(header).is_err());
    }

    #[test]
    fn ipv4_tlvs_to_string() {
        let header = Header::new(
            Version::One,
            Command::Proxy,
            Protocol::Stream,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            ([127, 0, 0, 1], [192, 168, 1, 2], 80, 443).into(),
        );

        assert!(to_string(header).is_err());
    }

    #[test]
    fn ipv6_tlvs_to_string() {
        let header = Header::new(
            Version::One,
            Command::Proxy,
            Protocol::Stream,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
                80,
                443,
            )
                .into(),
        );

        assert!(to_string(header).is_err());
    }

    #[test]
    fn local_to_string() {
        let header = Header::new(
            Version::One,
            Command::Local,
            Protocol::Stream,
            vec![],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
                80,
                443,
            )
                .into(),
        );

        assert!(to_string(header).is_err());
    }

    #[test]
    fn ipv4_no_port_to_string() {
        let header = Header::new(
            Version::One,
            Command::Proxy,
            Protocol::Stream,
            vec![],
            ([127, 0, 0, 1], [192, 168, 1, 2]).into(),
        );

        assert!(to_string(header).is_err());
    }

    #[test]
    fn ipv6_no_port_to_string() {
        let header = Header::new(
            Version::One,
            Command::Proxy,
            Protocol::Stream,
            vec![],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
            )
                .into(),
        );

        assert!(to_string(header).is_err());
    }
}
