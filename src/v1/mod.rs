//! Version 1 of the HAProxy protocol (text version).
//!
//! See <haproxy.org/download/1.8/doc/proxy-protocol.txt>

mod borrowed;
mod error;

pub use borrowed::{Addresses, Header, Tcp4, Tcp6, Unknown};
pub use error::{BinaryParseError, ParseError};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::from_utf8;

const MAX_LENGTH: usize = 107;
const ZERO: &str = "0";
const PROTOCOL_PREFIX: &str = "PROXY";
const SEPARATOR: &str = " ";
const TCP4: &str = "TCP4";
const TCP6: &str = "TCP6";
const UNKNOWN: &str = "UNKNOWN";
const PROTOCOL_SUFFIX: &str = "\r\n";

impl<'a> TryFrom<&'a str> for Header<'a> {
    type Error = ParseError<'a>;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        let end = input
            .find(PROTOCOL_SUFFIX)
            .ok_or(ParseError::MissingNewLine)?;
        let length = end + PROTOCOL_SUFFIX.len();

        if length > MAX_LENGTH {
            return Err(ParseError::HeaderTooLong);
        }

        let header = &input[..end];
        let mut iterator = header.split(SEPARATOR).peekable();

        if Some(PROTOCOL_PREFIX) != iterator.next() {
            return Err(ParseError::MissingPrefix);
        }

        let addresses = match iterator.next() {
            Some(TCP4) => {
                let source_address = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let destination_address = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let source_port = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let destination_port = iterator.next().ok_or(ParseError::EmptyAddresses)?;

                let source_address = source_address
                    .parse::<Ipv4Addr>()
                    .map_err(ParseError::InvalidSourceAddress)?;
                let destination_address = destination_address
                    .parse::<Ipv4Addr>()
                    .map_err(ParseError::InvalidDestinationAddress)?;

                if source_port.starts_with(ZERO) && source_port != ZERO {
                    return Err(ParseError::InvalidSourcePort(None));
                }

                let source_port = source_port
                    .parse::<u16>()
                    .map_err(|e| ParseError::InvalidSourcePort(Some(e)))?;

                if destination_port.starts_with(ZERO) && destination_port != ZERO {
                    return Err(ParseError::InvalidDestinationPort(None));
                }

                let destination_port = destination_port
                    .parse::<u16>()
                    .map_err(|e| ParseError::InvalidDestinationPort(Some(e)))?;

                Addresses::Tcp4(Tcp4 {
                    source: SocketAddrV4::new(source_address, source_port),
                    destination: SocketAddrV4::new(destination_address, destination_port),
                })
            }
            Some(TCP6) => {
                let source_address = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let destination_address = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let source_port = iterator.next().ok_or(ParseError::EmptyAddresses)?;
                let destination_port = iterator.next().ok_or(ParseError::EmptyAddresses)?;

                let source_address = source_address
                    .parse::<Ipv6Addr>()
                    .map_err(ParseError::InvalidSourceAddress)?;
                let destination_address = destination_address
                    .parse::<Ipv6Addr>()
                    .map_err(ParseError::InvalidDestinationAddress)?;

                if source_port.starts_with(ZERO) && source_port != ZERO {
                    return Err(ParseError::InvalidSourcePort(None));
                }

                let source_port = source_port
                    .parse::<u16>()
                    .map_err(|e| ParseError::InvalidSourcePort(Some(e)))?;

                if destination_port.starts_with(ZERO) && destination_port != ZERO {
                    return Err(ParseError::InvalidDestinationPort(None));
                }

                let destination_port = destination_port
                    .parse::<u16>()
                    .map_err(|e| ParseError::InvalidDestinationPort(Some(e)))?;

                Addresses::Tcp6(Tcp6 {
                    source: SocketAddrV6::new(source_address, source_port, 0, 0),
                    destination: SocketAddrV6::new(destination_address, destination_port, 0, 0),
                })
            }
            Some(UNKNOWN) => {
                let start =
                    PROTOCOL_PREFIX.len() + SEPARATOR.len() + UNKNOWN.len() + SEPARATOR.len();
                let rest = match iterator.next() {
                    Some(_) => Some(&header[start..]),
                    None => None,
                };

                while iterator.next().is_some() {}

                Addresses::Unknown(Unknown { rest })
            }
            Some(protocol) if !protocol.is_empty() => {
                return Err(ParseError::InvalidProtocol(protocol))
            }
            _ => return Err(ParseError::MissingProtocol),
        };

        if iterator.peek().is_some() {
            return Err(ParseError::UnexpectedCharacters);
        }

        Ok(Header {
            header: &input[..length],
            addresses,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = BinaryParseError<'a>;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        let end = input
            .windows(PROTOCOL_SUFFIX.len())
            .position(|window| window == PROTOCOL_SUFFIX.as_bytes())
            .ok_or(ParseError::MissingNewLine)
            .map_err(BinaryParseError::Parse)?;
        let length = end + PROTOCOL_SUFFIX.len();
        let header = from_utf8(&input[..length])?;

        Header::try_from(header).map_err(BinaryParseError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tcp4() {
        let ip = "255.255.255.255".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp4(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn valid_tcp4() {
        let ip = "255.255.255.255".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nFoobar";
        let expected = Header::new(
            "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
            Addresses::new_tcp4(ip, ip, port, port),
        );

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_partial() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535";

        assert_eq!(
            Header::try_from(text).unwrap_err(),
            ParseError::MissingNewLine
        );
    }

    #[test]
    fn parse_invalid() {
        let text = "PROXY \r\n";

        assert_eq!(
            Header::try_from(text).unwrap_err(),
            ParseError::MissingProtocol
        );
    }

    #[test]
    fn parse_tcp4_invalid() {
        let text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n";

        assert!(!Header::try_from(text).is_err());
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\nTwo";

        assert_eq!(
            Header::try_from(text),
            Ok(Header::new("PROXY UNKNOWN\r\n", Addresses::default()))
        );
    }

    #[test]
    fn valid_tcp6() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!";
        let expected = Header::new("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n", Addresses::new_tcp6(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));

        let short_ip = "::1".parse().unwrap();
        let text = "PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!";
        let expected = Header::new(
            "PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            Addresses::new_tcp6(short_ip, ip, port, port),
        );

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_invalid() {
        let text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff::ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_single_zero() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff:ffff:ffff:ffff::ffff:ffff:ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff::ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_wildcard() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "::".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_implied() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff::".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_unknown("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535"));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourcePort(None))
        );
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationPort(None))
        );
    }

    #[test]
    fn parse_source_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_destination_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_lowercase_proxy() {
        let text = "proxy UNKNOWN\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let text = "PROXY tcp4\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_too_long() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space() {
        let text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::MissingProtocol));
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourceAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourcePort(Some(
                "".parse::<u16>().unwrap_err()
            )))
        );
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationPort(Some(
                "".parse::<u16>().unwrap_err()
            )))
        );
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::UnexpectedCharacters)
        );
    }
}
