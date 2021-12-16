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

const MAX_LENGTH: usize = 107;
const PROTOCOL_PREFIX: &str = "PROXY";
const SEPARATOR: &str = " ";
const TCP4: &str = "TCP4";
const TCP6: &str = "TCP6";
const UNKNOWN_SHORT: &str = "UNKNOWN\r\n";
const UNKNOWN: &str = "UNKNOWN";
const PROTOCOL_SUFFIX: &str = "\r\n";

const INVALID_PROTOCOL: &str = "Header has an invalid protocol.";
const MISSING_PROTOCOL: &str = "Header missing protocol.";
const EMPTY_ADDRESS: &str = "Header missing an expected part of the address.";
const MISSING_NEWLINE: &str = "Header does not end with the string '\\r\\n'.";

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = &'static str;

    fn try_from(header: &'a [u8]) -> Result<Self, Self::Error> {
        Header::try_from(from_utf8(header).map_err(|_| "Header is not valid UTF-8.")?)
    }
}

impl<'a> TryFrom<&'a str> for Header<'a> {
    type Error = &'static str;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        let end = input.find(PROTOCOL_SUFFIX).ok_or(MISSING_NEWLINE)?;
        let header = &input[..end];
        let mut iterator = header.split(SEPARATOR).peekable();

        println!("Header: {:?}", &header[..end]);
        if Some(PROTOCOL_PREFIX) != iterator.next() {
            return Err("Header does not start with the string 'PROXY'.");
        }

        let addresses = match iterator.next() {
            Some(TCP4) => {
                let source_address = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let destination_address = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let source_port = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let destination_port = iterator.next().ok_or(EMPTY_ADDRESS)?;

                Addresses::Tcp4(Tcp {
                    source_address,
                    source_port,
                    destination_address,
                    destination_port,
                })
            }
            Some(TCP6) => {
                let source_address = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let destination_address = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let source_port = iterator.next().ok_or(EMPTY_ADDRESS)?;
                let destination_port = iterator.next().ok_or(EMPTY_ADDRESS)?;

                Addresses::Tcp6(Tcp {
                    source_address,
                    source_port,
                    destination_address,
                    destination_port,
                })
            }
            Some(UNKNOWN) => {
                let rest = match iterator.next() {
                    Some(_) => Some(&header[(PROTOCOL_PREFIX.len() + SEPARATOR.len() + UNKNOWN.len() + SEPARATOR.len())..]),
                    None => None
                };

                Addresses::Unknown(Unknown {
                    rest,
                })
            }
            Some(_) => return Err(INVALID_PROTOCOL),
            None => return Err(MISSING_PROTOCOL),
        };

        Ok(Header {
            header: &input[..end + PROTOCOL_SUFFIX.len()],
            addresses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tcp4() {
        let ip = "255.255.255.255";
        let port = "65535";
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp4(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn valid_tcp4() {
        let ip = "255.255.255.255";
        let port = "65535";
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nFoobar";
        let expected = Header::new("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", Addresses::new_tcp4(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_partial() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535";

        assert_eq!(Header::try_from(text).unwrap_err(), MISSING_NEWLINE);
    }

    #[test]
    fn parse_invalid() {
        let text = "PROXY \r\n";

        assert_eq!(Header::try_from(text).unwrap_err(), MISSING_PROTOCOL);
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
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let port = "65535";
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!";
        let expected = Header::new("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n", Addresses::new_tcp6(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));

        let short_ip = "::1";
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
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let short_ip = "ffff::ffff";
        let port = "65535";
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_single_zero() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let short_ip = "ffff:ffff:ffff:ffff::ffff:ffff:ffff";
        let port = "65535";
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff::ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_wildcard() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let short_ip = "::";
        let port = "65535";
        let text = "PROXY TCP6 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected));
    }

    #[test]
    fn parse_tcp6_implied() {
        let ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let short_ip = "ffff::";
        let port = "65535";
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

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n";

        assert!(Header::try_from(text).is_err());
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

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n";

        assert!(Header::try_from(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n";

        assert!(Header::try_from(text).is_err());
    }
}
