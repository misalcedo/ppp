use std::io::Read;
use crate::error::Error;
use crate::error::ErrorKind::*;

trait Parser {
    fn parse(stream: &mut dyn Read) -> Result<Header, Error>;
}

const PROXY: &str = "PROXY";
const CRLF: &str = "\r\n";
const TCP4: &str = "TCP4";
const TCP6: &str = "TCP6";
const UNKNOWN: &str = "UNKNOWN";

#[derive(Debug, Eq, PartialEq)]
struct Header {
    protocol_family: String,
    source_address: String,
    source_port: String,
    destination_address: String,
    destination_port: String
}

impl Header {
    fn unknown() -> Header {
        Header {
            protocol_family: String::from("UNKNOWN"),
            source_address: String::from(""),
            source_port: String::from(""),
            destination_address: String::from(""),
            destination_port: String::from("")
        }
    }
}

impl Parser for Header {
    /// See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
    fn parse(stream: &mut dyn Read) -> Result<Header, Error> {
        let mut buffer: [u8; 108] = [0; 108];
        let result = stream.read(&mut buffer)?;
        let header = std::str::from_utf8(&buffer[..result])?;
        let mut parts = header.trim_end_matches(CRLF).split(' ');

        match parts.next() {
            Some("") => Err(Error::from(MissingProxy)),
            Some(part) => {
                println!("Proxy: '{}'", part);
                if PROXY.eq_ignore_ascii_case(part) {
                    Ok(())
                } else {
                    Err(Error::from(InvalidHeader))
                }
            },
            None => Err(Error::from(MissingProxy))
        }?;

        if !header.ends_with(CRLF) {
            return Err(Error::from(MissingCRLF));
        }

        let protocol_family = match parts.next() {
            Some(part) => {
                if TCP4.eq_ignore_ascii_case(part) || TCP6.eq_ignore_ascii_case(part) || UNKNOWN.eq_ignore_ascii_case(part) {
                    Ok(part.to_string())
                } else {
                    Err(Error::from(InvalidProtocolFamily))
                }
            },
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        if UNKNOWN.eq_ignore_ascii_case(&protocol_family) {
            return Ok(Header::unknown())
        }

        let source_address = match parts.next() {
            Some(part) => Ok(part.to_string()),
            None => Err(Error::from(MissingSourceAddress))
        }?;

        let destination_address = match parts.next() {
            Some(part) => Ok(part.to_string()),
            None => Err(Error::from(MissingDestinationAddress))
        }?;

        let source_port = match parts.next() {
            Some(part) => Ok(part.to_string()),
            None => Err(Error::from(MissingSourcePort))
        }?;

        let destination_port = match parts.next() {
            Some(part) => Ok(part.to_string()),
            None => Err(Error::from(MissingDestinationPort))
        }?;

        if let Some(_) = parts.next() {
            return Err(Error::from(InvalidHeader));
        }

        Ok(Header {
            protocol_family: protocol_family.to_string(), 
            source_address: source_address.to_string(), 
            source_port: source_port.to_string(),
            destination_address: destination_address.to_string(), 
            destination_port: destination_port.to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy() {}

    #[test]
    fn parse_empty() {
        let stream: [u8; 0] = [];

        assert_eq!(Header::parse(&mut &stream[..]).unwrap_err(), Error::from(MissingProxy));
    }

    #[test]
    fn parse_tcp4() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let expected = Header {
            protocol_family: String::from("TCP4"),
            source_address: String::from("255.255.255.255"),
            source_port: String::from("65535"),
            destination_address: String::from("255.255.255.255"),
            destination_port: String::from("65535")
        };

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_tcp6() {
        let mut text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header {
            protocol_family: String::from("TCP6"),
            source_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            source_port: String::from("65535"),
            destination_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            destination_port: String::from("65535")
        };

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_unknown_connection() {
        let mut text = "PROXY UNKNOWN\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_worst_case() {
        let mut text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_too_long() {
        let mut text =  "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(MissingCRLF));
    }

    #[test]
    fn parse_more_than_one_space() {
        let mut text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidProtocolFamily));
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let mut text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let mut text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }
}
