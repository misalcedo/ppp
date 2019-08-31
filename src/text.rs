use std::io::Read;
use crate::error::Error;
use crate::error::ErrorKind::*;
use std::net::IpAddr;
use std::str::FromStr;

extern crate test;

trait Parser {
    fn parse(stream: &mut dyn Read) -> Result<Header, Error>;
}

const PROXY: &str = "PROXY";
const CRLF: &str = "\r\n";
const TCP4: &str = "TCP4";
const TCP6: &str = "TCP6";
const UNKNOWN: &str = "UNKNOWN";

#[derive(Debug, Eq, PartialEq)]
pub enum Header {
    TCP {
        protocol_family: String,
        source_address: IpAddr,
        source_port: u16,
        destination_address: IpAddr,
        destination_port: u16
    },
    Unknown
} 

impl Header {
    pub fn unknown() -> Header {
        Header::Unknown {}
    }
}

impl Parser for Header {
    /// See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
    fn parse(stream: &mut dyn Read) -> Result<Header, Error> {
        let mut buffer: [u8; 107] = [0; 107];
        let result = stream.read(&mut buffer)?;
        let header = std::str::from_utf8(&buffer[..result])?;
        let mut parts = header.trim_end_matches(CRLF).split(' ');

        match parts.next() {
            Some("") => Err(Error::from(MissingProxy)),
            Some(part) => {
                println!("Proxy: '{}'", part);
                if PROXY == part {
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
                if TCP4 == part || TCP6 == part || UNKNOWN == part {
                    Ok(part.to_string())
                } else {
                    Err(Error::from(InvalidProtocolFamily))
                }
            },
            None => Err(Error::from(MissingProtocolFamily))
        }?;

        if UNKNOWN == protocol_family {
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

        if source_port.starts_with("0") {
            return Err(Error::from(InvalidPort));
        }

        let destination_port = match parts.next() {
            Some(part) => Ok(part.to_string()),
            None => Err(Error::from(MissingDestinationPort))
        }?;

        if destination_port.starts_with("0") {
            return Err(Error::from(InvalidPort));
        }

        

        if let Some(_) = parts.next() {
            return Err(Error::from(InvalidHeader));
        }


        Ok(Header::TCP {
            protocol_family: protocol_family, 
            source_address: IpAddr::from_str(&source_address)?, 
            source_port: source_port.parse::<u16>()?,
            destination_address: IpAddr::from_str(&destination_address)?, 
            destination_port: destination_port.parse::<u16>()?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

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
        let expected = Header::TCP {
            protocol_family: String::from("TCP4"),
            source_address: IpAddr::from_str("255.255.255.255").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("255.255.255.255").unwrap(),
            destination_port: 65535
        };

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_tcp4_invalid() {
        let mut text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidAddress));
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let mut text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidAddress));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidPort));
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidPort));
    }

    #[test]
    fn parse_tcp6() {
        let mut text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            destination_port: 65535
        };

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_tcp6_invalid() {
        let mut text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidAddress));
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let mut text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidAddress));
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let mut text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: IpAddr::from_str("ffff::ffff").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            destination_port: 65535,
        };

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_source_port_too_large() {
        let mut text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidPort));
    }

    #[test]
    fn parse_destination_port_too_large() {
        let mut text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidPort));
    }

    #[test]
    fn parse_unknown_connection() {
        let mut text = "PROXY UNKNOWN\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(Header::parse(&mut text).unwrap(), expected);
    }

    #[test]
    fn parse_lowercase_proxy() {
        let mut text = "proxy UNKNOWN\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidHeader));
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let mut text = "PROXY tcp4\r\n".as_bytes();

        assert_eq!(Header::parse(&mut text).unwrap_err(), Error::from(InvalidProtocolFamily));
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

    #[bench]
    fn bench_parse(b: &mut Bencher) {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        
        b.iter(|| Header::parse(&mut text.as_bytes()).unwrap());
    }
}
