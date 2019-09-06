use nom::IResult;
use nom::bytes::complete::*;
use nom::combinator::*;
use nom::character::complete::*;
use nom::sequence::*;

use nom::branch::alt;
use nom::Err::*;
use std::str::{FromStr, from_utf8};
use std::net::IpAddr;

extern crate test;

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

/// Parses a byte array as version 1 of the Proxy Protocol header.
pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, address) = map_res(
        delimited(terminated(tag("PROXY"), tag(" ")), take_until("\r\n"), crlf),
        from_utf8
    )(input)?;

    all_consuming(alt((parse_tcp, parse_unknown)))(address)
        .map(|(_, o)| (input, o))
        .map_err(|e| {
            match e {
                Incomplete(n) => Incomplete(n),
                Failure((i, k)) => Failure((i.as_bytes(), k)), 
                Error((i, k)) => Error((i.as_bytes(), k))
            }
        })
}

fn parse_unknown(input: &str) -> IResult<&str, Header> {
    map(
        preceded(tag("UNKNOWN"), take_while_m_n(0, 92, |_| true)),
        |_| Header::unknown()
    )(input)
}

fn from_decimal(input: &str) -> Result<u16, &'static str> {
    if input.starts_with("0") {
        Err("Number must not start with leading zeroes.")
    } else {
        u16::from_str(input).map_err(|_| "Unable to parse input as u16.")
    }
}

fn parse_u16(input: &str) -> IResult<&str, u16> {
    map_res(
        digit1,
        from_decimal
    )(input)
}

fn parse_until_space(input: &str) -> IResult<&str, IpAddr> {
    map_res(take_until(" "), IpAddr::from_str)(input)
}

fn parse_tcp(input: &str) -> IResult<&str, Header> {
    map(
        tuple((
            map(alt((tag("TCP4"), tag("TCP6"))), String::from),
            preceded(tag(" "), parse_until_space), 
            preceded(tag(" "), parse_until_space),
            preceded(tag(" "), parse_u16),
            preceded(tag(" "), parse_u16)
        )),
        |(protocol_family, source_address, destination_address, source_port, destination_port)| Header::TCP {
            protocol_family,
            source_address,
            source_port,
            destination_address,
            destination_port,
        }
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::Bencher;

    #[test]
    fn proxy() {}

    #[test]
    fn parse_tcp4_connection() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP4"),
            source_address: IpAddr::from_str("255.255.255.255").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("255.255.255.255").unwrap(),
            destination_port: 65535,
        };

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_incomplete() {
        let text = "PROXY \r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_tcp4_invalid() {
        let text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_connection() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            destination_port: 65535,
        };

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_invalid() {
        let text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: IpAddr::from_str("ffff::ffff").unwrap(),
            source_port: 65535,
            destination_address: IpAddr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
            destination_port: 65535,
        };

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_source_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_destination_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_lowercase_proxy() {
        let text = "proxy UNKNOWN\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let text = "PROXY tcp4\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_too_long() {
        let text =  "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space() {
        let text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[bench]
    fn bench_parse(b: &mut Bencher) {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        b.iter(|| parse_header(text.as_bytes()).unwrap());
    }
}