use nom::IResult;
use nom::bytes::streaming::*;
use nom::combinator::*;
use nom::character::streaming::*;
use nom::sequence::*;

use nom::branch::alt;
use nom::Err::*;
use std::str::{FromStr, from_utf8};
use std::net::IpAddr;
use crate::model::{Header, Version, Command, Protocol, Tlv};

extern crate test;

fn parse_v1_header(input: &[u8]) -> IResult<&[u8], Header> {
    Ok((&[][..], Header::unknown()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::Bencher;
    use crate::model::Address;

    #[test]
    fn parse_tcp4_connection() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let address = Address::new_ip(65535, &[255, 255, 255, 255][..]).unwrap();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_incomplete() {
        let text = "PROXY \r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_tcp4_invalid() {
        let text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_v1_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_connection() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let address = Address::new_ip(65535, &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255][..]).unwrap();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_invalid() {
        let text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let address = Address::new_ip(65535, &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255][..]).unwrap();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_v1_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_source_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_destination_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_lowercase_proxy() {
        let text = "proxy UNKNOWN\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let text = "PROXY tcp4\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_too_long() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space() {
        let text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[bench]
    fn bench_parse(b: &mut Bencher) {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        b.iter(|| parse_v1_header(text.as_bytes()).unwrap());
    }
}