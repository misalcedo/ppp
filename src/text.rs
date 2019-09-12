use nom::IResult;
use nom::bytes;
use nom::bytes::complete::{take_while_m_n, tag};
use nom::character::complete::{digit1, hex_digit1};
use nom::branch::alt;
use crate::model::{Header, Version, Command, Protocol, Address};
use nom::combinator::{map, map_res, verify, map_parser, all_consuming};
use nom::sequence::{terminated, tuple, separated_pair, preceded, pair, delimited};
use nom::bytes::streaming::take_until;

extern crate test;

fn parse_hexadecimal(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(hex_digit1, std::str::from_utf8)(input)
}

fn parse_ipv6_group(input: &[u8]) -> IResult<&[u8], u16> {
    map_res(parse_hexadecimal, |s| s.parse::<u16>())(input)
}

fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], [u16; 8]> {
    map(
        tuple((
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            terminated(parse_ipv6_group, tag(":")),
            parse_ipv6_group
        )),
        |(a, b, c, d, e, f, g, h)| [a, b, c, d, e, f, g, h],
    )(input)
}

fn parse_decimal(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        verify(digit1, |i: &[u8]| i.len() == 1 || i[0] != 48),
        std::str::from_utf8,
    )(input)
}

fn parse_port(input: &[u8]) -> IResult<&[u8], u16> {
    map_res(parse_decimal, |s| s.parse::<u16>())(input)
}


fn parse_ipv4_byte(input: &[u8]) -> IResult<&[u8], u8> {
    map_res(parse_decimal, |s| s.parse::<u8>())(input)
}

fn parse_ipv4_address(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    map(
        tuple((
            terminated(parse_ipv4_byte, tag(".")),
            terminated(parse_ipv4_byte, tag(".")),
            terminated(parse_ipv4_byte, tag(".")),
            parse_ipv4_byte
        )),
        |(a, b, c, d)| [a, b, c, d],
    )(input)
}

fn parse_ipv4(input: &[u8]) -> IResult<&[u8], Header> {
    all_consuming(map(preceded(
        terminated(tag("TCP4"), tag(" ")), pair(
            terminated(separated_pair(parse_ipv4_address, tag(" "), parse_ipv4_address), tag(" ")),
            separated_pair(parse_port, tag(" "), parse_port),
        ),
    ),
                      |((source_address, destination_address), (source_port, destination_port))| {
                          Header::new(
                              Version::One,
                              Command::Proxy,
                              Some(Protocol::Stream),
                              vec![],
                              Some((source_port, source_address).into()),
                              Some((source_port, destination_address).into()),
                          )
                      },
    ))(input)
}

fn parse_unknown(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        preceded(tag("UNKNOWN"), take_while_m_n(0, 92, |_| true)),
        |_| Header::unknown(),
    )(input)
}

fn parse_v1_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_parser(
        delimited(
            pair(bytes::streaming::tag("PROXY"), bytes::streaming::tag(" ")),
            verify(take_until("\r\n"), |i: &[u8]| i.len() < 100),
            bytes::streaming::tag("\r\n"),
        ),
        alt((parse_unknown, parse_ipv4)),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::Bencher;
    use crate::model::Address;

    #[test]
    fn parse_tcp4_connection() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let address: Address = (65535, [255, 255, 255, 255]).into();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
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

        assert_eq!(parse_v1_header(text), Ok((&[][..], Header::unknown())));
    }

    #[test]
    fn parse_tcp6_connection() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let address: Address = (65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
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
        let address: Address = (65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();

        assert_eq!(parse_v1_header(text), Ok((&[][..], Header::unknown())));
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