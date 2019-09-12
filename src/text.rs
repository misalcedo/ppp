use nom::{IResult, InputLength};
use nom::bytes;
use nom::bytes::complete::{take_while_m_n, tag};
use nom::character::complete::{digit1, hex_digit1};
use nom::branch::alt;
use crate::model::{Header, Version, Command, Protocol, Address};
use nom::combinator::{map, map_res, verify, map_parser, all_consuming, opt};
use nom::sequence::{terminated, tuple, separated_pair, preceded, pair, delimited};
use nom::bytes::streaming::take_until;
use nom::character::is_hex_digit;
use nom::error::ParseError;
use nom::multi::separated_nonempty_list;

extern crate test;

fn parse_hexadecimal(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while_m_n(4, 4, is_hex_digit), std::str::from_utf8)(input)
}

fn parse_ipv6_group(input: &[u8]) -> IResult<&[u8], Option<u16>> {
    opt(map_res(parse_hexadecimal, |s| u16::from_str_radix(s, 16)))(input)
}

fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], [u16; 8]> {
    map(
        verify(separated_nonempty_list(tag(":"), parse_ipv6_group), |groups: &Vec<Option<u16>>| {
            let all_present = groups.iter().filter(|x| x.is_some()).count() == 8;

            all_present || {
                let bounded_length = groups.len() >= 3 && groups.len() <= 8;
                let no_more_than_one_empty_group = groups.iter().filter(|x| x.is_none()).count() <= 1;
                let starts_with_some = groups[0].is_some();
                let ends_with_some = groups[groups.len() - 1].is_some();

                bounded_length && starts_with_some && ends_with_some && no_more_than_one_empty_group
            }
        }),
        |groups| {
            let mut address: [u16; 8] = [0; 8];
            let mut index = 0;

            groups.iter().for_each(|group| {
                match group {
                    Some(a) => {
                        address[index] = *a;
                        index += 1;
                    }
                    None => {
                        let none_len = 8 - groups.iter().filter(|x| x.is_some()).count();

                        for offset in 0..none_len {
                            address[index + offset] = 0;
                        }

                        index += none_len;
                    }
                }
            });

            address
        },
    )(input)
}

pub fn parse_ip<O, F>(protocol_family: &'static str, parse_ip_address: F) -> impl Fn(&[u8]) -> IResult<&[u8], Header>
    where
        F: Fn(&[u8]) -> IResult<&[u8], O>,
        (u16, O): Into<Address>
{
    move |input: &[u8]| {
        all_consuming(map(preceded(
            terminated(tag(protocol_family), tag(" ")), pair(
                terminated(separated_pair(&parse_ip_address, tag(" "), &parse_ip_address), tag(" ")),
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
}

fn parse_ipv6(input: &[u8]) -> IResult<&[u8], Header> {
    parse_ip("TCP6", parse_ipv6_address)(input)
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
    parse_ip("TCP4", parse_ipv4_address)(input)
}

fn parse_unknown(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        preceded(tag("UNKNOWN"), take_while_m_n(0, 92, |_| true)),
        |_| Header::unknown(),
    )(input)
}

pub fn parse_v1_header(input: &[u8]) -> IResult<&[u8], Header> {
    map_parser(
        delimited(
            pair(bytes::streaming::tag("PROXY"), bytes::streaming::tag(" ")),
            verify(take_until("\r\n"), |i: &[u8]| i.len() < 100),
            bytes::streaming::tag("\r\n"),
        ),
        alt((parse_ipv4, parse_ipv6, parse_unknown)),
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
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some((65535, [0xFFFF, 0, 0, 0, 0, 0, 0, 0xFFFF]).into()),
            Some((65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into()),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_single_zero() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff::ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some((65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0, 0xFFFF, 0xFFFF, 0xFFFF]).into()),
            Some((65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into()),
        );

        assert_eq!(parse_v1_header(text), Ok((&[][..], expected)));
    }

    #[test]
    fn parse_tcp6_wildcard() {
        let text = "PROXY TCP6 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let address: Address = (65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert!(parse_v1_header(text).is_err());
    }

    #[test]
    fn parse_tcp6_implied() {
        let text = "PROXY TCP6 ffff:: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let address: Address = (65535, [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]).into();
        let expected = Header::new(
            Version::One,
            Command::Proxy,
            Some(Protocol::Stream),
            vec![],
            Some(address.clone()),
            Some(address),
        );

        assert!(parse_v1_header(text).is_err());
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
    fn bench_parse_tcp4(b: &mut Bencher) {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        b.iter(|| parse_v1_header(text.as_bytes()).unwrap());
    }

    #[bench]
    fn bench_parse_tcp6(b: &mut Bencher) {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        b.iter(|| parse_v1_header(text.as_bytes()).unwrap());
    }

    #[bench]
    fn bench_parse_tcp6_compact(b: &mut Bencher) {
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        b.iter(|| parse_v1_header(text.as_bytes()).unwrap());
    }
}