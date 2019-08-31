use nom::IResult;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::sequence::*;

use crate::text::Header;
use nom::branch::alt;
use nom::number::complete::*;
use nom::combinator::map_res;
use nom::character::is_digit;
use std::str::{FromStr, from_utf8};

extern crate test;

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _) = pair(tag("PROXY"), tag(" "))(input)?;
    let (input, header) = alt((parse_tcp4, parse_unknown))(input)?;

    crlf(input).map(|(i, _)| (i, header))
}

fn parse_unknown(input: &[u8]) -> IResult<&[u8], Header> {
    tuple((tag("UNKNOWN"), take_until("\r\n")))(input)
        .map(|(i, _)| (i, Header::unknown()))
}

fn from_decimal(input: &[u8]) -> Result<u8, &'static str> {
    match from_utf8(input).ok().and_then(|s| u8::from_str(s).ok()) {
        Some(value) => Ok(value),
        None => Err("Unable to parse input as u8.")
    }
}

fn u16_from_decimal(input: &[u8]) -> Result<u16, &'static str> {
    match from_utf8(input).ok() {
        Some(value) => {
            if value.starts_with("0") {
                Err("Port must not start with leading zeroes.")
            } else {
                u16::from_str(value).map_err(|_| "Unable to parse input as u16.")
            }
        },
        None => Err("Unable to parse input as u16.")
    }
}

fn parse_u8(input: &[u8]) -> IResult<&[u8], u8> {
    map_res(
        take_while_m_n(1, 3, is_digit),
        from_decimal
    )(input)
}

fn parse_u16(input: &[u8]) -> IResult<&[u8], u16> {
    map_res(
        take_while_m_n(1, 5, is_digit),
        u16_from_decimal
    )(input)
}

fn parse_ipv4_part(input: &[u8]) -> IResult<&[u8], u8> {
    preceded(tag("."), parse_u8)(input)
}

fn parse_until_space(input: &[u8]) -> IResult<&[u8], String> {
    map_res(take_until(" "), |i| from_utf8(i).map(String::from))(input)
}

fn parse_ipv4(input: &[u8]) -> IResult<&[u8], String> {
    tuple((parse_u8, parse_ipv4_part, parse_ipv4_part, parse_ipv4_part))(input)
        .map(|(i, o)| (i, format!("{}.{}.{}.{}", o.0, o.1, o.2, o.3)))
}


fn parse_ports(input: &[u8]) -> IResult<&[u8], (u16, u16)> {
    separated_pair(parse_u16, tag(" "), parse_u16)(input)
}

fn parse_tcp4(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _) = pair(tag("TCP4"), tag(" "))(input)?;
    let (input, (source_address, destination_address)) = separated_pair(parse_until_space, tag(" "), parse_until_space)(input)?;
    let (input, (source_port, destination_port)) = preceded(tag(" "), parse_ports)(input)?;

    Ok((input, Header::TCP {
        protocol_family: String::from("TCP4"),
        source_address,
        source_port,
        destination_address,
        destination_port,
    }))
}

fn parse_tcp6(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _) = pair(tag("TCP6"), tag(" "))(input)?;
    let (input, (source_address, destination_address)) = separated_pair(parse_until_space, tag(" "), parse_until_space)(input)?;
    let (input, (source_port, destination_port)) = preceded(tag(" "), parse_ports)(input)?;

    Ok((input, Header::TCP {
        protocol_family: String::from("TCP6"),
        source_address,
        source_port,
        destination_address,
        destination_port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test::Bencher;

    #[test]
    fn proxy() {}

    #[test]
    fn parse_tcp4() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP4"),
            source_address: String::from("255.255.255.255"),
            source_port: 65535,
            destination_address: String::from("255.255.255.255"),
            destination_port: 65535,
        };

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let mut text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n".as_bytes();

        assert!(parse_header(text).is_err());
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_tcp6() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            source_port: 65535,
            destination_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            destination_port: 65535,
        };

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n".as_bytes();
        let expected = Header::unknown();

        assert_eq!(parse_header(text).unwrap(), (&[][..], expected));
    }

    #[bench]
    fn bench_parse(b: &mut Bencher) {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        b.iter(|| parse_header(text.as_bytes()).unwrap());
    }
}