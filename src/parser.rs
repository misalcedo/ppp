
use nom::IResult;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::sequence::*;

use crate::text::Header;

fn parse_unknown(input: &str) -> IResult<&str, Header> {
    let (leftovers, result) = tuple((delimited(tag("PROXY"), tag(" "), tag("UNKNOWN")), take_until("\r\n"), crlf))(input)?;

    Ok((leftovers, Header::unknown()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy() {}

    //#[test]
    fn parse_tcp4() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let expected = Header::TCP {
            protocol_family: String::from("TCP4"),
            source_address: String::from("255.255.255.255"),
            source_port: 65535,
            destination_address: String::from("255.255.255.255"),
            destination_port: 65535
        };

        assert_eq!(parse_unknown(text).unwrap(), ("", expected));
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\n";
        let expected = Header::unknown();

        assert_eq!(parse_unknown(text).unwrap(), ("", expected));
    }

    //#[test]
    fn parse_tcp6() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::TCP {
            protocol_family: String::from("TCP6"),
            source_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            source_port: 65535,
            destination_address: String::from("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            destination_port: 65535
        };

        assert_eq!(parse_unknown(text).unwrap(), ("", expected));
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::unknown();

        assert_eq!(parse_unknown(text).unwrap(), ("", expected));
    }
}