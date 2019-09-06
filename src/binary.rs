use nom::IResult;
use nom::bytes::complete::*;
use nom::number::complete::*;
use nom::combinator::*;
use nom::sequence::*;

extern crate test;

const PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Debug, Eq, PartialEq)]
struct Header {
    version_and_command: u8,
    protocol_and_address_family: u8,
    address_size: u16
}

impl Header {
    fn new(version_and_command: u8, protocol_and_address_family: u8, address_size: u16) -> Header {
        Header { version_and_command, protocol_and_address_family, address_size }
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        preceded(tag(PREFIX), tuple((be_u8, be_u8, be_u16))),
        |(x, y, z)| Header::new(x, y, z)
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_address() {
        let result = parse_header(b"\r\n\r\n\0\r\nQUIT\n\x03\x02\0\x01");

        assert_eq!(result, Ok((&[][..], Header::new(0x3, 0x2, 1u16))));
    }

    #[test]
    fn not_prefixed() {
        let result = parse_header(b"\r\n\r\n\x01\r\nQUIT\n");

        assert!(result.is_err());
    }

    #[test]
    fn incomplete() {
        let bytes = [0x0D, 0x0A, 0x0D, 0x0A, 0x00];
        let result = parse_header(&bytes[..]);

        assert!(result.is_err());
    }
}