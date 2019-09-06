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

const PREFIX: [u8; 12] = [0x0D , 0x0A , 0x0D , 0x0A , 0x00 , 0x0D , 0x0A , 0x51 , 0x55 , 0x49 , 0x54 , 0x0A];

struct Header {

}

fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    map(tag(PREFIX), |_| Header {})(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn not_prefixed() {
        let result = parse_header(&[0x0D , 0x0A , 0x0D , 0x0A , 0x01 , 0x0D , 0x0A , 0x51 , 0x55 , 0x49 , 0x54 , 0x0A]);

        assert_eq!(result.is_err(), true);
    }
}