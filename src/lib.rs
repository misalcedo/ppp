#![feature(test)]
//! A Proxy Protocol Parser written in Rust using nom.

use nom::branch::alt;
use nom::IResult;

use crate::binary::parse_v2_header;
use crate::model::Header;
use crate::text::parse_v1_header;

/// Parsers for the binary representation of HAProxy's proxy protocol header.
pub mod binary;

/// Parsers for the text representation of HAProxy's proxy protocol header.
pub mod text;

/// Types representing both text and binary versions of HAProxy's proxy protocol header.
pub mod model;

/// A parser that can handle both version 1 and version 2 of the proxy protocol header.
///
/// # Examples
/// Partial
/// ```rust
/// assert!(ppp::parse_header(b"\r\n").unwrap_err().is_incomplete());
/// ```
///
/// Version 1 TCP4
/// ```rust
/// assert_eq!(ppp::parse_header(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"), Ok((&[][..], ppp::model:: Header::version_1(
///            ([255, 255, 255, 255], 65535).into(),
///            ([255, 255, 255, 255], 65535).into(),
///        ))));
/// ```
///
/// Version 2 TCP over IPv6 with some TLVs
/// ```rust
/// let mut input: Vec<u8> = Vec::new();
///
/// input.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
/// input.push(0x21);
/// input.push(0x21);
/// input.extend(&[0, 45]);
/// input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
/// input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF1]);
/// input.extend(&[0, 80]);
/// input.extend(&[1, 187]);
/// input.extend(&[1, 0, 1, 5]);
/// input.extend(&[2, 0, 2, 5, 5]);
///
/// assert_eq!(ppp::binary::parse_v2_header(&input[..]), Ok((&[][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Proxy,
///     ppp::model::Protocol::Stream,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     ([0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF], 80).into(),
///     ([0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1], 443).into(),
/// ))))
/// ```
pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    alt((parse_v2_header, parse_v1_header))(input)
}
