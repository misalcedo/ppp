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
/// assert!(ppp::text::parse_v1_header(b"\r\n").unwrap_err().is_incomplete());
/// ```
///
/// Version 1 TCP4
/// ```rust
/// assert_eq!(ppp::text::parse_v1_header(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"), Ok((&[][..], ppp::model:: Header::version_1(
///            (65535, [255, 255, 255, 255]).into(),
///            (65535, [255, 255, 255, 255]).into(),
///        ))));
/// ```
pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    alt((parse_v2_header, parse_v1_header))(input)
}