//! A Proxy Protocol Parser written in Rust using nom.
//! Supports both text and binary versions of the header.
//! A general function is provided to parse either version using a single call.
//! When using the general function, performance depends almost entirely on the type of header.

use nom::branch::alt;

use crate::error::ParseError;
use crate::model::ParseResult;

/// Parsers for the binary representation of HAProxy's proxy protocol header.
mod binary;

/// Parsers for the text representation of HAProxy's proxy protocol header.
mod text;

/// Types representing both text and binary versions of HAProxy's proxy protocol header.
pub mod model;

/// The error type used by the parsers.
pub mod error;

/// Parses a version 1 header of HAProxy's proxy protocol.
/// Supports TCP with IPv4 and IPv6 addresses, as well as UNKNOWN address information.
///
/// # Examples
/// Partial
/// ```rust
/// assert!(ppp::parse_v1_header(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535").unwrap_err().is_incomplete());
/// ```
///
/// Unknown
/// ```rust
/// assert_eq!(ppp::parse_v1_header(b"PROXY UNKNOWN\r\n"), Ok((&[][..], ppp::model::Header::unknown())));
/// ```
///
/// TCP4
/// ```rust
/// assert_eq!(ppp::parse_v1_header(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nHello, World!"), Ok((&b"Hello, World!"[..], ppp::model:: Header::version_1(
///            ([255, 255, 255, 255], [255, 255, 255, 255], 65535, 65535).into(),
///        ))));
/// ```
///
/// TCP6
/// ```rust
/// assert_eq!(ppp::parse_v1_header(b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!"), Ok((&b"Hi!"[..], ppp::model:: Header::version_1(
///            (
///                 [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
///                 [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
///                 65535,
///                 65535
///             ).into()
///        ))));
/// ```
pub fn parse_v1_header(input: &[u8]) -> ParseResult<&[u8]> {
    text::parse_v1_header(input).map_err(ParseError::from)
}

/// Creates a `String` from a valid Version 1 header.
/// See the protocol specification for the definition of valid text headers.
/// 
/// # Examples
/// TCP4
/// ```rust
/// # use ppp::model::Header;
///
/// let text = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
/// let header = Header::version_1(([127, 0, 1, 2], [192, 168, 1, 101], 80, 443).into());
///
/// assert_eq!(ppp::to_string(header), Ok(String::from(text)));
/// ```
///
/// TCP6
/// ```rust
/// # use ppp::model::Header;
///
/// let text = "PROXY TCP6 1234:5678:90AB:CDEF:FEDC:BA09:8765:4321 4321:8765:BA09:FEDC:CDEF:90AB:5678:1234 443 65535\r\n";
/// let header = Header::version_1((
///     [0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321],
///     [0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234],
///     443,
///     65535,
/// ).into());
/// assert_eq!(ppp::to_string(header), Ok(String::from(text)));
/// ```
///
/// Invalid Text Header
/// ```rust
/// # use ppp::model::{Header, Version, Command, Protocol};
///
/// let header = Header::no_address(Version::Two, Command::Proxy, Protocol::Unspecified);
///
/// assert!(ppp::to_string(header).is_err());
///```
pub fn to_string(header: model::Header) -> Result<String, ()> {
    text::to_string(header)
}

/// Parse the first 16 bytes of the protocol header; the only required payload.
/// The 12 byte signature and 4 bytes used to describe the connection and header information.
/// The adress portion of the header, as denoted by the last 2 bytes of the required payload, must be present a header with invalid addresses or TLVs (Type-Length-Value) can be determined to be invalid.
///
/// # Examples
/// TCP over IPv6 with some TLVs
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
/// input.extend(&[1, 1, 1]);
///
/// assert_eq!(ppp::parse_v2_header(&input[..]), Ok((&[1, 1, 1][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Proxy,
///     ppp::model::Protocol::Stream,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     (
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
///         80,
///         443
///     ).into(),
/// ))))
/// ```
///
/// UDP over IPv4 with some TLVs
/// ```rust
/// let mut input: Vec<u8> = Vec::new();
///
/// input.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
/// input.push(0x20);
/// input.push(0x12);
/// input.extend(&[0, 21]);
/// input.extend(&[127, 0, 0, 1]);
/// input.extend(&[192, 168, 1, 1]);
/// input.extend(&[0, 80]);
/// input.extend(&[1, 187]);
/// input.extend(&[1, 0, 1, 5]);
/// input.extend(&[2, 0, 2, 5, 5]);
/// input.extend(&[1, 2, 3, 4, 5]);
///
/// assert_eq!(ppp::parse_v2_header(&input[..]), Ok((&[1, 2, 3, 4, 5][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Local,
///     ppp::model::Protocol::Datagram,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     ([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into(),
/// ))))
/// ```
///
/// Stream over Unix with some TLVs
/// ```rust
/// let mut input: Vec<u8> = Vec::new();
///
/// input.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
/// input.push(0x20);
/// input.push(0x31);
/// input.extend(&[0, 225]);
/// input.extend(&[0xFFu8; 108][..]);
/// input.extend(&[0xAAu8; 108][..]);
/// input.extend(&[1, 0, 1, 5]);
/// input.extend(&[2, 0, 2, 5, 5]);
/// input.extend(&[1, 2, 3, 4, 5]);
///
/// assert_eq!(ppp::parse_v2_header(&input[..]), Ok((&[1, 2, 3, 4, 5][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Local,
///     ppp::model::Protocol::Stream,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     ([0xFFFFFFFFu32; 27], [0xAAAAAAAAu32; 27]).into(),
/// ))))
/// ```
///
/// Unspecified protocol over IPv6 with some TLVs
/// ```rust
/// let mut input: Vec<u8> = Vec::new();
///
/// input.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
/// input.push(0x21);
/// input.push(0x20);
/// input.extend(&[0, 41]);
/// input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
/// input.extend(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF1]);
/// input.extend(&[1, 0, 1, 5]);
/// input.extend(&[2, 0, 2, 5, 5]);
/// input.extend(&[42]);
///
/// assert_eq!(ppp::parse_v2_header(&input[..]), Ok((&[42][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Proxy,
///     ppp::model::Protocol::Unspecified,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     (
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1]
///     ).into()
/// ))))
/// ```
pub fn parse_v2_header(input: &[u8]) -> ParseResult<&[u8]> {
    binary::parse_v2_header(input).map_err(ParseError::from)
}

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
/// assert_eq!(ppp::parse_header(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nHi!"), Ok((&b"Hi!"[..], ppp::model:: Header::version_1(
///            ([255, 255, 255, 255], [255, 255, 255, 255], 65535, 65535).into(),
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
/// input.extend(&[42]);
///
/// assert_eq!(ppp::parse_v2_header(&input[..]), Ok((&[42][..], ppp::model::Header::new(
///     ppp::model::Version::Two,
///     ppp::model::Command::Proxy,
///     ppp::model::Protocol::Stream,
///     vec![ppp::model::Tlv::new(1, vec![5]), ppp::model::Tlv::new(2, vec![5, 5])],
///     (
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
///         [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
///         80,
///         443
///     ).into(),
/// ))))
/// ```
pub fn parse_header(input: &[u8]) -> ParseResult<&[u8]> {
    alt((binary::parse_v2_header, text::parse_v1_header))(input).map_err(ParseError::from)
}
