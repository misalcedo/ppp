use crate::ip::{IPv4, IPv6};
use crate::v2::error::ParseError;
use std::fmt;
use std::net::SocketAddr;
use std::ops::BitOr;

pub const PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
pub const VERSION_COMMAND: usize = PROTOCOL_PREFIX.len();
pub const ADDRESS_FAMILY_PROTOCOL: usize = VERSION_COMMAND + 1;
pub const LENGTH: usize = ADDRESS_FAMILY_PROTOCOL + 1;
pub const MINIMUM_LENGTH: usize = LENGTH + 2;
pub const MINIMUM_TLV_LENGTH: usize = 3;
const IPV4_ADDRESSES_BYTES: usize = 12;
const IPV6_ADDRESSES_BYTES: usize = 36;
const UNIX_ADDRESSES_BYTES: usize = 216;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a [u8],
    pub version: Version,
    pub command: Command,
    pub protocol: Protocol,
    pub addresses: Addresses,
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:#X} {:#X} ({} bytes)",
            PROTOCOL_PREFIX,
            self.version | self.command,
            self.protocol | self.address_family(),
            self.length()
        )
    }
}

impl<'a> Header<'a> {
    pub fn length(&self) -> usize {
        self.header[MINIMUM_LENGTH..].len()
    }

    pub fn len(&self) -> usize {
        self.header.len()
    }

    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
    }

    pub fn address_family(&self) -> AddressFamily {
        self.addresses.address_family()
    }

    fn address_bytes_end(&self) -> usize {
        let length = self.length();
        let address_bytes = self.address_family().byte_length().unwrap_or(length);

        MINIMUM_LENGTH + std::cmp::min(address_bytes, length)
    }

    pub fn address_bytes(&self) -> &'a [u8] {
        &self.header[MINIMUM_LENGTH..self.address_bytes_end()]
    }

    pub fn tlv_bytes(&self) -> &'a [u8] {
        &self.header[self.address_bytes_end()..]
    }

    pub fn tlvs(&self) -> TypeLengthValues<'a> {
        TypeLengthValues {
            bytes: self.tlv_bytes(),
            offset: 0,
        }
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.header
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValues<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TypeLengthValues<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> From<&'a [u8]> for TypeLengthValues<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        TypeLengthValues { bytes, offset: 0 }
    }
}

impl<'a> Iterator for TypeLengthValues<'a> {
    type Item = Result<TypeLengthValue<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let remaining = &self.bytes[self.offset..];

        if remaining.len() < MINIMUM_TLV_LENGTH {
            self.offset = self.bytes.len();
            return Some(Err(ParseError::Leftovers(self.bytes.len())));
        }

        let tlv_type = remaining[0];
        let length = u16::from_be_bytes([remaining[1], remaining[2]]);
        let tlv_length = MINIMUM_TLV_LENGTH + length as usize;

        if remaining.len() < tlv_length {
            self.offset = self.bytes.len();
            return Some(Err(ParseError::InvalidTLV(tlv_type, length)));
        }

        self.offset += tlv_length;

        Some(Ok(TypeLengthValue {
            kind: tlv_type,
            value: &remaining[MINIMUM_TLV_LENGTH..tlv_length],
        }))
    }
}

impl<'a> TypeLengthValues<'a> {
    pub fn len(&self) -> u16 {
        self.bytes.len() as u16
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Version {
    Two = 0x20,
}

impl BitOr<Command> for Version {
    type Output = u8;

    fn bitor(self, command: Command) -> Self::Output {
        (self as u8) | (command as u8)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Command {
    Local = 0,
    Proxy,
}

impl BitOr<Version> for Command {
    type Output = u8;

    fn bitor(self, version: Version) -> Self::Output {
        (self as u8) | (version as u8)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressFamily {
    Unspecified = 0x00,
    IPv4 = 0x10,
    IPv6 = 0x20,
    Unix = 0x30,
}

impl BitOr<Protocol> for AddressFamily {
    type Output = u8;

    fn bitor(self, protocol: Protocol) -> Self::Output {
        (self as u8) | (protocol as u8)
    }
}

impl AddressFamily {
    pub fn byte_length(&self) -> Option<usize> {
        match self {
            AddressFamily::IPv4 => Some(IPV4_ADDRESSES_BYTES),
            AddressFamily::IPv6 => Some(IPV6_ADDRESSES_BYTES),
            AddressFamily::Unix => Some(UNIX_ADDRESSES_BYTES),
            AddressFamily::Unspecified => None,
        }
    }
}

impl From<AddressFamily> for u16 {
    fn from(address_family: AddressFamily) -> Self {
        address_family.byte_length().unwrap_or_default() as u16
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Addresses {
    Unspecified,
    IPv4(IPv4),
    IPv6(IPv6),
    Unix(Unix),
}

impl From<(SocketAddr, SocketAddr)> for Addresses {
    fn from(addresses: (SocketAddr, SocketAddr)) -> Self {
        match addresses {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => IPv4::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )
            .into(),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => IPv6::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )
            .into(),
            _ => Addresses::Unspecified,
        }
    }
}

impl From<IPv4> for Addresses {
    fn from(addresses: IPv4) -> Self {
        Addresses::IPv4(addresses)
    }
}

impl From<IPv6> for Addresses {
    fn from(addresses: IPv6) -> Self {
        Addresses::IPv6(addresses)
    }
}

impl From<Unix> for Addresses {
    fn from(addresses: Unix) -> Self {
        Addresses::Unix(addresses)
    }
}

impl Addresses {
    pub fn address_family(&self) -> AddressFamily {
        match self {
            Addresses::Unspecified => AddressFamily::Unspecified,
            Addresses::IPv4(..) => AddressFamily::IPv4,
            Addresses::IPv6(..) => AddressFamily::IPv6,
            Addresses::Unix(..) => AddressFamily::Unix,
        }
    }

    pub fn len(&self) -> usize {
        self.address_family().byte_length().unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.address_family().byte_length().is_none()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Unix {
    pub source: [u8; 108],
    pub destination: [u8; 108],
}

impl Unix {
    pub fn new(source: [u8; 108], destination: [u8; 108]) -> Self {
        Unix {
            source,
            destination,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Protocol {
    Unspecified = 0,
    Stream,
    Datagram,
}

impl BitOr<AddressFamily> for Protocol {
    type Output = u8;

    fn bitor(self, address_family: AddressFamily) -> Self::Output {
        (self as u8) | (address_family as u8)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValue<'a> {
    pub kind: u8,
    pub value: &'a [u8],
}

impl<'a, T: Into<u8>> From<(T, &'a [u8])> for TypeLengthValue<'a> {
    fn from((kind, value): (T, &'a [u8])) -> Self {
        TypeLengthValue {
            kind: kind.into(),
            value,
        }
    }
}

impl<'a> TypeLengthValue<'a> {
    pub fn new<T: Into<u8>>(kind: T, value: &'a [u8]) -> Self {
        TypeLengthValue {
            kind: kind.into(),
            value,
        }
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Type {
    ALPN = 1,
    Authority,
    CRC32C,
    NoOp,
    UniqueId,
    SSL = 20,
    SSLVersion,
    SSLCommonName,
    SSLCipher,
    SSLSignatureAlgorithm,
    SSLKeyAlgorithm,
    NetworkNamespace = 30,
}

impl From<Type> for u8 {
    fn from(kind: Type) -> Self {
        kind as u8
    }
}
