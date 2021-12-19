use crate::ip::{IPv4, IPv6};
use crate::v2::error::ParseError;

pub const PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
pub const VERSION_COMMAND: usize = PROTOCOL_PREFIX.len();
pub const ADDRESS_FAMILY_PROTOCOL: usize = VERSION_COMMAND + 1;
pub const LENGTH: usize = ADDRESS_FAMILY_PROTOCOL + 1;
pub const MINIMUM_LENGTH: usize = LENGTH + 2;
const IPV4_ADDRESSES_BYTES: usize = 12;
const IPV6_ADDRESSES_BYTES: usize = 36;
const UNIX_ADDRESSES_BYTES: usize = 216;
const MINIMUM_TLV_LENGTH: usize = 3;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a [u8],
    pub version: Version,
    pub command: Command,
    pub address_family: AddressFamily,
    pub protocol: Protocol,
    pub length: u16,
    pub addresses: Addresses
}

impl<'a> Header<'a> {
    pub fn length(&self) -> usize {
        self.length as usize
    }

    fn address_bytes_end(&self) -> usize {
        let length = self.length();
        let address_bytes = self.address_family.byte_length().unwrap_or(length);

        MINIMUM_LENGTH + std::cmp::min(address_bytes, length)
    }

    pub fn address_bytes(&self) -> &'a [u8] {
        &self.header[MINIMUM_LENGTH..self.address_bytes_end()]
    }

    pub fn additional_bytes(&self) -> &'a [u8] {
        &self.header[self.address_bytes_end()..]
    }

    pub fn tlvs(&self) -> TypeLengthValues<'a> {
        TypeLengthValues {
            bytes: self.additional_bytes(),
            offset: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValues<'a> {
    bytes: &'a [u8],
    offset: usize,
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Version {
    Two = 0x20,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Command {
    Local = 0,
    Proxy,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressFamily {
    Unspecified = 0x00,
    IPv4 = 0x10,
    IPv6 = 0x20,
    Unix = 0x30,
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Addresses {
    Unspecified,
    IPv4(IPv4),
    IPv6(IPv6),
    Unix(Unix),
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Unix {
    pub source: [u8; 108],
    pub destination: [u8; 108],
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Protocol {
    Unspecified = 0,
    Stream,
    Datagram,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValue<'a> {
    kind: u8,
    value: &'a [u8],
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ClientType {
    SSL = 1,
    CertificateConnection,
    CertificateSession,
}
