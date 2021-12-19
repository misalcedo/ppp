use crate::ip::{IPv4, IPv6};
use crate::v2::error::ParseError;
use std::net::{Ipv4Addr, Ipv6Addr};

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

    pub fn addresses(&self) -> Result<Addresses, ParseError> {
        let bytes = self.address_bytes();

        match self.address_family {
            AddressFamily::Unspecified => Ok(Addresses::Unspecified),
            AddressFamily::IPv4 => {
                let source_address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let destination_address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                let source_port = u16::from_be_bytes([bytes[8], bytes[9]]);
                let destination_port = u16::from_be_bytes([bytes[10], bytes[11]]);

                Ok(Addresses::IPv4(IPv4 {
                    source_address,
                    destination_address,
                    source_port,
                    destination_port
                }))
            },
            AddressFamily::IPv6 => {
                let mut address = [0; 16];

                address[..].copy_from_slice(&bytes[..16]);
                let source_address = Ipv6Addr::from(address);

                address[..].copy_from_slice(&bytes[16..32]);
                let destination_address = Ipv6Addr::from(address);

                let source_port = u16::from_be_bytes([bytes[32], bytes[33]]);
                let destination_port = u16::from_be_bytes([bytes[34], bytes[35]]);

                Ok(Addresses::IPv6(IPv6 {
                    source_address,
                    destination_address,
                    source_port,
                    destination_port
                }))
            },
            AddressFamily::Unix => {
                let mut source = [0; 108];
                let mut destination = [0; 108];

                source[..].copy_from_slice(&bytes[..108]);
                destination[..].copy_from_slice(&bytes[108..]);

                Ok(Addresses::Unix(Unix {
                    source,
                    destination
                }))
            },
        }        
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Unix {
    source: [u8; 108],
    destination: [u8; 108],
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
