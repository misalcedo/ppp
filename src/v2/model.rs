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
}

impl<'a> Header<'a> {
    pub fn length(&self) -> usize {
        self.length as usize
    }

    fn address_bytes_end(&self) -> usize {
        let address_bytes = match self.address_family {
            AddressFamily::IPv4 => IPV4_ADDRESSES_BYTES,
            AddressFamily::IPv6 => IPV6_ADDRESSES_BYTES,
            AddressFamily::Unix => UNIX_ADDRESSES_BYTES,
            AddressFamily::Unspecified => self.length()
        };
        
        MINIMUM_LENGTH + std::cmp::min(address_bytes, self.length())
    }

    pub fn address_bytes(&self) -> &'a [u8] {
        &self.header[MINIMUM_LENGTH..self.address_bytes_end()]
    }

    pub fn additional_bytes(&self) -> &'a [u8] {
        &self.header[self.address_bytes_end()..]
    }

    pub fn tlvs(&self) -> Result<TypeLengthValues<'a>, ParseError> {
        let mut current = self.additional_bytes();
        while current.len() >= MINIMUM_TLV_LENGTH {
            let length = u16::from_be_bytes([current[1], current[2]]);
            let tlv_length = MINIMUM_TLV_LENGTH + length as usize;
    
            if current.len() < tlv_length {
                return Err(ParseError::InvalidTLV(current[0], length));
            }
    
            current = &current[tlv_length..];
        }
    
        if current.len() != 0 {
            return Err(ParseError::LeftoverTLVs(current.len()));
        }
    
        Ok(TypeLengthValues {
            buffer: self.additional_bytes()
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValues<'a> {
    pub buffer: &'a [u8],
}

impl<'a> Default for TypeLengthValues<'a> {
    fn default() -> Self {
        TypeLengthValues { buffer: &[] }
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Protocol {
    Unspecified = 0,
    Stream,
    Datagram,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TypeLengthValue<'a> {
    tlv: &'a [u8],
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
