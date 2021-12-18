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
