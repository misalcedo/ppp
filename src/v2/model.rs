pub struct Header<'a> {
    pub header: &'a [u8],
    pub version: Version,
    pub command: Command,
    pub address_family: AddressFamily,
    pub protocol: Protocol,
    pub length: u16,
    pub tlvs: TypeLengthValues<'a>,
}

pub struct TypeLengthValues<'a> {
    pub buffer: &'a [u8],
}

pub enum Version {
    Two = 0x20,
}

pub enum Command {
    Local = 0,
    Proxy,
}

pub enum AddressFamily {
    Unspecified = 0x00,
    IPv4 = 0x10,
    IPv6 = 0x20,
    Unix = 0x30,
}

pub enum Protocol {
    Unspecified = 0,
    Stream,
    Datagram,
}

pub struct TypeLengthValue<'a> {
    tlv: &'a [u8],
}

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

pub enum ClientType {
    SSL = 1,
    CertificateConnection,
    CertificateSession,
}
