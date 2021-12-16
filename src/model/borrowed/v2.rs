pub struct Header<'a> {
    header: &'a [u8]
}

pub enum Version {
    Two = 2,
}

pub enum Command {
    Local = 0,
    Proxy,
}

pub enum AddressFamily {
    Unspecified = 0,
    IPv4,
    IPv6,
    Unix
}

pub enum Protocol {
    Unspecified = 0,
    Stream,
    Datagram,
}

pub struct TypeLengthValue<'a> {
    tlv: &'a [u8]
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
    NetworkNamespace = 30
}

pub enum ClientType {
    SSL = 1,
    CertificateConnection,
    CertificateSession
}