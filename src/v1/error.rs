#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ParseError<'a> {
    #[error("Header does not start with the string 'PROXY'.")]
    MissingPrefix,
    #[error("Header has an invalid protocol.")]
    InvalidProtocol(&'a str),
    #[error("Header missing protocol.")]
    MissingProtocol,
    #[error("Header missing an expected part of the address.")]
    EmptyAddresses,
    #[error("Header does not end with the string '\\r\\n'.")]
    MissingNewLine,
    #[error("Header contains additional characters after the destination port, but before the '\\r\\n'.")]
    UnexpectedCharacters,
    #[error("Header does not fit within the expected buffer size of 107 bytes (plus 1 byte for null-terminated strings).")]
    HeaderTooLong,
    #[error("Header contains invalid IP address for the source.")]
    InvalidSourceAddress(#[source] std::net::AddrParseError),
    #[error("Header contains invalid IP address for the destination.")]
    InvalidDestinationAddress(#[source] std::net::AddrParseError),
    #[error("Header contains invalid TCP port for the source.")]
    InvalidSourcePort(#[source] std::num::ParseIntError),
    #[error("Header contains invalid TCP port for the destination.")]
    InvalidDestinationPort(#[source] std::num::ParseIntError),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BinaryParseError<'a> {
    #[error("Encountered an error in parsing the header.")]
    Parse(ParseError<'a>),
    #[error("Header is not valid UTF-8.")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}
