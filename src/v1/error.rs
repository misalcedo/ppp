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
    #[error("Header does not fit within the expected buffer size of 107 bytes (plus 1 byte for null-terminated strings).")]
    HeaderTooLong,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BinaryParseError<'a> {
    #[error("Encountered an error in parsing the header.")]
    Parse(ParseError<'a>),
    #[error("Header is not valid UTF-8.")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}
