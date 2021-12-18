#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("Expected header to include 4 bytes after the prefix.")]
    Incomplete,
    #[error("Expected header to start with a prefix of '\\r\\n\\r\\n\\0\\r\\nQUIT\\n'.")]
    Prefix,
    #[error("Expected version to be equal to 2.")]
    Version,
    #[error("Invalid command. Command must be one of: Local, Proxy.")]
    Command,
    #[error(
        "Invalid Address Family. Address Family must be one of: Unspecified, IPv4, IPv6, Unix."
    )]
    AddressFamily,
    #[error("Invalid protocol. Protocol must be one of: Unspecified, Stream, or Datagram.")]
    Protocol,
}
