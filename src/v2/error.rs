#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("Expected header to include 4 bytes after the prefix (length {0}).")]
    Incomplete(usize),
    #[error("Expected header to start with a prefix of '\\r\\n\\r\\n\\0\\r\\nQUIT\\n'.")]
    Prefix,
    #[error("Expected version {0:X} to be equal to 2.")]
    Version(u8),
    #[error("Invalid command {0:X}. Command must be one of: Local, Proxy.")]
    Command(u8),
    #[error(
        "Invalid Address Family {0:X}. Address Family must be one of: Unspecified, IPv4, IPv6, Unix."
    )]
    AddressFamily(u8),
    #[error("Invalid protocol {0:X}. Protocol must be one of: Unspecified, Stream, or Datagram.")]
    Protocol(u8),
    #[error("Header does not contain the advertised length of the TLVs (contains {1} out of {0} bytes).")]
    PartialTLVs(u16, usize),
    #[error("Header is not long enough to contain enough TLV {0} with lengh {1}.")]
    InvalidTLV(u8, u16),
    #[error("Header contains leftover {0} bytes not accounted for by the address family or TLVs.")]
    LeftoverTLVs(usize),
}
