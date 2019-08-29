use crate::error::ErrorKind::{IoError, InvalidEncoding, InvalidAddress};
use std::io;
use std::str::Utf8Error;
use std::net::AddrParseError;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    EmptyStream,
    MissingProxy,
    InvalidHeader,
    MissingProtocolFamily,
    InvalidLayer3AddressFormat,
    InvalidSourceAddress,
    InvalidDestinationAddress,
    InvalidSourcePort,
    InvalidDestinationPort,
    InvalidAddress,
    MissingCRLF,
    IoError,
    InvalidEncoding
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    cause: Option<io::Error>
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error occurred while parsing a Proxy Protocol Header (kind: {}).", self.kind)
    }
}

impl std::cmp::PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error { kind: IoError, cause: Some(error) }
    }
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Self {
        Error { kind: InvalidEncoding, cause: None }
    }
}

impl From<AddrParseError> for Error {
    fn from(error: AddrParseError) -> Self {
        Error { kind: InvalidAddress, cause: None }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error { kind, cause: None }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "Error occurred while parsing a Proxy Protocol Header."
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}