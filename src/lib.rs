//! A Proxy Protocol Parser written in Rust.
//! Supports both text and binary versions of the header protocol.

mod ip;

pub mod v1;
pub mod v2;

pub trait PartialResult {
    fn is_complete(&self) -> bool {
        !self.is_incomplete()
    }

    fn is_incomplete(&self) -> bool;
}

impl<'a, T, E: PartialResult> PartialResult for Result<T, E> {
    fn is_incomplete(&self) -> bool {
        match self {
            Ok(_) => false,
            Err(error) => error.is_incomplete(),
        }
    }
}

impl<'a> PartialResult for v1::ParseError {
    fn is_incomplete(&self) -> bool {
        matches!(
            self,
            v1::ParseError::Partial
                | v1::ParseError::MissingPrefix
                | v1::ParseError::MissingProtocol
                | v1::ParseError::MissingSourceAddress
                | v1::ParseError::MissingDestinationAddress
                | v1::ParseError::MissingSourcePort
                | v1::ParseError::MissingDestinationPort
                | v1::ParseError::MissingNewLine
        )
    }
}

impl<'a> PartialResult for v1::BinaryParseError {
    fn is_incomplete(&self) -> bool {
        match self {
            v1::BinaryParseError::Parse(error) => error.is_incomplete(),
            _ => false,
        }
    }
}

impl<'a> PartialResult for v2::ParseError {
    fn is_incomplete(&self) -> bool {
        matches!(
            self,
            v2::ParseError::Incomplete(..) | v2::ParseError::Partial(..)
        )
    }
}
