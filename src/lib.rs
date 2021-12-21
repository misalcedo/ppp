//! A Proxy Protocol Parser written in Rust.
//! Supports both text and binary versions of the header protocol.

mod ip;

pub mod v1;
pub mod v2;

/// The canonical way to determin when a streamed header should be retried in a streaming context.
/// The protocol states that servers may choose to support partial headers or to close the connection if the header is not preset all at once.
pub trait PartialResult {
    /// Tests whether this `Result` is successful or whether the error is terminal.
    /// A terminal error will not result in a success even with more bytes.
    /// Retrying with the same -- or more -- input will not change the result.
    fn is_complete(&self) -> bool {
        !self.is_incomplete()
    }

    /// Tests whether this `Result` is incomplete.
    /// An action that leads to an incomplete result may have a different result with more bytes.
    /// Retrying with the same input will not change the result.
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
