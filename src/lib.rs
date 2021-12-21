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

impl<'a> PartialResult for Result<v1::Header<'a>, v1::ParseError> {
    fn is_incomplete(&self) -> bool {
        matches!(self, Err(v1::ParseError::MissingNewLine))
    }
}

impl<'a> PartialResult for Result<v2::Header<'a>, v2::ParseError> {
    fn is_incomplete(&self) -> bool {
        matches!(self, Err(v2::ParseError::Incomplete(..) | v2::ParseError::Partial(..)))
    }
}