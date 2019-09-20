use std::error::Error;
use std::fmt::{Display, Formatter};

/// An error occurred while parsing a header.
#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The parser was unable to fully parse a header, however, the parser needs more information
    /// (i.e. bytes) in order to determine success or failure.
    Incomplete,
    /// The parser was unable to parse a header; no additional information is necessary.
    Failure
}

impl ParseError {
    /// A predicate that tests if an parse error needs more information (i.e. bytes) to
    /// determine success or failure, or not.
    pub fn is_incomplete(&self) -> bool {
        match self {
            ParseError::Incomplete => true,
            ParseError::Failure => false,
        }
    }
}

/// Create a parse error from a nom error.
impl<T> From<nom::Err<(T, nom::error::ErrorKind)>> for ParseError {
    fn from(e: nom::Err<(T, nom::error::ErrorKind)>) -> Self {
        match e {
            nom::Err::Incomplete(_) => ParseError::Incomplete,
            _ => ParseError::Failure,
        }
    }
}

impl Error for ParseError {
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Unable to parse a header from input (Reason: {:?}).", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_complete() {
        assert!(ParseError::Incomplete.is_incomplete());
        assert!(!ParseError::Failure.is_incomplete());
    }
}