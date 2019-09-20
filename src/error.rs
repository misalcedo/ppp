/// An error occurred while parsing a header.
enum ParseError {
    /// The parser was unable to fully parse a header, however, the parser needs more information
    /// (i.e. bytes) in order to determine success or failure.
    Incomplete,
    /// The parser was unable to parse a header; no additional information is necessary.
    Failure
}