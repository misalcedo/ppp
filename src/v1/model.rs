use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PROTOCOL_SUFFIX: &str = "\r\n";
pub const PROTOCOL_PREFIX: &str = "PROXY";
pub const TCP4: &str = "TCP4";
pub const TCP6: &str = "TCP6";
pub const UNKNOWN: &str = "UNKNOWN";

/// The sperator of the header parts.
pub const SEPARATOR: char = ' ';

/// A text PROXY protocol header that borrows the input string.
///
/// ## Examples
/// ### Worst Case (from bytes)
/// ```rust
/// use ppp::v1::{Addresses, Header, UNKNOWN};
///
/// let input = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
/// let header = Header::try_from(input.as_bytes()).unwrap();
///
/// assert_eq!(header, Header::new(input, Addresses::Unknown));
/// assert_eq!(header.protocol(), UNKNOWN);
/// assert_eq!(header.addresses_str(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535");
/// ```
///
/// ### UNKNOWN
/// ```rust
/// use ppp::v1::{Addresses, Header, UNKNOWN};
///
/// let input = "PROXY UNKNOWN\r\nhello";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(header, Header::new("PROXY UNKNOWN\r\n", Addresses::Unknown));
/// assert_eq!(header.protocol(), UNKNOWN);
/// assert_eq!(header.addresses_str(), "");
/// ```
///
/// ### TCP4
/// ```rust
/// use std::net::Ipv4Addr;
/// use ppp::v1::{Header, Addresses, TCP4};
///
/// let input = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(header, Header::new(input, Addresses::new_tcp4(Ipv4Addr::new(127, 0, 1, 2), Ipv4Addr::new(192, 168, 1, 101), 80, 443)));
/// assert_eq!(header.protocol(), TCP4);
/// assert_eq!(header.addresses_str(), "127.0.1.2 192.168.1.101 80 443");
/// ```
///
/// ### TCP6
/// ```rust
/// use std::net::Ipv6Addr;
/// use ppp::v1::{Header, Addresses, TCP6};
///
/// let input = "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(
///     header,
///     Header::new(
///         input,
///         Addresses::new_tcp6(
///             Ipv6Addr::from([0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321]),
///             Ipv6Addr::from([0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,]),
///             443,
///             65535
///         )
///     )
/// );
/// assert_eq!(header.protocol(), TCP6);
/// assert_eq!(header.addresses_str(), "1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535");
/// ```
///
/// ### Invalid
/// ```rust
/// use ppp::v1::{Header, Addresses, ParseError};
///
/// assert_eq!(Err(ParseError::InvalidProtocol), "PROXY tcp4\r\n".parse::<Addresses>());
/// ```
#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    pub header: &'a str,
    pub addresses: Addresses,
}

impl<'a> Header<'a> {
    /// Creates a new `Header` with the given addresses and a reference to the original input.
    pub fn new(header: &'a str, addresses: Addresses) -> Self {
        Header { header, addresses }
    }

    /// The protocol portion of this `Header`.
    pub fn protocol(&self) -> &str {
        self.addresses.protocol()
    }

    /// The source and destination addressses portion of this `Header`.
    pub fn addresses_str(&self) -> &'a str {
        let start = PROTOCOL_PREFIX.len() + SEPARATOR.len_utf8() + self.protocol().len();
        let end = self.header.len() - PROTOCOL_SUFFIX.len();
        let addresses = &self.header[start..end];

        if addresses.starts_with(SEPARATOR) {
            &addresses[SEPARATOR.len_utf8()..]
        } else {
            addresses
        }
    }
}

/// The source and destination of a header.
/// Includes IP (v4 or v6) addresses and TCP ports.
///
/// ## Examples
/// ### Worst Case
/// ```rust
/// use ppp::v1::{Addresses, Header, UNKNOWN};
///
/// let header = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
/// let addresses = Addresses::Unknown;
///
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_ne!(addresses.to_string().as_str(), header);
/// ```
/// 
/// ### UNKNOWN
/// ```rust
/// use ppp::v1::Addresses;
///
/// let header = "PROXY UNKNOWN\r\n";
/// let addresses = Addresses::Unknown;
/// 
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### TCP4
/// ```rust
/// use std::net::Ipv4Addr;
/// use ppp::v1::Addresses;
///
/// let header = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
/// let addresses = Addresses::new_tcp4(Ipv4Addr::new(127, 0, 1, 2), Ipv4Addr::new(192, 168, 1, 101), 80, 443);
/// 
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### TCP6
/// ```rust
/// use std::net::Ipv6Addr;
/// use ppp::v1::Addresses;
///
/// let header = "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n";
/// let addresses = Addresses::new_tcp6(
///     Ipv6Addr::from([0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321]),
///     Ipv6Addr::from([0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,]),
///     443,
///     65535
/// );
/// 
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### Invalid
/// ```rust
/// use ppp::v1::{Addresses, ParseError};
///
/// assert_eq!(Err(ParseError::InvalidProtocol), "PROXY tcp4\r\n".parse::<Addresses>());
/// ```
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Addresses {
    Unknown,
    Tcp4(Tcp4),
    Tcp6(Tcp6),
}

impl Addresses {
    /// Create a new IPv4 TCP address.
    pub fn new_tcp4(
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp4(Tcp4 {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }

    /// Create a new IPv6 TCP address.
    pub fn new_tcp6(
        source_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp6(Tcp6 {
            source_address,
            source_port,
            destination_address,
            destination_port,
        })
    }

    /// The protocol portion of this `Addresses`.
    pub fn protocol(&self) -> &str {
        match self {
            Addresses::Tcp4(..) => TCP4,
            Addresses::Tcp6(..) => TCP6,
            Addresses::Unknown => UNKNOWN,
        }
    }
}

impl Default for Addresses {
    fn default() -> Self {
        Addresses::Unknown
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)
    }
}

impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PROXY ")?;

        match self {
            Self::Unknown => write!(f, "UNKNOWN")?,
            Self::Tcp4(a) => write!(f, "TCP4 {} {} {} {}", a.source_address, a.destination_address, a.source_port, a.destination_port)?,
            Self::Tcp6(a) => write!(f, "TCP6 {} {} {} {}", a.source_address, a.destination_address, a.source_port, a.destination_port)?,
        }

        write!(f, "\r\n")
    }
}

/// The source and destination IPv4 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Tcp4 {
    pub source_address: Ipv4Addr,
    pub source_port: u16,
    pub destination_address: Ipv4Addr,
    pub destination_port: u16,
}

/// The source and destination IPv6 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Tcp6 {
    pub source_address: Ipv6Addr,
    pub source_port: u16,
    pub destination_address: Ipv6Addr,
    pub destination_port: u16,
}
