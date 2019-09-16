use std::convert::TryFrom;
use std::fmt::{Display, Error, Formatter};
use std::slice::Iter;

/// The version of the proxy protocol header.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum Version {
    One,
    Two,
}

impl Version {
    /// Create a new instance of a version.
    /// If the version is not supported, returns an error.
    pub fn new(version: u8) -> Result<Version, ()> {
        match version {
            1 => Ok(Version::One),
            2 => Ok(Version::Two),
            _ => Err(()),
        }
    }
}

/// The type of connection received by the server from the proxy.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Command {
    Local,
    Proxy,
}

impl Command {
    /// Create a new instance of a command.
    /// If the command is not supported, returns an error.
    pub fn new(command: u8) -> Result<Command, ()> {
        match command {
            0 => Ok(Command::Local),
            1 => Ok(Command::Proxy),
            _ => Err(()),
        }
    }
}

/// The network protocol used by the client.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Protocol {
    Stream,
    Datagram,
    Unspecified,
}

impl Protocol {
    /// Create a new instance of a protocol.
    /// If the protocol is not supported, returns an error.
    pub fn new(protocol: u8) -> Result<Protocol, ()> {
        match protocol {
            0 => Ok(Protocol::Unspecified),
            1 => Ok(Protocol::Stream),
            2 => Ok(Protocol::Datagram),
            _ => Err(()),
        }
    }
}

/// A Type-Length-Value object.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Tlv {
    value_type: u8,
    value: Vec<u8>,
}

impl Tlv {
    /// The type used to interpret the value.
    pub fn value_type(&self) -> u8 {
        self.value_type
    }

    /// The value.
    pub fn value(&self) -> &[u8] {
        &self.value[..]
    }

    /// The length of the value.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn new(value_type: u8, value: Vec<u8>) -> Tlv {
        Tlv { value_type, value }
    }
}

/// An reference to a destination; either remote or local.
/// Unix addresses must be 108 bytes.
/// A none address means no address was found, this is done to avoid unwrapping an optional and then an address.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Address {
    IPv4 {
        address: [u8; 4],
        port: Option<u16>,
    },
    IPv6 {
        address: [u16; 8],
        port: Option<u16>,
    },
    Unix(Vec<u8>),
    None,
}

impl Address {
    /// A predicate to test if the address is not the `IPv4` variant.
    pub fn is_ipv4(&self) -> bool {
        match self {
            Address::IPv4 { .. } => true,
            _ => false,
        }
    }

    /// A predicate to test if the address is not the `IPv6` variant.
    pub fn is_ipv6(&self) -> bool {
        match self {
            Address::IPv6 { .. } => true,
            _ => false,
        }
    }

    /// A predicate to test if the address is the `Unix` variant.
    pub fn is_unix(&self) -> bool {
        match self {
            Address::Unix(_) => true,
            _ => false,
        }
    }

    /// A predicate to test if the address is not the `None` variant.
    pub fn is_present(&self) -> bool {
        match self {
            Address::None => false,
            _ => true,
        }
    }

    /// The port of this address if one is set.
    pub fn port(&self) -> Result<u16, ()> {
        match self {
            Address::IPv4 {
                address: _,
                port: Some(port),
            } => Ok(*port),
            Address::IPv6 {
                address: _,
                port: Some(port),
            } => Ok(*port),
            _ => Err(()),
        }
    }
}

impl From<[u8; 4]> for Address {
    fn from(address: [u8; 4]) -> Self {
        Address::IPv4 {
            port: None,
            address,
        }
    }
}

impl From<([u8; 4], u16)> for Address {
    fn from((address, port): ([u8; 4], u16)) -> Self {
        Address::IPv4 {
            port: Some(port),
            address,
        }
    }
}

impl From<[u16; 8]> for Address {
    fn from(address: [u16; 8]) -> Self {
        Address::IPv6 {
            port: None,
            address,
        }
    }
}

impl From<([u16; 8], u16)> for Address {
    fn from((address, port): ([u16; 8], u16)) -> Self {
        Address::IPv6 {
            port: Some(port),
            address,
        }
    }
}

impl TryFrom<Vec<u8>> for Address {
    type Error = &'static str;

    fn try_from(path: Vec<u8>) -> Result<Self, Self::Error> {
        match path.len() {
            108 => Ok(Address::Unix(path)),
            _ => Err("Unix address must be exactly 108 bytes long."),
        }
    }
}

/// A parsed proxy protocol header.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Header {
    version: Version,
    command: Command,
    protocol: Protocol,
    tlvs: Vec<Tlv>,
    source_address: Address,
    destination_address: Address,
}

impl Header {
    /// Create a new instance of a header.
    pub fn new(
        version: Version,
        command: Command,
        protocol: Protocol,
        tlvs: Vec<Tlv>,
        source_address: Address,
        destination_address: Address,
    ) -> Header {
        Header {
            version,
            command,
            protocol,
            tlvs,
            source_address,
            destination_address,
        }
    }

    /// Create a new instance of a header for version 1 with an unknown address family and protocol.
    pub fn unknown() -> Header {
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            tlvs: vec![],
            source_address: Address::None,
            destination_address: Address::None,
        }
    }

    /// Create a new instance of a header for version 1 with an unknown address family and protocol.
    pub fn version_1(source_address: Address, destination_address: Address) -> Header {
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            tlvs: vec![],
            source_address,
            destination_address,
        }
    }

    /// Create a new instance of a header.
    pub fn no_address(version: Version, command: Command, protocol: Protocol) -> Header {
        Header {
            version,
            command,
            protocol,
            tlvs: vec![],
            source_address: Address::None,
            destination_address: Address::None,
        }
    }

    /// The version of the parsed header.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The command of the parsed header.
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// The command of the parsed header.
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// An iterator of all the TLVs.
    pub fn tlvs(&self) -> Iter<'_, Tlv> {
        self.tlvs.iter()
    }

    /// The source address of the client connected to the proxy.
    pub fn source_address(&self) -> &Address {
        &self.source_address
    }

    /// The destination address of the server connected to by the proxy.
    pub fn destination_address(&self) -> &Address {
        &self.destination_address
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            Address::IPv4 {
                address,
                port: Some(_),
            } => write!(
                f,
                "{}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )?,
            Address::IPv6 {
                address,
                port: Some(_),
            } => write!(
                f,
                "{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}",
                address[0],
                address[1],
                address[2],
                address[3],
                address[4],
                address[5],
                address[6],
                address[7]
            )?,
            _ => Err(Error)?,
        }

        Ok(())
    }
}

/// Prints the header as a version 1 header.
impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        if Version::One != self.version {
            return Err(Error);
        }

        if Command::Proxy != self.command {
            return Err(Error);
        }

        if !self.tlvs.is_empty() {
            return Err(Error);
        }

        let protocol = match self.protocol() {
            Protocol::Stream => {
                if self.source_address().is_ipv4() && self.destination_address().is_ipv4() {
                    Ok("TCP4")
                } else if self.source_address().is_ipv6() && self.destination_address().is_ipv6() {
                    Ok("TCP6")
                } else {
                    Err(Error)
                }
            }
            Protocol::Unspecified => Ok("UNKNOWN"),
            _ => Err(Error),
        };

        if Protocol::Unspecified == self.protocol {
            write!(f, "PROXY {}\r\n", protocol?)?;
        } else {
            write!(
                f,
                "PROXY {} {} {} {} {}\r\n",
                protocol?,
                self.source_address,
                self.destination_address,
                self.source_address.port().map_err(|_| Error)?,
                self.destination_address.port().map_err(|_| Error)?,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    #[test]
    fn header_version() {
        let version = Version::One;
        let header = Header::new(
            version.clone(),
            Command::Proxy,
            Protocol::Unspecified,
            vec![Tlv::new(1, vec![1, 2, 3]), Tlv::new(2, vec![1, 1])],
            Address::None,
            Address::None,
        );
        let mut iter = header.tlvs();

        assert_eq!(&version, header.version());
        assert_eq!(&Protocol::Unspecified, header.protocol());
        assert_eq!(&Command::Proxy, header.command());
        assert_eq!(&Address::None, header.source_address());
        assert_eq!(&Address::None, header.destination_address());
        assert_eq!(Some(&Tlv::new(1, vec![1, 2, 3])), iter.next());
        assert_eq!(Some(&Tlv::new(2, vec![1, 1])), iter.next());
        assert_eq!(None, iter.next());
    }

    #[test]
    fn header_unknown() {
        let expected = Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            tlvs: vec![],
            source_address: Address::None,
            destination_address: Address::None,
        };

        assert_eq!(expected, Header::unknown());
    }

    #[test]
    fn header_version1() {
        let expected = Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            tlvs: vec![],
            source_address: ([127, 0, 0, 1], 1).into(),
            destination_address: ([127, 0, 0, 2], 2).into(),
        };

        assert_eq!(
            expected,
            Header::version_1(([127, 0, 0, 1], 1).into(), ([127, 0, 0, 2], 2).into())
        );
    }

    #[test]
    fn header_version1_display() {
        assert_eq!(
            "PROXY TCP4 127.0.0.1 127.0.0.2 1 2\r\n",
            format!(
                "{}",
                Header::version_1(([127, 0, 0, 1], 1).into(), ([127, 0, 0, 2], 2).into())
            )
            .as_str()
        );
    }

    #[test]
    fn header_version1_ipv6_display() {
        let source_address = (
            [
                0x0123, 0x4567, 0x890A, 0xBCDE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
            ],
            80,
        )
            .into();
        let destination_address = (
            [
                0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
            ],
            443,
        )
            .into();

        assert_eq!(
            "PROXY TCP6 0123:4567:890A:BCDE:FFFF:FFFF:FFFF:FFFF FFFF:FFFF:FFFF:FFFF:0123:4567:890A:BCDE 80 443\r\n",
            format!("{}", Header::version_1(source_address, destination_address)).as_str()
        );
    }

    #[test]
    #[should_panic]
    fn header_port_less_display() {
        let source_address = [
            0x0123, 0x4567, 0x890A, 0xBCDE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        ]
        .into();
        let destination_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();

        format!("{}", Header::version_1(source_address, destination_address));
    }

    #[test]
    #[should_panic]
    fn header_bad_command_display() {
        let source_address = [
            0x0123, 0x4567, 0x890A, 0xBCDE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        ]
        .into();
        let destination_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();

        format!(
            "{}",
            Header {
                version: Version::One,
                command: Command::Local,
                protocol: Protocol::Stream,
                tlvs: vec![],
                source_address,
                destination_address,
            }
        );
    }

    #[test]
    #[should_panic]
    fn header_bad_tlv_display() {
        let source_address = [
            0x0123, 0x4567, 0x890A, 0xBCDE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        ]
        .into();
        let destination_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();

        format!(
            "{}",
            Header {
                version: Version::One,
                command: Command::Proxy,
                protocol: Protocol::Stream,
                tlvs: vec![Tlv::new(1, vec![])],
                source_address,
                destination_address,
            }
        );
    }

    #[test]
    #[should_panic]
    fn header_bad_protocol_display() {
        let source_address = [
            0x0123, 0x4567, 0x890A, 0xBCDE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        ]
        .into();
        let destination_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();

        format!(
            "{}",
            Header {
                version: Version::One,
                command: Command::Proxy,
                protocol: Protocol::Datagram,
                tlvs: vec![],
                source_address,
                destination_address,
            }
        );
    }

    #[test]
    #[should_panic]
    fn header_mismatch_address_display() {
        let source_address = [127, 0, 0, 1].into();
        let destination_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();

        format!("{}", Header::version_1(source_address, destination_address));
    }

    #[test]
    #[should_panic]
    fn header_mismatch_address_reversed_display() {
        let source_address = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0123, 0x4567, 0x890A, 0xBCDE,
        ]
        .into();
        let destination_address = [127, 0, 0, 1].into();

        format!("{}", Header::version_1(source_address, destination_address));
    }

    #[test]
    #[should_panic]
    fn version_2_display() {
        format!(
            "{}",
            Header::no_address(Version::Two, Command::Proxy, Protocol::Stream)
        );
    }

    #[test]
    fn header_unknown_display() {
        assert_eq!(
            "PROXY UNKNOWN\r\n",
            format!("{}", Header::unknown()).as_str()
        );
    }

    #[test]
    fn header_no_address() {
        let expected = Header {
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            tlvs: vec![],
            source_address: Address::None,
            destination_address: Address::None,
        };

        assert_eq!(
            expected,
            Header::no_address(Version::Two, Command::Proxy, Protocol::Stream)
        );
    }

    #[test]
    fn tlv() {
        let tlv = Tlv::new(7, vec![1, 2, 3]);

        assert_eq!(3, tlv.len());
        assert_eq!(7, tlv.value_type());
        assert_eq!(&vec![1, 2, 3][..], tlv.value());
    }

    #[test]
    fn version() {
        assert_eq!(Err(()), Version::new(0));
        assert_eq!(Ok(Version::One), Version::new(1));
        assert_eq!(Ok(Version::Two), Version::new(2));
    }

    #[test]
    fn protocol() {
        assert_eq!(Ok(Protocol::Unspecified), Protocol::new(0));
        assert_eq!(Ok(Protocol::Stream), Protocol::new(1));
        assert_eq!(Ok(Protocol::Datagram), Protocol::new(2));
        assert_eq!(Err(()), Protocol::new(3));
    }

    #[test]
    fn command() {
        assert_eq!(Ok(Command::Local), Command::new(0));
        assert_eq!(Ok(Command::Proxy), Command::new(1));
        assert_eq!(Err(()), Command::new(3));
    }

    #[test]
    fn address() {
        assert_eq!(Ok(Address::Unix(zeros(108))), Address::try_from(zeros(108)));
        assert!(Address::try_from(zeros(107)).is_err());
        assert_eq!(
            Address::IPv4 {
                address: [127, 0, 0, 1],
                port: Some(3456),
            },
            ([127u8, 0u8, 0u8, 1u8], 3456u16).into()
        );
        assert_eq!(
            Address::IPv4 {
                address: [127, 0, 0, 2],
                port: None,
            },
            [127u8, 0u8, 0u8, 2u8].into()
        );
        assert_eq!(
            Address::IPv6 {
                address: [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
                port: Some(12345),
            },
            (
                [
                    0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16,
                    0xFFFFu16
                ],
                12345u16
            )
                .into()
        );
        assert_eq!(
            Address::IPv6 {
                address: [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
                port: None,
            },
            [
                0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16,
                0xFFF1u16
            ]
            .into()
        );
    }

    #[test]
    fn address_predicates() {
        let unix = Address::Unix(zeros(108));

        assert!(unix.is_unix());
        assert!(unix.is_present());
        assert!(!unix.is_ipv4());
        assert!(!unix.is_ipv6());

        let ipv4 = Address::IPv4 {
            address: [127, 0, 0, 2],
            port: None,
        };

        assert!(!ipv4.is_unix());
        assert!(ipv4.is_present());
        assert!(ipv4.is_ipv4());
        assert!(!ipv4.is_ipv6());

        let ipv6 = Address::IPv6 {
            address: [
                0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16,
                0xFFFFu16,
            ],
            port: None,
        };

        assert!(!ipv6.is_unix());
        assert!(ipv6.is_present());
        assert!(!ipv6.is_ipv4());
        assert!(ipv6.is_ipv6());
    }

    fn zeros(size: usize) -> Vec<u8> {
        iter::repeat(0).take(size).collect()
    }
}
