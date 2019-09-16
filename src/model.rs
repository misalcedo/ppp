use std::convert::TryFrom;
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
                port: Some(12345)
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
                port: None
            },
            [
                0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16, 0xFFFFu16,
                0xFFF1u16
            ]
            .into()
        );
    }

    fn zeros(size: usize) -> Vec<u8> {
        iter::repeat(0).take(size).collect()
    }
}
