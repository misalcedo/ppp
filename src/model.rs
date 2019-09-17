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
pub enum Addresses {
    IPv4 {
        source_address: [u8; 4],
        destination_address: [u8; 4],
        source_port: Option<u16>,
        destination_port: Option<u16>,
    },
    IPv6 {
        source_address: [u16; 8],
        destination_address: [u16; 8],
        source_port: Option<u16>,
        destination_port: Option<u16>,
    },
    Unix {
        source_address: [u32; 27],
        destination_address: [u32; 27],
    },
    None,
}

impl From<([u8; 4], [u8; 4])> for Addresses {
    fn from((source_address, destination_address): ([u8; 4], [u8; 4])) -> Self {
        Addresses::IPv4 {
            source_address,
            source_port: None,
            destination_address,
            destination_port: None,
        }
    }
}

impl From<([u8; 4], [u8; 4], u16, u16)> for Addresses {
    fn from(
        (source_address, destination_address, source_port, destination_port): (
            [u8; 4],
            [u8; 4],
            u16,
            u16,
        ),
    ) -> Self {
        Addresses::IPv4 {
            source_address,
            source_port: Some(source_port),
            destination_address,
            destination_port: Some(destination_port),
        }
    }
}

impl From<([u16; 8], [u16; 8])> for Addresses {
    fn from((source_address, destination_address): ([u16; 8], [u16; 8])) -> Self {
        Addresses::IPv6 {
            source_address,
            source_port: None,
            destination_address,
            destination_port: None,
        }
    }
}

impl From<([u16; 8], [u16; 8], u16, u16)> for Addresses {
    fn from(
        (source_address, destination_address, source_port, destination_port): (
            [u16; 8],
            [u16; 8],
            u16,
            u16,
        ),
    ) -> Self {
        Addresses::IPv6 {
            source_address,
            source_port: Some(source_port),
            destination_address,
            destination_port: Some(destination_port),
        }
    }
}

impl From<([u32; 27], [u32; 27])> for Addresses {
    fn from((source_address, destination_address): ([u32; 27], [u32; 27])) -> Self {
        Addresses::Unix {
            source_address,
            destination_address,
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
    addresses: Addresses,
}

impl Header {
    /// Create a new instance of a header.
    pub fn new(
        version: Version,
        command: Command,
        protocol: Protocol,
        tlvs: Vec<Tlv>,
        addresses: Addresses,
    ) -> Header {
        Header {
            version,
            command,
            protocol,
            tlvs,
            addresses,
        }
    }

    /// Create a new instance of a header for version 1 with an unknown address family and protocol.
    pub fn unknown() -> Header {
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            tlvs: vec![],
            addresses: Addresses::None,
        }
    }

    /// Create a new instance of a header for version 1 with an unknown address family and protocol.
    pub fn version_1(addresses: Addresses) -> Header {
        Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            tlvs: vec![],
            addresses,
        }
    }

    /// Create a new instance of a header.
    pub fn no_address(version: Version, command: Command, protocol: Protocol) -> Header {
        Header {
            version,
            command,
            protocol,
            tlvs: vec![],
            addresses: Addresses::None,
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

    /// The addresses of the client and server connected to by the proxy.
    pub fn addresses(&self) -> &Addresses {
        &self.addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_version() {
        let version = Version::One;
        let header = Header::new(
            version.clone(),
            Command::Proxy,
            Protocol::Unspecified,
            vec![Tlv::new(1, vec![1, 2, 3]), Tlv::new(2, vec![1, 1])],
            Addresses::None,
        );
        let mut iter = header.tlvs();

        assert_eq!(&version, header.version());
        assert_eq!(&Protocol::Unspecified, header.protocol());
        assert_eq!(&Command::Proxy, header.command());
        assert_eq!(&Addresses::None, header.addresses());
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
            addresses: Addresses::None,
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
            addresses: ([127, 0, 0, 1], [127, 0, 0, 2], 1, 2).into(),
        };

        assert_eq!(
            expected,
            Header::version_1(([127, 0, 0, 1], [127, 0, 0, 2], 1, 2).into())
        );
    }

    #[test]
    fn header_no_address() {
        let expected = Header {
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            tlvs: vec![],
            addresses: Addresses::None,
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
}
