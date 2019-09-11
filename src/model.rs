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
            _ => Err(())
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
            _ => Err(())
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
            _ => Err(())
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

/// An Internet Protocol address in bytes.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl From<[u8; 4]> for IpAddress {
    fn from(address: [u8; 4]) -> Self {
        IpAddress::V4(address)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(address: [u8; 16]) -> Self {
        IpAddress::V6(address)
    }
}

/// An reference to a destination; either remote or local.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Address {
    InternetProtocol {
        address: IpAddress,
        port: u16,
    },
    Unix,
}

impl Address {
    /// Create a new instance of an address.
    /// If the address is not valid, returns an error.
    pub fn new_unix(bytes: &[u8]) -> Result<Address, ()> {
        match bytes.len() {
            128 => Ok(Address::Unix),
            _ => Err(())
        }
    }

    /// Create a new instance of an address.
    /// If the address is not valid, returns an error.
    pub fn new_ip(port: u16, bytes: &[u8]) -> Result<Address, ()> {
        match bytes.len() {
            4 => {
                let mut address: [u8; 4] = [0; 4];

                address.copy_from_slice(bytes);

                Ok((port, address).into())
            }
            16 => {
                let mut address: [u8; 16] = [0; 16];

                address.copy_from_slice(bytes);

                Ok((port, address).into())
            }
            _ => Err(())
        }
    }
}

impl From<(u16, [u8; 4])> for Address {
    fn from((port, address): (u16, [u8; 4])) -> Self {
        Address::InternetProtocol { port, address: address.into() }
    }
}

impl From<(u16, [u8; 16])> for Address {
    fn from((port, address): (u16, [u8; 16])) -> Self {
        Address::InternetProtocol { port, address: address.into() }
    }
}

impl From<[u8; 128]> for Address {
    fn from(_path: [u8; 128]) -> Self {
        Address::Unix
    }
}

/// A parsed proxy protocol header.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Header {
    version: Version,
    command: Command,
    protocol: Option<Protocol>,
    tlvs: Vec<Tlv>,
    source_address: Option<Address>,
    destination_address: Option<Address>,
}

impl Header {
    /// Create a new instance of a header.
    pub fn new(
        version: Version,
        command: Command,
        protocol: Option<Protocol>,
        tlvs: Vec<Tlv>,
        source_address: Option<Address>,
        destination_address: Option<Address>,
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
            protocol: None,
            tlvs: vec![],
            source_address: None,
            destination_address: None,
        }
    }

    /// The version of the parsed header.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The command of the parsed header.
    pub fn protocol(&self) -> Option<&Protocol> {
        self.protocol.as_ref()
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
    pub fn source_address(&self) -> Option<&Address> {
        self.source_address.as_ref()
    }

    /// The destination address of the server connected to by the proxy.
    pub fn destination_address(&self) -> Option<&Address> {
        self.destination_address.as_ref()
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
            None,
            vec![Tlv::new(1, vec![1, 2, 3]), Tlv::new(2, vec![1, 1])],
            None,
            None,
        );
        let mut iter = header.tlvs();

        assert_eq!(&version, header.version());
        assert_eq!(None, header.protocol());
        assert_eq!(&Command::Proxy, header.command());
        assert_eq!(None, header.source_address());
        assert_eq!(None, header.destination_address());
        assert_eq!(Some(&Tlv::new(1, vec![1, 2, 3])), iter.next());
        assert_eq!(Some(&Tlv::new(2, vec![1, 1])), iter.next());
        assert_eq!(None, iter.next());
    }

    #[test]
    fn header_unknown() {
        let expected = Header {
            version: Version::One,
            command: Command::Proxy,
            protocol: None,
            tlvs: vec![],
            source_address: None,
            destination_address: None,
        };

        assert_eq!(expected, Header::unknown());
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
    fn ip_address() {
        assert_eq!(IpAddress::V4([127, 0, 0, 1]), [127, 0, 0, 1].into());
        assert_eq!(
            IpAddress::V6([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]),
            [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255].into()
        );
    }

    #[test]
    fn address() {
        let ipv6 = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];

        assert_eq!(Err(()), Address::new_unix(&[1, 2, 3, 4, 5][..]));
        assert_eq!(Ok(Address::Unix), Address::new_unix(&[0; 128][..]));
        assert_eq!(Err(()), Address::new_ip(1, &[1, 2, 3, 4, 5][..]));
        assert_eq!(
            Ok(Address::InternetProtocol {
                address: IpAddress::V4([127, 0, 0, 1]),
                port: 3456,
            }),
            Address::new_ip(3456, &[127, 0, 0, 1][..])
        );
        assert_eq!(
            Ok(Address::InternetProtocol { address: IpAddress::V6(ipv6.clone()), port: 12345 }),
            Address::new_ip(12345, &ipv6[..])
        );
    }
}