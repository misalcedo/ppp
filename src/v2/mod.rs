mod error;
mod model;

pub use error::ParseError;
use crate::ip::{IPv4, IPv6};
pub use model::{
    Addresses, AddressFamily, Command, Header, Protocol, TypeLengthValues, Unix, Version, ADDRESS_FAMILY_PROTOCOL,
    LENGTH, MINIMUM_LENGTH, PROTOCOL_PREFIX, VERSION_COMMAND,
};
use std::net::{Ipv4Addr, Ipv6Addr};

const LEFT_MASK: u8 = 0xF0;
const RIGH_MASK: u8 = 0x0F;

fn parse_addresses(address_family: AddressFamily, bytes: &[u8]) -> Addresses {
    match address_family {
        AddressFamily::Unspecified => Addresses::Unspecified,
        AddressFamily::IPv4 => {
            let source_address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let destination_address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            let source_port = u16::from_be_bytes([bytes[8], bytes[9]]);
            let destination_port = u16::from_be_bytes([bytes[10], bytes[11]]);

            Addresses::IPv4(IPv4 {
                source_address,
                destination_address,
                source_port,
                destination_port
            })
        },
        AddressFamily::IPv6 => {
            let mut address = [0; 16];

            address[..].copy_from_slice(&bytes[..16]);
            let source_address = Ipv6Addr::from(address);

            address[..].copy_from_slice(&bytes[16..32]);
            let destination_address = Ipv6Addr::from(address);

            let source_port = u16::from_be_bytes([bytes[32], bytes[33]]);
            let destination_port = u16::from_be_bytes([bytes[34], bytes[35]]);

            Addresses::IPv6(IPv6 {
                source_address,
                destination_address,
                source_port,
                destination_port
            })
        },
        AddressFamily::Unix => {
            let mut source = [0; 108];
            let mut destination = [0; 108];

            source[..].copy_from_slice(&bytes[..108]);
            destination[..].copy_from_slice(&bytes[108..]);

            Addresses::Unix(Unix {
                source,
                destination
            })
        },
    }
}

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = ParseError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        if input.len() < MINIMUM_LENGTH {
            return Err(ParseError::Incomplete(input.len()));
        }

        if &input[..VERSION_COMMAND] != PROTOCOL_PREFIX {
            return Err(ParseError::Prefix);
        }

        let version = match input[VERSION_COMMAND] & LEFT_MASK {
            0x20 => Version::Two,
            v => return Err(ParseError::Version(v)),
        };
        let command = match input[VERSION_COMMAND] & RIGH_MASK {
            0x00 => Command::Local,
            0x01 => Command::Proxy,
            c => return Err(ParseError::Command(c)),
        };

        let address_family = match input[ADDRESS_FAMILY_PROTOCOL] & LEFT_MASK {
            0x00 => AddressFamily::Unspecified,
            0x10 => AddressFamily::IPv4,
            0x20 => AddressFamily::IPv6,
            0x30 => AddressFamily::Unix,
            a => return Err(ParseError::AddressFamily(a)),
        };
        let protocol = match input[ADDRESS_FAMILY_PROTOCOL] & RIGH_MASK {
            0x00 => Protocol::Unspecified,
            0x01 => Protocol::Stream,
            0x02 => Protocol::Datagram,
            p => return Err(ParseError::Protocol(p)),
        };

        let length = u16::from_be_bytes([input[LENGTH], input[LENGTH + 1]]);
        let address_family_bytes = address_family.byte_length().unwrap_or_default();

        if (length as usize) < address_family_bytes {
            return Err(ParseError::InvalidAddresses(length, address_family_bytes));
        }

        let full_length = MINIMUM_LENGTH + length as usize;

        if input.len() < full_length {
            return Err(ParseError::Partial(length, input.len() - MINIMUM_LENGTH));
        }

        let header = &input[..full_length];
        let addresses = parse_addresses(address_family, &header[MINIMUM_LENGTH..]);

        Ok(Header {
            header,
            version,
            command,
            protocol,
            length,
            addresses
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{IPv4, IPv6};

    #[test]
    fn no_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let expected = Header {
            header: input.as_slice(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            length: 12,
            addresses: IPv4::new([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into()
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.address_family(), AddressFamily::IPv4);
        assert_eq!(actual.address_bytes(), &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]);
        assert_eq!(actual.additional_bytes(), &[]);
    }

    #[test]
    fn no_tlvs_unspec() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x00);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let expected = Header {
            header: input.as_slice(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            length: 12,
            addresses: Addresses::Unspecified
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert_eq!(actual.address_bytes(), &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]);
        assert_eq!(actual.additional_bytes(), &[]);
    }

    #[test]
    fn no_tlvs_unspec_stream() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x01);
        input.extend(&[0, 8]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);

        let expected = Header {
            header: input.as_slice(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            length: 8,
            addresses: Addresses::Unspecified
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert_eq!(actual.address_bytes(), &[127, 0, 0, 1, 127, 0, 0, 2]);
        assert_eq!(actual.additional_bytes(), &[]);
        
    }

    #[test]
    fn no_tlvs_unspec_ipv4() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x10);
        input.extend(&[0, 8]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::InvalidAddresses(8, 12));
    }
    
    #[test]
    fn invalid_version() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x11);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Version(0x10));
    }

    #[test]
    fn invalid_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x51);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::AddressFamily(0x50));    }

    #[test]
    fn invalid_command() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x23);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Command(0x03));
    }

    #[test]
    fn invalid_protocol() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x17);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Protocol(0x07));
    }

    #[test]
    fn proxy_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[42]);

        let expected = Header {
            header: &input[..input.len() - 1],
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            length: 12,
            addresses: IPv4::new([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into()
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.address_family(), AddressFamily::IPv4);
        assert_eq!(actual.address_bytes(), &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]);
        assert_eq!(actual.additional_bytes(), &[]);
    }

    /*
    #[test]
    fn with_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend(&[0, 45]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF2],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
                        80,
                        443
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn tlvs_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend(&[0, 45]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[2, 0, 2, 5, 5][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1],
                        80,
                        443
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn unix_tlvs_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x30);
        input.extend(&[0, 225]);
        input.extend(&[0xFFu8; 108][..]);
        input.extend(&[0xAAu8; 108][..]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[2, 0, 2, 5, 5][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    ([0xFFFFFFFFu32; 27], [0xAAAAAAAAu32; 27]).into(),
                )
            ))
        )
    }

    #[test]
    fn with_tlvs_without_ports() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x20);
        input.extend(&[0, 41]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ]);
        input.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        input.extend(&[1, 0, 1, 5]);
        input.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
                    (
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF],
                        [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1]
                    )
                        .into(),
                )
            ))
        )
    }

    #[test]
    fn partial_tlv() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 15]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(!Header::try_from(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn missing_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 17]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(Header::try_from(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn partial_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend(&[0, 16]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[1, 187]);
        input.extend(&[1, 0, 1]);

        assert!(Header::try_from(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn no_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend(&[0, 0]);
        input.extend(&[0, 80]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[0, 80][..],
                Header::new(
                    Version::Two,
                    Command::Local,
                    Protocol::Datagram,
                    vec![],
                    Addresses::None,
                )
            ))
        );
    }

    #[test]
    fn unspecified_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend(&[0, 12]);
        input.extend(&[127, 0, 0, 1]);
        input.extend(&[127, 0, 0, 2]);
        input.extend(&[0, 80]);
        input.extend(&[0xbb, 1]);

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Local,
                    Protocol::Datagram,
                    vec![],
                    Addresses::None,
                )
            ))
        );
    }

    #[test]
    fn missing_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x22);
        input.extend(&[0, 0]);
        input.extend(&[0, 80]);

        assert!(Header::try_from(&input[..]).unwrap_err().is_incomplete());
    }

    #[test]
    fn not_prefixed() {
        let result = Header::try_from(b"\r\n\r\n\x01\r\nQUIT\n");

        assert!(!result.unwrap_err().is_incomplete());
    }

    #[test]
    fn incomplete() {
        let bytes = [0x0D, 0x0A, 0x0D, 0x0A, 0x00];
        let result = Header::try_from(&bytes[..]);

        assert!(result.unwrap_err().is_incomplete());
    }

    #[test]
    fn to_bytes_ipv4_without_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Stream,
            vec![],
            ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        output.extend_from_slice(PROTOCOL_PREFIX);
        output.push(0x21);
        output.push(0x11);
        output.extend(&[0, 12]);
        output.extend(&[127, 0, 0, 1]);
        output.extend(&[127, 0, 0, 2]);
        output.extend(&[0, 80]);
        output.extend(&[1, 187]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_unspec() {
        let header = Header::new(
            Version::Two,
            Command::Local,
            Protocol::Unspecified,
            vec![],
            Addresses::None,
        );
        let mut output: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        output.extend_from_slice(PROTOCOL_PREFIX);
        output.push(0x20);
        output.push(0x00);
        output.extend(&[0, 0]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_unix_with_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Unspecified,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            ([0xFFFFFFFFu32; 27], [0xAAAAAAAAu32; 27]).into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        output.extend_from_slice(PROTOCOL_PREFIX);
        output.push(0x21);
        output.push(0x30);
        output.extend(&[0, 225]);
        output.extend(&[0xFFu8; 108][..]);
        output.extend(&[0xAAu8; 108][..]);
        output.extend(&[1, 0, 1, 5]);
        output.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_ipv6_with_tlvs() {
        let header = Header::new(
            Version::Two,
            Command::Proxy,
            Protocol::Stream,
            vec![Tlv::new(1, vec![5]), Tlv::new(2, vec![5, 5])],
            (
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF2,
                ],
                [
                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFF1,
                ],
                80,
                443,
            )
                .into(),
        );
        let mut output: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        output.extend_from_slice(PROTOCOL_PREFIX);
        output.push(0x21);
        output.push(0x21);
        output.extend(&[0, 45]);
        output.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ]);
        output.extend(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ]);
        output.extend(&[0, 80]);
        output.extend(&[1, 187]);
        output.extend(&[1, 0, 1, 5]);
        output.extend(&[2, 0, 2, 5, 5]);

        assert_eq!(to_bytes(header), Ok(output));
    }

    #[test]
    fn to_bytes_verion_one() {
        let header = Header::unknown();
        assert!(to_bytes(header).is_err());
    }
    */
}
