mod error;
mod model;

pub use error::ParseError;
pub use model::{AddressFamily, Command, Header, Protocol, TypeLengthValues, Version};

const PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
const VERSION_COMMAND: usize = PROTOCOL_PREFIX.len();
const ADDRESS_FAMILY_PROTOCOL: usize = VERSION_COMMAND + 1;
const LENGTH: usize = ADDRESS_FAMILY_PROTOCOL + 1;
const MINIMUM_LENGTH: usize = LENGTH + 2;
const LEFT_MASK: u8 = 0xF0;
const RIGH_MASK: u8 = 0xF0;

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = ParseError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        if input.len() < MINIMUM_LENGTH {
            return Err(ParseError::Incomplete);
        }

        if &input[..VERSION_COMMAND] != PROTOCOL_PREFIX {
            return Err(ParseError::Prefix);
        }

        let version = match input[VERSION_COMMAND] & LEFT_MASK {
            0x20 => Version::Two,
            _ => return Err(ParseError::Version),
        };
        let command = match input[VERSION_COMMAND] & RIGH_MASK {
            0x00 => Command::Local,
            0x01 => Command::Proxy,
            _ => return Err(ParseError::Command),
        };

        let address_family = match input[ADDRESS_FAMILY_PROTOCOL] & LEFT_MASK {
            0x00 => AddressFamily::Unspecified,
            0x10 => AddressFamily::IPv4,
            0x20 => AddressFamily::IPv6,
            0x30 => AddressFamily::Unix,
            _ => return Err(ParseError::AddressFamily),
        };
        let protocol = match input[ADDRESS_FAMILY_PROTOCOL] & RIGH_MASK {
            0x00 => Protocol::Unspecified,
            0x01 => Protocol::Stream,
            0x02 => Protocol::Datagram,
            _ => return Err(ParseError::Protocol),
        };

        let length = u16::from_be_bytes([input[LENGTH], input[LENGTH + 1]]);
        let full_length = MINIMUM_LENGTH + length as usize;

        if input.len() < full_length {
            return Err(ParseError::TLVs);
        }

        let header = &input[..full_length];

        let mut current = &input[MINIMUM_LENGTH..full_length];
        while current.len() >= 3 { 
            let full_length = (3 + u16::from_be_bytes([input[1], input[2]])) as usize;
            
            if current.len() < full_length {
                return Err(ParseError::TLVs);
            }
            
            current = &current[full_length..];
        }

        if current.len() != 0 {
            return Err(ParseError::TLVs);
        }

        let tlvs = TypeLengthValues {
            buffer: &input[MINIMUM_LENGTH..full_length]
        };

        Ok(Header {
            header,
            version,
            command,
            address_family,
            protocol,
            length,
            tlvs
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
                )
            ))
        );
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

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![],
                    Addresses::None,
                )
            ))
        );
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

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    Addresses::None,
                )
            ))
        );
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

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Unspecified,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2]).into(),
                )
            ))
        );
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

        assert!(!Header::try_from(&input[..]).unwrap_err().is_incomplete());
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

        assert!(!Header::try_from(&input[..]).unwrap_err().is_incomplete());
    }

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

        assert!(!Header::try_from(&input[..]).unwrap_err().is_incomplete());
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

        assert!(!Header::try_from(&input[..]).unwrap_err().is_incomplete());
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

        assert_eq!(
            Header::try_from(&input[..]),
            Ok((
                &[42][..],
                Header::new(
                    Version::Two,
                    Command::Proxy,
                    Protocol::Stream,
                    vec![],
                    ([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
                )
            ))
        );
    }

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
}