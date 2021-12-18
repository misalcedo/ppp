mod error;
mod model;

pub use error::ParseError;
pub use model::{AddressFamily, Command, Header, Protocol, Version};

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
        let tlvs = &input[MINIMUM_LENGTH..full_length];

        let mut current = &tlvs[..];
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

        Ok(Header {
            header,
            version,
            command,
            address_family,
            protocol,
            length,
        })
    }
}
