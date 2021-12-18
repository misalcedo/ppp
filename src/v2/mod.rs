mod error;
mod model;

pub use error::ParseError;
pub use model::{Command, Header, Version};

const PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
const VERSION_COMMAND: usize = PROTOCOL_PREFIX.len();
const ADDRESS_FAMILY_PROTOCOL: usize = VERSION_COMMAND + 1;
const LENGTH: usize = ADDRESS_FAMILY_PROTOCOL + 1;
const MINIMUM_LENGTH: usize = LENGTH + 2;

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = ParseError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        if input.len() < MINIMUM_LENGTH {
            return Err(ParseError::Incomplete);
        }

        if &input[..VERSION_COMMAND] != PROTOCOL_PREFIX {
            return Err(ParseError::Prefix);
        }

        let version = match input[VERSION_COMMAND] & 0xF0 {
            0x20 => Version::Two,
            _ => return Err(ParseError::Version) 
        };
        let command = match input[VERSION_COMMAND] & 0x0F {
            0x00 => Command::Local,
            0x01 => Command::Proxy,
            _ => return Err(ParseError::Command)
        };

        // (AddressFamily, Protocol), u16
        let mut length = [0, 0];
        let length = u16::from_be_bytes([0, 1]);

        Ok(Header {
            header: input
        })
    }
}