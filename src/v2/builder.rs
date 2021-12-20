use crate::v2::{Addresses, LENGTH, MINIMUM_LENGTH, PROTOCOL_PREFIX};

pub struct HeaderBuilder {
    header: Vec<u8>,
    version_command: u8,
    address_family_protocol: u8,
    length: Option<u16>,
}

impl HeaderBuilder {
    pub fn new(version_command: u8, address_family_protocol: u8, length: Option<u16>) -> Self {
        HeaderBuilder {
            header: Vec::new(),
            version_command,
            address_family_protocol,
            length,
        }
    }

    fn write_header(&mut self) {
        if !self.header.is_empty() {
            return;
        }

        let length = self.length.unwrap_or_default();

        self.header.reserve(MINIMUM_LENGTH + length as usize);
        self.header.extend(PROTOCOL_PREFIX);
        self.header.push(self.version_command);
        self.header.push(self.address_family_protocol);
        self.header.extend(length.to_be_bytes());
    }

    pub fn write_addresses(mut self, addresses: Addresses) -> Self {
        self.write_header();

        match addresses {
            Addresses::Unspecified => (),
            Addresses::IPv4(a) => {
                self.header.extend(a.source_address.octets());
                self.header.extend(a.destination_address.octets());
                self.header.extend(a.source_port.to_be_bytes());
                self.header.extend(a.destination_port.to_be_bytes());
            }
            Addresses::IPv6(a) => {
                self.header.extend(a.source_address.octets());
                self.header.extend(a.destination_address.octets());
                self.header.extend(a.source_port.to_be_bytes());
                self.header.extend(a.destination_port.to_be_bytes());
            }
            Addresses::Unix(a) => {
                self.header.extend(a.source);
                self.header.extend(a.destination);
            }
        }

        self
    }

    /// ## Panics
    /// When the length of the `value` for any TLV exceeds `u16::MAX`.
    pub fn write_tlvs<'a, T, I, II>(mut self, tlvs: II) -> Self
    where
        T: Into<u8>,
        I: Iterator<Item = (T, &'a [u8])>,
        II: IntoIterator<IntoIter = I, Item = I::Item>,
    {
        for (kind, value) in tlvs {
            self.header.push(kind.into());
            self.header.extend((value.len() as u16).to_be_bytes());
            self.header.extend(value);
        }

        self
    }

    pub fn write_type_length<T: Into<u8>>(mut self, kind: T, length: u16) -> Self {
        self.header.push(kind.into());
        self.header.extend(length.to_be_bytes());

        self
    }

    /// ## Panics
    /// When the length of `value` exceeds `u16::MAX`.
    pub fn write_tlv<T: Into<u8>>(mut self, kind: T, value: &[u8]) -> Self {
        self.header.push(kind.into());
        self.header.extend((value.len() as u16).to_be_bytes());
        self.header.extend(value);
        self
    }

    pub fn write(mut self, bytes: &[u8]) -> Self {
        self.write_header();
        self.header.extend(bytes);
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        self.write_header();

        if self.length.is_none() {
            let payload_length =
                u16::try_from(self.header[MINIMUM_LENGTH..].len()).unwrap_or_default();
            let length = payload_length.to_be_bytes();
            self.header[LENGTH..LENGTH + length.len()].copy_from_slice(length.as_slice());
        };

        self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{AddressFamily, Command, IPv4, IPv6, Protocol, Type, Unix, Version};

    #[test]
    fn build_no_payload() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x01, 0, 0]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::Unspecified | Protocol::Stream,
            Some(0),
        )
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_arbitrary_payload() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x01, 0, 1, 42]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::Unspecified | Protocol::Stream,
            None,
        )
        .write(&[42])
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 12, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187,
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
            Some(addresses.len()),
        )
        .write_addresses(addresses)
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv6() {
        let source_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ];
        let destination_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ];
        let addresses: Addresses = IPv6::new(source_address, destination_address, 80, 443).into();
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x20, 0x20, 0, 36]);
        expected.extend(source_address);
        expected.extend(destination_address);
        expected.extend([0, 80, 1, 187]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Local,
            AddressFamily::IPv6 | Protocol::Unspecified,
            Some(addresses.len()),
        )
        .write_addresses(addresses)
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_unix() {
        let source_address = [0xFFu8; 108];
        let destination_address = [0xAAu8; 108];

        let addresses: Addresses = Unix::new(source_address, destination_address).into();
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x20, 0x31, 0, 216]);
        expected.extend(source_address);
        expected.extend(destination_address);

        let header = HeaderBuilder::new(
            Version::Two | Command::Local,
            AddressFamily::Unix | Protocol::Stream,
            Some(addresses.len()),
        )
        .write_addresses(addresses)
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4_with_tlv() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 17, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187, 4, 0, 2, 0, 42,
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
            None,
        )
        .write_addresses(addresses)
        .write_tlvs(vec![(Type::NoOp, [0, 42].as_slice())])
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4_with_nested_tlv() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 20, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187, 20, 0, 5, 0, 0, 0, 0, 0
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
            None,
        )
        .write_addresses(addresses)
        .write_type_length(Type::SSL, 5)
        .write(&[0; 5])
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv6_with_tlvs() {
        let source_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ];
        let destination_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ];
        let addresses: Addresses = IPv6::new(source_address, destination_address, 80, 443).into();
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x20, 0x20, 0, 44]);
        expected.extend(source_address);
        expected.extend(destination_address);
        expected.extend([0, 80, 1, 187]);
        expected.extend([4, 0, 1, 0, 4, 0, 1, 42]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Local,
            AddressFamily::IPv6 | Protocol::Unspecified,
            None,
        )
        .write_addresses(addresses)
        .write_tlvs(vec![(Type::NoOp, [0].as_slice())])
        .write_tlv(Type::NoOp, [42].as_slice())
        .build();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_unix_with_tlv() {
        let source_address = [0xFFu8; 108];
        let destination_address = [0xAAu8; 108];

        let addresses: Addresses = Unix::new(source_address, destination_address).into();
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x20, 0x31, 0, 216]);
        expected.extend(source_address);
        expected.extend(destination_address);
        expected.extend([20, 0, 0]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Local,
            AddressFamily::Unix | Protocol::Stream,
            Some(216),
        )
        .write_addresses(addresses)
        .write_tlv(Type::SSL, &[])
        .build();

        assert_eq!(header, expected);
    }
}