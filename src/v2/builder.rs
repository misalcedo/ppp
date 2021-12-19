use crate::v2::{Addresses, MINIMUM_LENGTH, PROTOCOL_PREFIX};

pub struct HeaderBuilder {
    header: Vec<u8>,
    version_command: u8,
    address_family_protocol: u8,
    length: u16,
}

impl HeaderBuilder {
    pub fn new(version_command: u8, address_family_protocol: u8, length: u16) -> Self {
        println!("{}, {}, {}", version_command,address_family_protocol, length);
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

        self.header
            .reserve_exact(MINIMUM_LENGTH + self.length as usize);
        self.header.extend(PROTOCOL_PREFIX);
        self.header.push(self.version_command);
        self.header.push(self.address_family_protocol);
        self.header.extend(self.length.to_be_bytes());
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

    pub fn build(mut self) -> Vec<u8> {
        self.write_header();
        self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{AddressFamily, Command, IPv4, IPv6, Protocol, Unix, Version};

    #[test]
    fn build_no_payload() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x01, 0, 0]);

        let header = HeaderBuilder::new(
            Version::Two | Command::Proxy,
            AddressFamily::Unspecified | Protocol::Stream,
            0,
        )
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
            addresses.len(),
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
            addresses.len(),
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
            addresses.len(),
        )
        .write_addresses(addresses)
        .build();

        assert_eq!(header, expected);
    }
}
