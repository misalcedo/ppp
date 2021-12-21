use crate::v2::{
    Addresses, Protocol, Type, TypeLengthValue, TypeLengthValues, LENGTH, MINIMUM_LENGTH,
    MINIMUM_TLV_LENGTH, PROTOCOL_PREFIX,
};
use std::io::{self, Write};

#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Builder {
    header: Option<Vec<u8>>,
    version_command: u8,
    address_family_protocol: u8,
    addresses: Option<Addresses>,
    length: Option<u16>,
    additional_capacity: usize,
}

impl Writer {
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<Vec<u8>> for Writer {
    fn from(bytes: Vec<u8>) -> Self {
        Writer { bytes }
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len() > (u16::MAX as usize) + MINIMUM_LENGTH {
            Err(io::ErrorKind::WriteZero.into())
        } else {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub trait WriteToHeader {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize>;

    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut writer = Writer::default();

        self.write_to(&mut writer)?;

        Ok(writer.finish())
    }
}

impl WriteToHeader for Addresses {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        match self {
            Addresses::Unspecified => (),
            Addresses::IPv4(a) => {
                writer.write_all(a.source_address.octets().as_slice())?;
                writer.write_all(a.destination_address.octets().as_slice())?;
                writer.write_all(a.source_port.to_be_bytes().as_slice())?;
                writer.write_all(a.destination_port.to_be_bytes().as_slice())?;
            }
            Addresses::IPv6(a) => {
                writer.write_all(a.source_address.octets().as_slice())?;
                writer.write_all(a.destination_address.octets().as_slice())?;
                writer.write_all(a.source_port.to_be_bytes().as_slice())?;
                writer.write_all(a.destination_port.to_be_bytes().as_slice())?;
            }
            Addresses::Unix(a) => {
                writer.write_all(a.source.as_slice())?;
                writer.write_all(a.destination.as_slice())?;
            }
        };

        Ok(self.len())
    }
}

impl<'a> WriteToHeader for TypeLengthValue<'a> {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        if self.value.len() > u16::MAX as usize {
            return Err(io::ErrorKind::WriteZero.into());
        }

        writer.write_all([self.kind].as_slice())?;
        writer.write_all((self.value.len() as u16).to_be_bytes().as_slice())?;
        writer.write_all(self.value)?;

        Ok(MINIMUM_TLV_LENGTH + self.value.len())
    }
}

impl<'a> WriteToHeader for TypeLengthValues<'a> {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        let bytes = self.as_bytes();

        writer.write_all(bytes)?;

        Ok(bytes.len())
    }
}

impl WriteToHeader for [u8] {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        let slice = self.as_ref();

        if slice.len() > u16::MAX as usize {
            return Err(io::ErrorKind::WriteZero.into());
        }

        writer.write_all(slice)?;

        Ok(slice.len())
    }
}

impl<T: ?Sized + WriteToHeader> WriteToHeader for &T {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        (*self).write_to(writer)
    }
}

impl WriteToHeader for Type {
    fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
        writer.write([(*self).into()].as_slice())
    }
}

macro_rules! impl_write_to_header {
    ($t:ident) => {
        impl WriteToHeader for $t {
            fn write_to(&self, writer: &mut Writer) -> io::Result<usize> {
                let bytes = self.to_be_bytes();

                writer.write_all(bytes.as_slice())?;

                Ok(bytes.len())
            }
        }
    };
}

impl_write_to_header!(u8);
impl_write_to_header!(u16);
impl_write_to_header!(u32);
impl_write_to_header!(u64);
impl_write_to_header!(u128);
impl_write_to_header!(usize);

impl_write_to_header!(i8);
impl_write_to_header!(i16);
impl_write_to_header!(i32);
impl_write_to_header!(i64);
impl_write_to_header!(i128);
impl_write_to_header!(isize);

impl Builder {
    pub fn new(version_command: u8, address_family_protocol: u8) -> Self {
        Builder {
            header: None,
            version_command,
            address_family_protocol,
            addresses: None,
            length: None,
            additional_capacity: 0,
        }
    }

    pub fn with_addresses<T: Into<Addresses>>(
        version_command: u8,
        protocol: Protocol,
        addresses: T,
    ) -> Self {
        let addresses = addresses.into();

        Builder {
            header: None,
            version_command,
            address_family_protocol: addresses.address_family() | protocol,
            addresses: Some(addresses),
            length: None,
            additional_capacity: 0,
        }
    }

    pub fn reserve_capacity(mut self, capacity: usize) -> Self {
        if let Some(header) = self.header.as_mut() {
            header.reserve(capacity);
        } else {
            self.additional_capacity += capacity;
        }

        self
    }

    pub fn set_length<T: Into<Option<u16>>>(mut self, length: T) -> Self {
        self.length = length.into();
        self
    }

    pub fn write_payload<T: WriteToHeader>(mut self, payload: T) -> io::Result<Self> {
        self.write_header()?;
        self.write_internal(payload)?;

        Ok(self)
    }

    pub fn write_tlv(self, kind: impl Into<u8>, value: &[u8]) -> io::Result<Self> {
        self.write_payload(TypeLengthValue::new(kind, value))
    }

    fn write_internal<T: WriteToHeader>(&mut self, payload: T) -> io::Result<()> {
        let mut writer = Writer::from(self.header.take().unwrap_or_default());

        payload.write_to(&mut writer)?;

        self.header = Some(writer.finish());

        Ok(())
    }

    fn write_header(&mut self) -> io::Result<()> {
        if self.header.is_some() {
            return Ok(());
        }

        let addresses_length = self
            .addresses
            .as_ref()
            .map(Addresses::len)
            .unwrap_or_default();
        let mut header =
            Vec::with_capacity(MINIMUM_LENGTH + addresses_length + self.additional_capacity);

        let length = self.length.unwrap_or_default();

        header.extend_from_slice(PROTOCOL_PREFIX);
        header.push(self.version_command);
        header.push(self.address_family_protocol);
        header.extend_from_slice(length.to_be_bytes().as_slice());

        self.header = Some(header);

        if let Some(addresses) = self.addresses {
            self.write_internal(addresses)?;
        }

        Ok(())
    }

    pub fn build(mut self) -> io::Result<Vec<u8>> {
        self.write_header()?;

        let mut header = self.header.take().unwrap_or_default();

        if self.length.is_some() {
            return Ok(header);
        }

        if let Ok(payload_length) = u16::try_from(header[MINIMUM_LENGTH..].len()) {
            let length = payload_length.to_be_bytes();
            header[LENGTH..LENGTH + length.len()].copy_from_slice(length.as_slice());
            Ok(header)
        } else {
            Err(io::ErrorKind::WriteZero.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{AddressFamily, Command, IPv4, IPv6, Protocol, Type, Unix, Version};

    #[test]
    fn build_length_too_small() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x12, 0, 1, 0, 0, 0, 1]);

        let actual = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
        )
        .set_length(1)
        .write_payload(1u32)
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn build_payload_too_long() {
        let error = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
        )
        .write_payload(vec![0u8; (u16::MAX as usize) + 1].as_slice())
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn build_no_payload() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x01, 0, 0]);

        let header = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::Unspecified | Protocol::Stream,
        )
        .build()
        .unwrap();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_arbitrary_payload() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x21, 0x01, 0, 1, 42]);

        let header = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::Unspecified | Protocol::Stream,
        )
        .write_payload(42u8)
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 12, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187,
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
        )
        .set_length(addresses.len() as u16)
        .write_payload(addresses)
        .unwrap()
        .build()
        .unwrap();

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
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([0x20, 0x20, 0, 36]);
        expected.extend(source_address);
        expected.extend(destination_address);
        expected.extend([0, 80, 1, 187]);

        let header = Builder::with_addresses(
            Version::Two | Command::Local,
            Protocol::Unspecified,
            IPv6::new(source_address, destination_address, 80, 443),
        )
        .build()
        .unwrap();

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

        let header = Builder::new(
            Version::Two | Command::Local,
            AddressFamily::Unix | Protocol::Stream,
        )
        .reserve_capacity(addresses.len())
        .write_payload(addresses)
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4_with_tlv() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 17, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187, 4, 0, 2, 0, 42,
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header =
            Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Datagram, addresses)
                .reserve_capacity(5)
                .write_tlv(Type::NoOp, [0, 42].as_slice())
                .unwrap()
                .build()
                .unwrap();

        assert_eq!(header, expected);
    }

    #[test]
    fn build_ipv4_with_nested_tlv() {
        let mut expected = Vec::from(PROTOCOL_PREFIX);
        expected.extend([
            0x21, 0x12, 0, 20, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187, 20, 0, 5, 0, 0, 0, 0, 0,
        ]);

        let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
        let header = Builder::new(
            Version::Two | Command::Proxy,
            AddressFamily::IPv4 | Protocol::Datagram,
        )
        .write_payload(addresses)
        .unwrap()
        .write_payload(Type::SSL)
        .unwrap()
        .write_payload(5u16)
        .unwrap()
        .write_payload([0u8; 5].as_slice())
        .unwrap()
        .build()
        .unwrap();

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
        expected.extend([0x20, 0x20, 0, 48]);
        expected.extend(source_address);
        expected.extend(destination_address);
        expected.extend([0, 80, 1, 187]);
        expected.extend([4, 0, 1, 0, 4, 0, 1, 0, 4, 0, 1, 42]);

        let header = Builder::new(
            Version::Two | Command::Local,
            AddressFamily::IPv6 | Protocol::Unspecified,
        )
        .write_payload(addresses)
        .unwrap()
        .write_tlv(Type::NoOp, [0].as_slice())
        .unwrap()
        .write_tlv(Type::NoOp, [0].as_slice())
        .unwrap()
        .write_tlv(Type::NoOp, [42].as_slice())
        .unwrap()
        .build()
        .unwrap();

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

        let header = Builder::new(
            Version::Two | Command::Local,
            AddressFamily::Unix | Protocol::Stream,
        )
        .set_length(216)
        .write_payload(addresses)
        .unwrap()
        .write_tlv(Type::SSL, &[])
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(header, expected);
    }
}
