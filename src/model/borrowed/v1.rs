pub struct Header<'a> {
    header: &'a str,
    adresses: Addresses<'a>
}

pub enum Addresses<'a> {
    Tcp4(Tcp<'a>),
    Tcp6(Tcp<'a>),
    Unknown(Unknown<'a>)
}

pub struct Tcp<'a> {
    source_address: &'a str,
    source_port: &'a str,
    destination_address: &'a str,
    destination_port: &'a str,
}

pub struct Unknown<'a> {
    addresses: &'a str
}