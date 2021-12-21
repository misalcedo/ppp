use ppp::v1::BinaryParseError;
use ppp::v2::{Header, ParseError};
use ppp::{v1, v2, PartialResult};
use std::io::{self, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

const RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7777);
    let listener = TcpListener::bind(&address)?;

    println!("Server Listening on: {}", address);

    for stream in listener.incoming() {
        if let Err(error) = handle_connection(stream?) {
            eprintln!("[ERROR] {}", error);
        }
    }

    Ok(())
}

fn handle_connection(mut client: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 512];
    let mut read = client.read(&mut buffer)?;

    let header = read_v2_header(&mut client, &mut buffer, &mut read);

    match header {
        Ok(header) => println!("Header: {}", header),
        Err(error) => {
            eprintln!("[ERROR] {:?} {}", buffer, error);

            let header = read_v1_header(&mut client, &mut buffer, &mut read);

            match header {
                Ok(header) => println!("Header: {}", header),
                Err(error) => eprintln!("[ERROR] {:?} {}", buffer, error),
            }
        }
    }

    client.write_all(RESPONSE.as_bytes())?;
    client.flush()
}

fn read_v1_header(
    client: &mut TcpStream,
    mut buffer: &mut [u8; 512],
    mut read: &mut usize,
) -> Result<Header, BinaryParseError> {
    let mut header = v1::Header::try_from(&buffer[..read]);

    while header.is_incomplete() {
        println!("Incomplete text header. Read {} bytes so far.", read);

        read += client.read(&mut buffer[read..])?;
        header = v1::Header::try_from(&buffer[..read]);
    }

    header
}

fn read_v2_header(
    client: &mut TcpStream,
    mut buffer: &mut [u8; 512],
    mut read: &mut usize,
) -> Result<Header, ParseError> {
    let mut header = v2::Header::try_from(&buffer[..read]);

    while header.is_incomplete() {
        println!("Incomplete binary header. Read {} bytes so far.", read);

        read += client.read(&mut buffer[read..])?;
        header = v2::Header::try_from(&buffer[..read]);
    }

    header
}
