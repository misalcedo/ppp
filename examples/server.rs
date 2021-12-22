use ppp::{HeaderResult, PartialResult};
use std::io::{self, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

const RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";

fn handle_connection(mut client: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 512];
    let mut read = client.read(&mut buffer)?;

    let mut header = HeaderResult::parse(&buffer[..read]);

    while header.is_incomplete() {
        println!("Incomplete header. Read {} bytes so far.", read);

        read += client.read(&mut buffer[read..])?;
        header = HeaderResult::parse(&buffer[..read]);
    }

    match header {
        HeaderResult::V1(Ok(header)) => println!("V1 Header: {}", header),
        HeaderResult::V2(Ok(header)) => println!("V2 Header: {}", header),
        HeaderResult::V1(Err(error)) => {
            eprintln!("[ERROR] V1 {:?} {}", buffer, error);
        }
        HeaderResult::V2(Err(error)) => {
            eprintln!("[ERROR] V2 {:?} {}", buffer, error);
        }
    }

    client.write_all(RESPONSE.as_bytes())?;
    client.flush()
}

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
