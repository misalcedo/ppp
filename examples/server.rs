use ppp::{PartialResult, v1, v2};
use std::io::{self, prelude::*};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::time::Duration;

const RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";

fn handle_connection(mut client: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 512];

    client.read(&mut buffer)?;
    client.write_all(RESPONSE.as_bytes())?;
    client.flush()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7777);
    let listener = TcpListener::bind(&address)?;

    println!("Server Listening on: {}", address);

    for stream in listener.incoming() {
        let stream = stream?;

        handle_connection(stream)?;
    }

    Ok(())
}