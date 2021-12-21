use ppp::v1::Addresses;
use ppp::v2::{Builder, Command, Protocol, Type, Version};
use std::env::args;
use std::io::{self, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread::spawn;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8888);
    let proxy_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7777);

    let listener = TcpListener::bind(&listen_address).unwrap();

    println!("Listening on: {}", listen_address);
    println!("Proxying to: {}", proxy_address);

    for stream in listener.incoming() {
        if let Err(error) = handle_connection(stream?, &proxy_address) {
            eprintln!("[ERROR] {}", error);
        }
    }

    Ok(())
}

fn handle_connection(mut client_input: TcpStream, server_address: &SocketAddr) -> io::Result<()> {
    let mut server_input = TcpStream::connect_timeout(server_address, Duration::from_secs(1))?;

    client_input.set_nodelay(true)?;
    server_input.set_nodelay(true)?;

    let mut client_output = client_input.try_clone()?;
    let mut server_output = server_input.try_clone()?;

    let client_to_server = spawn(move || proxy_client_to_server(client_input, &mut server_output));
    let server_to_client = spawn(move || std::io::copy(&mut server_input, &mut client_output));

    client_to_server.join().unwrap()?;
    server_to_client.join().unwrap()?;

    Ok(())
}

fn proxy_client_to_server(
    mut client_input: TcpStream,
    mut server_output: &mut TcpStream,
) -> io::Result<()> {
    let client_address = client_input.peer_addr()?;
    let server_address = server_output.peer_addr()?;

    match args().nth(1).as_ref().map(String::as_str) {
        Some("v1") => write_v1_header(&mut server_output, client_address, server_address),
        _ => write_v2_header(&mut server_output, client_address, server_address),
    }

    let mut buffer = [0; 512];

    client_input.read(&mut buffer)?;
    server_output.write_all(&mut buffer)?;
    server_output.flush()
}

fn write_v2_header(
    mut server_output: &mut TcpStream,
    client_address: SocketAddr,
    server_address: SocketAddr,
) {
    println!("Writing v2 header.");

    let mut header = Builder::with_addresses(
        Version::Two | Command::Proxy,
        Protocol::Stream,
        (client_address, server_address),
    )
    .write_tlv(Type::NoOp, b"Hello, World!")?
    .build()?;

    for byte in header.drain(..) {
        server_output.write_all(&[byte])?;
        server_output.flush()?;
    }
}

fn write_v1_header(
    mut server_output: &mut TcpStream,
    client_address: SocketAddr,
    server_address: SocketAddr,
) {
    println!("Writing v1 header.");

    let header = Addresses::from((client_address, server_address)).to_string();

    for byte in header.as_bytes() {
        server_output.write_all(&[*byte])?;
        server_output.flush()?;
    }
}
