use ppp::v2::Builder;
use std::io::{self, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
use std::thread::spawn;

fn handle_connection(mut client_input: TcpStream, server_address: &SocketAddr) -> io::Result<()> {    
    let mut server_input = TcpStream::connect_timeout(server_address, Duration::from_secs(1))?;
    
    client_input.set_nodelay(true)?;
    server_input.set_nodelay(true)?;

    let mut client_output = client_input.try_clone()?;
    let mut server_output = server_input.try_clone()?;
    
    let client_to_server = spawn(move || {
        let mut buffer = [0; 1];

        client_input.read(&mut buffer)?;
        server_output.write_all(&mut buffer)?;
        server_output.flush()
    });
    let server_to_client = spawn(move || {
        std::io::copy(&mut server_input, &mut client_output)
    });


    client_to_server.join();
    server_to_client.join();
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8888);
    let proxy_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7777);

    let listener = TcpListener::bind(&listen_address).unwrap();

    println!("Listening on: {}", listen_address);
    println!("Proxying to: {}", proxy_address);

    for stream in listener.incoming() {
        handle_connection(stream?, &proxy_address)?;
    }

    Ok(())
}