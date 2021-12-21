use ppp::{v1, v2, PartialResult};
use std::io::{self, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

const RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";

fn handle_connection(mut client: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 512];
    let mut read = client.read(&mut buffer)?;

    let mut header = v2::Header::try_from(&buffer[..read]);

    while header.is_incomplete() {
        println!("Incomplete binary header. Read {} bytes so far.", read);

        read += client.read(&mut buffer[read..])?;
        header = v2::Header::try_from(&buffer[..read]);
    }

    match header {
        Ok(header) => println!("Header: {}", header),
        Err(error) => {
            eprintln!("[ERROR] {:?} {}", buffer, error);

            let mut header = v1::Header::try_from(&buffer[..read]);

            while header.is_incomplete() {
                println!("Incomplete text header. Read {} bytes so far.", read);

                read += client.read(&mut buffer[read..])?;
                header = v1::Header::try_from(&buffer[..read]);
            }

            match header {
                Ok(header) => println!("Header: {}", header),
                Err(error) => eprintln!("[ERROR] {:?} {}", buffer, error),
            }
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
