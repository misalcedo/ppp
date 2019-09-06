use ppp;

fn main() {
    println!("{:?}", ppp::text::parse_header(b"PROXY UNKNOWN\r\n"));
}