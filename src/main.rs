use ppp;

fn main() {
    println!("{:?}", ppp::text::parse_v1_header(b"PROXY UNKNOWN\r\n"));
}