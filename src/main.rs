use ppp;

fn main() {
    println!("{:?}", ppp::text::parse_header(b"PROXY UNKNOWN\r\n"));
    println!("{:?}", unsafe { std::str::from_utf8_unchecked(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A][..]) });
    println!("{:?}", unsafe { std::str::from_utf8_unchecked(b"\r\n\r\n\0\r\nQUIT\n") });
}