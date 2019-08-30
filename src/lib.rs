#![feature(test)]

mod text;
mod binary;
mod error;
mod parser;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
