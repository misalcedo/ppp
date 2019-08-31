#![feature(test)]

mod binary;
mod error;
mod text;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
