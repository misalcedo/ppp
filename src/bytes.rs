use std::slice::Iter;

/// A finite stream of bytes.
/// Once the stream returns `None`, the stream has ended.
/// An open stream with no bytes to read will return `Some(0)`.
pub trait Stream {
    /// Reads a single byte from the stream.
    fn read(&mut self) -> Option<u8>;

    /// Reads at most `buffer.len` bytes into the buffer.
    /// Returns how many bytes were read.
    fn read_buffered(&mut self, buffer: &mut [u8]) -> Option<usize>;
}

impl Stream for Iter<'_, u8> {
    /// Reads the next byte from the iterator.
    fn read(&mut self) -> Option<u8> {
        self.next().copied()
    }

    /// Reads at most the next `buffer.len()` bytes from the iterator.
    fn read_buffered(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if buffer.len() == 0 {
            panic!("Must use a non-zero sized buffer.")
        }

        let mut read = 0;

        for next in self.take(buffer.len()) {
            buffer[read] = *next;
            read += 1;
        }

        if read == 0 { None } else { Some(read) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_empty_iter() {
        let mut stream: Iter<u8> = [].iter();

        assert_eq!(stream.read(), None);
    }

    #[test]
    fn read_iter() {
        let mut stream: Iter<u8> = [1, 2, 3].iter();

        assert_eq!(stream.read(), Some(1));
        assert_eq!(stream.read(), Some(2));
        assert_eq!(stream.read(), Some(3));
        assert_eq!(stream.read(), None);
    }

    #[test]
    fn read_buffered_empty_buffer() {
        let mut stream: Iter<u8> = [1, 2, 3].iter();
        let mut buffer: [u8; 0] = [];

        let result = std::panic::catch_unwind(move || stream.read_buffered(&mut buffer));
        assert!(result.is_err());
    }

    #[test]
    fn read_buffered_empty_stream() {
        let mut stream: Iter<u8> = [].iter();
        let mut buffer: [u8; 128] = [0; 128];

        assert_eq!(stream.read_buffered(&mut buffer), None);
    }

    #[test]
    fn read_buffered_smaller_stream() {
        let mut stream: Iter<u8> = [1, 2, 3].iter();
        let mut buffer: [u8; 128] = [0; 128];

        assert_eq!(stream.read_buffered(&mut buffer), Some(3));
        assert_eq!(buffer[0..3], [1, 2, 3]);

        assert_eq!(stream.read_buffered(&mut buffer), None);
        assert_eq!(buffer[0..3], [1, 2, 3]);
    }

    #[test]
    fn read_buffered_smaller_buffer() {
        let mut stream: Iter<u8> = [1, 2, 3].iter();
        let mut buffer: [u8; 2] = [0; 2];

        assert_eq!(stream.read_buffered(&mut buffer), Some(2));
        assert_eq!(buffer, [1, 2]);

        assert_eq!(stream.read_buffered(&mut buffer), Some(1));
        assert_eq!(buffer[0..1], [3]);

        assert_eq!(stream.read_buffered(&mut buffer), None);
    }
}
