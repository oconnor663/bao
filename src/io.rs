use std::cmp::min;
use std::io;
use std::io::prelude::*;

use decode::Decoder;
use hash::Hash;

/// Note that `Reader` works even if the underlying type doesn't implement
/// `Seek`. This is a major design requirement of the tree layout.
pub struct Reader<T> {
    inner_reader: T,
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    decoder: Decoder,
}

impl<T> Reader<T> {
    pub fn new(inner_reader: T, hash: &Hash) -> Self {
        Self {
            inner_reader,
            in_buffer: Vec::new(),
            out_buffer: Vec::new(),
            decoder: Decoder::new(hash),
        }
    }
}

impl<T: Read> Read for Reader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: performance, save state during errors
        while self.out_buffer.len() == 0 {
            let (_, needed) = self.decoder.needed();
            // Check for EOF.
            if needed == 0 {
                return Ok(0);
            }
            self.in_buffer.resize(needed, 0);
            self.inner_reader.read_exact(&mut self.in_buffer)?;
            // TODO: Return hash mismatches properly!
            let (_, out) = self.decoder.feed(&self.in_buffer).expect("was needed");
            // Could be empty.
            self.out_buffer.extend_from_slice(out);
        }

        let copy_len = min(self.out_buffer.len(), buf.len());
        buf[..copy_len].copy_from_slice(&self.out_buffer[..copy_len]);
        // TODO: perf
        self.out_buffer.drain(..copy_len);
        Ok(copy_len)
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use std::io::Cursor;
//     use simple;
//     use hash::TEST_CASES;

//     #[test]
//     fn test_writer() {
//         for &case in TEST_CASES {
//             println!("starting case {}", case);
//             let input = vec![0xb7; case];
//             let mut encoded = Cursor::new(Vec::new());
//             let hash = {
//                 let mut writer = Writer::new(&mut encoded);
//                 writer.write_all(&input).unwrap();
//                 writer.finish().unwrap()
//             };

//             // Compare to the simple encoder.
//             let (simple_encoded, simple_hash) = simple::encode(&input);
//             assert_eq!(hash, simple_hash);
//             assert_eq!(encoded.get_ref(), &simple_encoded);
//         }
//     }

//     #[test]
//     fn test_reader() {
//         for &case in TEST_CASES {
//             println!("starting case {}", case);
//             let input = vec![0xa9; case];
//             let (encoded, hash) = simple::encode(&input);

//             let mut reader = Reader::new(Cursor::new(&encoded), &hash);
//             let mut output = Vec::new();
//             reader.read_to_end(&mut output).unwrap();
//             assert_eq!(input, output);
//         }
//     }
// }
