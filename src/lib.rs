#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate ring;

use byteorder::{ByteOrder, BigEndian, WriteBytesExt};
use ring::{constant_time, digest};
use ring::error::Unspecified;
use std::io;
use std::io::prelude::*;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;

pub type Digest = [u8; DIGEST_SIZE];

fn hash(input: &[u8]) -> Digest {
    // First 32 bytes of SHA512. (The same as NaCl's crypto_hash.)
    let digest = digest::digest(&digest::SHA512, input);
    let mut ret = [0; DIGEST_SIZE];
    (&mut ret[..DIGEST_SIZE]).copy_from_slice(&digest.as_ref()[..DIGEST_SIZE]);
    ret
}

fn verify(input: &[u8], digest: &Digest) -> Result<(), Unspecified> {
    let computed = hash(input);
    constant_time::verify_slices_are_equal(&digest[..], &computed[..])
}

fn left_plaintext_len(input_len: u64) -> u64 {
    // Find the first power of 2 times the chunk size that is *strictly* less
    // than the input length. So if the input is exactly 4 chunks long, for
    // example, the answer here will be 2 chunks.
    assert!(input_len > CHUNK_SIZE as u64);
    let mut size = CHUNK_SIZE as u64;
    while (size * 2) < input_len {
        size *= 2;
    }
    size
}

pub fn encode(input: &[u8]) -> (Vec<u8>, Digest) {
    let (inner_encoded, inner_hash) = encode_inner(input);
    let mut encoded = Vec::with_capacity(8 + DIGEST_SIZE + inner_encoded.len());
    encoded.write_u64::<BigEndian>(input.len() as u64);
    encoded.extend_from_slice(&inner_hash);
    let final_hash = hash(&encoded);
    encoded.extend_from_slice(&inner_encoded);
    (encoded, final_hash)
}

pub fn encode_inner(input: &[u8]) -> (Vec<u8>, Digest) {
    if input.len() <= CHUNK_SIZE {
        return (input.to_vec(), hash(input));
    }
    let left_len = left_plaintext_len(input.len() as u64) as usize;
    let (left_encoded, left_hash) = encode(&input[..left_len]);
    let (right_encoded, right_hash) = encode(&input[left_len..]);
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&left_hash);
    encoded.extend_from_slice(&right_hash);
    let node_hash = hash(&encoded);
    encoded.extend_from_slice(&left_encoded);
    encoded.extend_from_slice(&right_encoded);
    (encoded, node_hash)
}

pub struct HashReader<R> {
    inner: R,
    buffer: Vec<u8>,
}

impl<R: Read> HashReader<R> {
    pub fn new(inner: R) -> HashReader<R> {
        HashReader {
            inner: inner,
            buffer: Vec::new(),
        }
    }

    // This is the only way HashReader ever returns data to a caller. Even if
    // there are bugs in the fill or seek functions, which could cause extra
    // errors where there shouldn't be, it should still be impossible for the
    // caller to read any bytes that don't exactly match the hash they provided.
    pub fn read_verified(&mut self, hash: Digest, buf: &mut [u8]) -> io::Result<()> {
        let buf_len = buf.len();
        self.fill_to_target_len(buf_len)?;
        // Check the hash!
        if verify(&self.buffer[..buf_len], &hash).is_err() {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      "hash mismatch in verified read"));
        }
        buf.copy_from_slice(&self.buffer[..buf_len]);
        // TODO: Only drain when we need the space. We don't want a pathological
        // situation where we're reading since bytes out of a huge buffer and
        // draining it over every time.
        self.buffer.drain(..buf_len);
        Ok(())
    }

    fn fill_to_target_len(&mut self, target_len: usize) -> io::Result<()> {
        if self.buffer.len() >= target_len {
            return Ok(());
        }
        let mut needed = target_len - self.buffer.len();
        self.buffer.resize(target_len, 0);
        while needed > 0 {
            let zeros_start = self.buffer.len() - needed;
            let error = match self.inner.read(&mut self.buffer[zeros_start..]) {
                Ok(0) => {
                    io::Error::new(io::ErrorKind::UnexpectedEof,
                                   "EOF in the middle of a verified read")
                }
                Ok(n) => {
                    needed -= n;
                    continue;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => e,
            };
            // The error case:
            let final_len = self.buffer.len() - needed;
            self.buffer.truncate(final_len);
            return Err(error);
        }
        Ok(())
    }
}

impl<R: Read + Seek> Seek for HashReader<R> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let ret = if let io::SeekFrom::Current(n) = pos {
            // When seeking from "current", we need to account for data in our
            // internal buffer. Like BufReader in the stdlib, assume that the
            // length of our buffer fits within an i64, but handle underflow
            // from crazy negative positions.
            let buf_len = self.buffer.len() as i64;
            if let Some(adjusted_n) = n.checked_sub(buf_len) {
                self.inner.seek(io::SeekFrom::Current(adjusted_n))?
            } else {
                // In the underflow case, seek twice.
                self.inner.seek(io::SeekFrom::Current(-buf_len))?;
                // If the last seek succeeded, clear the buffer now, in case the next seek fails.
                self.buffer.clear();
                self.inner.seek(io::SeekFrom::Current(n))?
            }
        } else {
            self.inner.seek(pos)?
        };
        self.buffer.clear();
        Ok(ret)
    }
}

pub struct RadReader<R: Read> {
    inner: HashReader<R>,
    header_hash: Digest,
    node_stack: Vec<(Digest, u64, u64)>,
    header_state: Option<(u64, Digest)>,
}

impl<R: Read> RadReader<R> {
    fn new(hash: Digest, inner: R) -> RadReader<R> {
        RadReader {
            inner: HashReader::new(inner),
            header_hash: hash,
            node_stack: Vec::new(),
            header_state: None,
        }
    }

    fn read_header(&mut self) -> io::Result<(u64, Digest)> {
        let mut buf = [0; 8 + DIGEST_SIZE];
        self.inner.read_verified(self.header_hash, &mut buf)?;
        let plaintext_len = <BigEndian>::read_u64(&buf[..8]);
        let root_hash = *array_ref!(&buf, 8, DIGEST_SIZE);
        let tuple = (plaintext_len, root_hash);
        self.header_state = Some(tuple);
        Ok(tuple)
    }

    fn plaintext_len(&mut self) -> io::Result<u64> {
        if let Some((plaintext_len, _)) = self.header_state {
            Ok(plaintext_len)
        } else {
            Ok(self.read_header()?.0)
        }
    }

    fn root_hash(&mut self) -> io::Result<Digest> {
        if let Some((_, root_hash)) = self.header_state {
            Ok(root_hash)
        } else {
            Ok(self.read_header()?.1)
        }
    }
}

impl<R: Read> Read for RadReader<R> {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        unimplemented!();
    }
}

impl<R: Read + Seek> Seek for RadReader<R> {
    fn seek(&mut self, _: io::SeekFrom) -> io::Result<u64> {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ZERO_HASH: [u8; DIGEST_SIZE] = [0; DIGEST_SIZE];

    #[test]
    fn test_hash() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            verify(input, &::hash(input)).unwrap();
        }
    }

    #[test]
    fn test_left_plaintext_len() {
        let cases = &[(::CHUNK_SIZE + 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE - 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2, 2 * CHUNK_SIZE)];
        for &case in cases {
            println!("testing {} and {}", case.0, case.1);
            assert_eq!(::left_plaintext_len(case.0 as u64), case.1 as u64);
        }
    }

    fn read_verified_expecting<R: Read>(reader: &mut HashReader<R>, slice: &[u8]) {
        let mut buf = vec![0; slice.len()];
        reader
            .read_verified(::hash(slice), &mut buf[..])
            .expect("read_verified failed");
        assert_eq!(slice, &buf[..]);
    }

    fn read_verified_invalid<R: Read>(reader: &mut HashReader<R>, n: usize) {
        let mut buf = vec![0; n];
        let err = reader
            .read_verified(ZERO_HASH, &mut buf[..])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_hash_reader() {
        let input = b"hello world";
        let mut reader = HashReader::new(&input[..]);

        // See if we can read the first two bytes.
        read_verified_expecting(&mut reader, b"he");

        // Now try an invalid read.
        read_verified_invalid(&mut reader, 5);
        // Twice for good measure.
        read_verified_invalid(&mut reader, 6);

        // Now finish the read, despite the errors above.
        read_verified_expecting(&mut reader, b"llo world");

        // At this point, an empty read should work.
        read_verified_expecting(&mut reader, b"");

        // But a non-empty read (regardles of the hash) should return UnexpectedEOF.
        let mut buf = [0];
        let error = reader.read_verified(ZERO_HASH, &mut buf);
        assert_eq!(error.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_hash_reader_long_then_short() {
        let input = b"hello world";
        let mut reader = HashReader::new(&input[..]);

        // Do a bogus read of the whole input. This fills the buffer, though the
        // hash won't match.
        read_verified_invalid(&mut reader, 11);

        // Now do a couple small reads from the buffer. This tests whether the
        // used part of the buffer gets drained properly.
        read_verified_expecting(&mut reader, b"h");
        read_verified_expecting(&mut reader, b"e");
    }

    // A reader that alternates between reading a single character and returning
    // a transient error.
    struct StupidReader<R> {
        inner: R,
        error_next: bool,
    }

    impl<R: Read> Read for StupidReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.error_next {
                self.error_next = false;
                Err(io::Error::new(io::ErrorKind::Other, "stupid error"))
            } else {
                self.error_next = true;
                self.inner.read(&mut buf[0..1]) // assumes non-empty buf
            }
        }
    }

    #[test]
    fn test_hash_reader_transient_errors() {
        let stupid = StupidReader {
            inner: &b"hello world"[..],
            error_next: true,
        };
        let mut reader = HashReader::new(stupid);
        let mut buf = [0; 11];
        let mut errors = 0;
        let good_hash = hash(b"hello world");
        // We expect 11 errors, followed by a successful read.
        loop {
            match reader.read_verified(good_hash, &mut buf) {
                Err(e) => {
                    errors += 1;
                    assert_eq!("stupid error", e.to_string());
                }
                Ok(()) => {
                    assert_eq!(11, errors);
                    break;
                }
            }
        }
    }

    #[test]
    fn test_hash_reader_seek() {
        let mut reader = HashReader::new(io::Cursor::new(b"hello world".to_vec()));
        reader.seek(io::SeekFrom::End(-1)).unwrap();
        read_verified_expecting(&mut reader, b"d");
        reader.seek(io::SeekFrom::Current(-2)).unwrap();
        read_verified_expecting(&mut reader, b"ld");
        reader.seek(io::SeekFrom::Start(1)).unwrap();
        read_verified_expecting(&mut reader, b"ello");
        // Now fill the buffer with a bad read, and confirm relative seeks still work.
        read_verified_invalid(&mut reader, 3);
        reader.seek(io::SeekFrom::Current(-2)).unwrap();
        read_verified_expecting(&mut reader, b"lo world");
    }
}
