#[macro_use]
extern crate arrayref;
extern crate ring;

use ring::{constant_time, digest};
use ring::error::Unspecified;
use std::cmp::min;
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
    // Find the first power of 2 times the chunk size that is *strictly* less than the input
    // length. So if the input is exactly 4 chunks long, for example, the answer here will be 2
    // chunks.
    assert!(input_len > CHUNK_SIZE as u64);
    let mut size = CHUNK_SIZE as u64;
    while (size * 2) < input_len {
        size *= 2;
    }
    size
}

pub fn encode(input: &[u8]) -> (Vec<u8>, Digest) {
    if input.len() <= CHUNK_SIZE {
        return (input.to_vec(), hash(input));
    }
    let left_len = left_plaintext_len(input.len() as u64) as usize;
    let (left_encoded, left_hash) = encode(&input[..left_len]);
    let (right_encoded, right_hash) = encode(&input[left_len..]);
    let mut node = [0; 2 * DIGEST_SIZE];
    (&mut node[..DIGEST_SIZE]).copy_from_slice(&left_hash);
    (&mut node[DIGEST_SIZE..]).copy_from_slice(&right_hash);
    let node_hash = hash(&node);
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&node);
    encoded.extend_from_slice(&left_encoded);
    encoded.extend_from_slice(&right_encoded);
    (encoded, node_hash)
}

fn left_subtree_len_and_chunk_count(encoded_len: u64) -> (u64, u64) {
    assert!(encoded_len > CHUNK_SIZE as u64);
    let mut encoded_size = CHUNK_SIZE as u64;
    let mut chunk_count = 1;
    loop {
        let next_size = 2 * encoded_size + 2 * DIGEST_SIZE as u64;
        if next_size >= encoded_len {
            return (encoded_size, chunk_count);
        }
        encoded_size = next_size;
        chunk_count *= 2;
    }
}

pub fn decode(encoded: &[u8],
              digest: &Digest,
              plaintext_len: usize)
              -> Result<Vec<u8>, Unspecified> {
    let mut reader = RahReader::new(io::Cursor::new(encoded), digest, plaintext_len as u64);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).or(Err(Unspecified))?;
    Ok(output)
}

pub fn decode_chunk<'a>(encoded: &'a [u8],
                        digest: &Digest,
                        chunk_num: u64)
                        -> Result<&'a [u8], Unspecified> {
    if encoded.len() <= CHUNK_SIZE {
        if chunk_num == 0 {
            verify(encoded, digest)?;
            Ok(encoded)
        } else {
            // Asking for a chunk num that doesn't exist.
            Err(Unspecified)
        }
    } else {
        verify(&encoded[..2 * DIGEST_SIZE], digest)?;
        let (left_len, left_chunk_count) = left_subtree_len_and_chunk_count(encoded.len() as u64);
        let left_digest = array_ref![encoded, 0, DIGEST_SIZE];
        let right_digest = array_ref![encoded, DIGEST_SIZE, DIGEST_SIZE];
        let left_start = 2 * DIGEST_SIZE;
        let left_end = left_start + left_len as usize;
        if chunk_num < left_chunk_count {
            decode_chunk(&encoded[left_start..left_end], left_digest, chunk_num)
        } else {
            decode_chunk(&encoded[left_end..],
                         right_digest,
                         chunk_num - left_chunk_count)
        }
    }
}

pub struct RahReader<T> {
    inner_reader: T,
    starting_digest: Digest,
    plaintext_len: u64,
    current_offset: u64,
    traversal_stack: Vec<(Digest, u64)>,
    read_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

impl<T> RahReader<T> {
    pub fn new(inner_reader: T, digest: &Digest, plaintext_len: u64) -> Self {
        RahReader {
            inner_reader: inner_reader,
            starting_digest: *digest,
            plaintext_len: plaintext_len,
            current_offset: 0,
            traversal_stack: vec![(*digest, plaintext_len)],
            read_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }
}

impl<T: Read> Read for RahReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If there's no data in the output buffer, and we haven't reached the end of the tree yet,
        // try to traverse the tree down to a chunk and read it.
        if self.output_buffer.len() == 0 && self.traversal_stack.len() > 0 {
            // Keep traversing nodes until we get down to the size of a single chunk.
            loop {
                let (digest, plaintext_len) = *self.traversal_stack.last().unwrap();
                if plaintext_len <= CHUNK_SIZE as u64 {
                    break;
                }
                // This should be able to recover from transient IO errors by retrying.
                fill_vec(&mut self.inner_reader,
                         &mut self.read_buffer,
                         2 * DIGEST_SIZE)?;
                as_io_error(verify(&self.read_buffer[..], &digest))?;
                let left_len = left_plaintext_len(plaintext_len);
                let left_digest = *array_ref![self.read_buffer, 0, DIGEST_SIZE];
                let right_len = plaintext_len - left_len;
                let right_digest = *array_ref![self.read_buffer, DIGEST_SIZE, DIGEST_SIZE];
                self.read_buffer.clear();
                self.traversal_stack.pop();
                self.traversal_stack.push((right_digest, right_len));
                self.traversal_stack.push((left_digest, left_len));
            }
            // Then read that chunk.
            let (digest, plaintext_len) = *self.traversal_stack.last().unwrap();
            debug_assert!(plaintext_len <= CHUNK_SIZE as u64);
            // This should be able to recover from transient IO errors by retrying.
            fill_vec(&mut self.inner_reader,
                     &mut self.read_buffer,
                     plaintext_len as usize)?;
            as_io_error(verify(&self.read_buffer[..], &digest))?;
            self.traversal_stack.pop();
            debug_assert!(self.output_buffer.len() == 0);
            std::mem::swap(&mut self.read_buffer, &mut self.output_buffer);
        }

        // Finally, return as much as we can from the output buffer. That might be zero bytes,
        // which would mean EOF.
        let write_len = min(self.output_buffer.len(), buf.len());
        (&mut buf[0..write_len]).copy_from_slice(&mut self.output_buffer[0..write_len]);
        self.output_buffer.drain(0..write_len);
        self.current_offset += write_len as u64;
        Ok(write_len)
    }
}

impl<T: Seek + Read> Seek for RahReader<T> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let new_offset = match pos {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::End(n) => {
                if -n > self.plaintext_len as i64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "can't seek before byte 0"));
                }
                (self.plaintext_len as i64 + n) as u64
            }
            io::SeekFrom::Current(n) => {
                if -n > self.current_offset as i64 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "can't seek before byte 0"));
                }
                (self.current_offset as i64 + n) as u64
            }
        };

        // Seek to the beginning of the inner reader, and then reset all of our traversal state.
        // TODO: Something more efficient with local seeks?
        self.inner_reader.seek(io::SeekFrom::Start(0))?;
        self.traversal_stack = vec![(self.starting_digest, self.plaintext_len)];
        self.current_offset = 0;
        self.read_buffer.clear();
        self.output_buffer.clear();

        // Now do a traversal to the new offset, similar to read() above, but using seeks instead.
        unimplemented!();
    }
}

fn fill_vec<R: Read>(reader: &mut R, vec: &mut Vec<u8>, target_len: usize) -> io::Result<usize> {
    let mut read_buf = [0u8; 4096];
    let mut total_read = 0;
    while vec.len() < target_len {
        let bytes_wanted = min(target_len - vec.len(), read_buf.len());
        let read_result = reader.read(&mut read_buf[0..bytes_wanted]);
        let bytes_got = match read_result {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                } else {
                    return Err(e);
                }
            }
        };
        if bytes_got == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF during fill_vec"));
        }
        total_read += bytes_got;
        vec.extend_from_slice(&read_buf[0..bytes_got]);
    }
    Ok(total_read)
}

fn as_io_error<T>(result: Result<T, Unspecified>) -> io::Result<T> {
    result.or(Err(io::Error::new(io::ErrorKind::InvalidData, "hash mismatch")))
}

#[cfg(test)]
mod test {
    use std::cmp::min;
    use std::io;
    use std::io::prelude::*;
    use super::*;
    use super::{hash, verify, left_plaintext_len, left_subtree_len_and_chunk_count};

    fn debug_sample(input: &[u8]) -> String {
        let sample_len = min(60, input.len());
        let mut ret = String::from_utf8_lossy(&input[..sample_len]).into_owned();
        if sample_len < input.len() {
            ret += &*format!("... (len {})", input.len());
        }
        ret
    }

    #[test]
    fn test_hash() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            verify(input, &hash(input)).unwrap();
        }
    }

    #[test]
    fn test_left_plaintext_len() {
        let cases = &[(CHUNK_SIZE + 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE - 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2, 2 * CHUNK_SIZE)];
        for &case in cases {
            println!("testing {} and {}", case.0, case.1);
            assert_eq!(left_plaintext_len(case.0 as u64), case.1 as u64);
        }
    }

    #[test]
    fn test_left_subtree_len_and_chunk_count() {
        // TODO: There are invalid encoded lengths in here...
        let cases =
            &[(CHUNK_SIZE + 1, (CHUNK_SIZE, 1)),
              (2 * CHUNK_SIZE + 2 * DIGEST_SIZE - 1, (CHUNK_SIZE, 1)),
              (2 * CHUNK_SIZE + 2 * DIGEST_SIZE, (CHUNK_SIZE, 1)),
              (2 * CHUNK_SIZE + 2 * DIGEST_SIZE + 1, (2 * CHUNK_SIZE + 2 * DIGEST_SIZE, 2)),
              (4 * CHUNK_SIZE + 6 * DIGEST_SIZE - 1, (2 * CHUNK_SIZE + 2 * DIGEST_SIZE, 2)),
              (4 * CHUNK_SIZE + 6 * DIGEST_SIZE, (2 * CHUNK_SIZE + 2 * DIGEST_SIZE, 2)),
              (4 * CHUNK_SIZE + 6 * DIGEST_SIZE + 1, (4 * CHUNK_SIZE + 6 * DIGEST_SIZE, 4))];
        for &(input_len, (expected_left_len, expected_left_chunk_count)) in cases {
            println!("testing {:?}", input_len);
            let (left_len, left_chunk_count) = left_subtree_len_and_chunk_count(input_len as u64);
            assert_eq!(left_len as usize,
                       expected_left_len,
                       "unexpected value for left subtree len");
            assert_eq!(left_chunk_count as usize,
                       expected_left_chunk_count,
                       "unexpected value for left subtree chunk count");
        }
    }

    #[test]
    fn test_decode() {
        fn one(input: &[u8]) {
            println!("input: {:?}", debug_sample(input));
            let (encoded, digest) = encode(input);
            let output = decode(&encoded, &digest, input.len()).expect("decode failed");
            assert_eq!(input.len(),
                       output.len(),
                       "input and output lengths don't match");
            assert_eq!(input, &*output, "input and output data doesn't match");
            println!("DONE!!!");
        }

        one(b"");

        one(b"foo");

        one(&vec![0; CHUNK_SIZE - 1]);
        one(&vec![0; CHUNK_SIZE]);
        one(&vec![0; CHUNK_SIZE + 1]);

        const BIGGER: usize = 2 * CHUNK_SIZE + 2 * DIGEST_SIZE;
        one(&vec![0; BIGGER - 1]);
        one(&vec![0; BIGGER]);
        one(&vec![0; BIGGER + 1]);

        const BIGGEST: usize = 2 * BIGGER + 2 * DIGEST_SIZE;
        one(&vec![0; BIGGEST - 1]);
        one(&vec![0; BIGGEST]);
        one(&vec![0; BIGGEST + 1]);
    }

    #[test]
    fn test_decode_chunk() {
        let chunks: &[&[u8]] = &[&[0; CHUNK_SIZE], &[1; CHUNK_SIZE], &[2, 2, 2]];
        let mut input = Vec::new();
        for chunk in chunks {
            input.extend_from_slice(chunk);
        }
        let (mut encoded, digest) = encode(&input);
        for i in 0..chunks.len() {
            let decoded_chunk = decode_chunk(&encoded, &digest, i as u64)
                .expect("decode_chunk failed!");
            assert_eq!(chunks[i], decoded_chunk);
        }

        // Twiddle the last byte. The first two chunks now succeed, but the last fails.
        *encoded.last_mut().unwrap() ^= 1;
        decode_chunk(&encoded, &digest, 0).unwrap();
        decode_chunk(&encoded, &digest, 1).unwrap();
        assert!(decode_chunk(&encoded, &digest, 2).is_err());

        // Twiddle the first byte. Now all of them fail.
        *encoded.first_mut().unwrap() ^= 1;
        assert!(decode_chunk(&encoded, &digest, 0).is_err());
        assert!(decode_chunk(&encoded, &digest, 1).is_err());
        assert!(decode_chunk(&encoded, &digest, 2).is_err());
    }

    #[test]
    fn test_read() {
        let chunks: &[&[u8]] = &[&[0; CHUNK_SIZE], &[1; CHUNK_SIZE], &[2, 2, 2]];
        let mut input = Vec::new();
        for chunk in chunks {
            input.extend_from_slice(chunk);
        }
        let (mut encoded, digest) = encode(&input);

        // Test that we can successfully read the input back out.
        {
            let mut reader = RahReader::new(io::Cursor::new(&encoded), &digest, input.len() as u64);
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(&output, &input);
        }

        // Do the same test, but reading one byte at a time.
        {
            let mut reader = RahReader::new(io::Cursor::new(&encoded), &digest, input.len() as u64);
            let mut output = Vec::new();
            loop {
                let mut one_byte_buffer = [0; 1];
                let bytes_read = reader.read(&mut one_byte_buffer[..]).unwrap();
                if bytes_read == 0 {
                    break;  // EOF
                }
                output.push(one_byte_buffer[0]);
            }
            assert_eq!(&output, &input);
        }

        // Twiddle one bit at the end and confirm that it breaks only the last chunk.
        {
            *encoded.last_mut().unwrap() ^= 1;
            let mut reader = RahReader::new(io::Cursor::new(&encoded), &digest, input.len() as u64);
            let mut chunk_buf = [0; CHUNK_SIZE];
            let first_read = reader.read(&mut chunk_buf[..]).unwrap();
            assert_eq!(first_read, CHUNK_SIZE);
            let second_read = reader.read(&mut chunk_buf[..]).unwrap();
            assert_eq!(second_read, CHUNK_SIZE);
            let third_error = reader.read(&mut chunk_buf[..]).unwrap_err();
            assert_eq!(third_error.kind(), io::ErrorKind::InvalidData);
        }

        // Twiddle one bit at the beginning and confirm that it breaks the first read.
        {
            *encoded.first_mut().unwrap() ^= 1;
            let mut reader = RahReader::new(io::Cursor::new(&encoded), &digest, input.len() as u64);
            let mut one_byte_buffer = [0; 1];
            let error = reader.read(&mut one_byte_buffer[..]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }
}
