#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate ring;

use byteorder::{ByteOrder, BigEndian, WriteBytesExt};
use ring::{constant_time, digest};
use ring::error::Unspecified;
use std::io::{self, Cursor};
use std::io::prelude::*;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;
pub const HEADER_SIZE: usize = 8 + DIGEST_SIZE;

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
    let (inner_encoded, inner_hash) = encode_tree(input);
    let mut encoded = Vec::with_capacity(HEADER_SIZE + inner_encoded.len());
    encoded.write_u64::<BigEndian>(input.len() as u64).unwrap();
    encoded.extend_from_slice(&inner_hash);
    let final_hash = hash(&encoded);
    encoded.extend_from_slice(&inner_encoded);
    (encoded, final_hash)
}

fn encode_tree(input: &[u8]) -> (Vec<u8>, Digest) {
    if input.len() <= CHUNK_SIZE {
        return (input.to_vec(), hash(input));
    }
    let left_len = left_plaintext_len(input.len() as u64) as usize;
    let (left_encoded, left_hash) = encode_tree(&input[..left_len]);
    let (right_encoded, right_hash) = encode_tree(&input[left_len..]);
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hash mismatch in verified read",
            ));
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
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF in the middle of a verified read",
                    )
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

#[derive(Clone, Copy, Debug)]
struct Region {
    start: u64,
    len: u64,
    hash: Digest,
}

impl Region {
    fn end(&self) -> u64 {
        self.start + self.len
    }
}

#[derive(Clone, Copy, Debug)]
struct Node {
    left: Region,
    right: Region,
}

pub struct RadReader<R: Read> {
    inner: HashReader<R>,
    header_hash: Digest,
    header: Option<Region>,
    node_stack: Vec<Node>,
    chunk: Cursor<Vec<u8>>,
    chunk_start: u64,
}

impl<R: Read> RadReader<R> {
    pub fn new(hash: Digest, inner: R) -> RadReader<R> {
        RadReader {
            inner: HashReader::new(inner),
            header_hash: hash,
            header: None,
            node_stack: Vec::new(),
            chunk: Cursor::new(Vec::new()),
            chunk_start: 0,
        }
    }

    fn get_header(&mut self) -> io::Result<Region> {
        // Parsing the header state is the very first thing the reader does. If
        // we don't have it yet, we can assume we're at the front of the stream.
        if let Some(header) = self.header {
            return Ok(header);
        }
        let mut buf = [0; HEADER_SIZE];
        self.inner.read_verified(self.header_hash, &mut buf)?;
        let len = <BigEndian>::read_u64(&buf[..8]);
        let hash = *array_ref!(&buf, 8, DIGEST_SIZE);
        let header = Region {
            start: 0,
            len,
            hash,
        };
        self.header = Some(header);
        Ok(header)
    }

    fn read_next_chunk(&mut self) -> io::Result<()> {
        debug_assert_eq!(
            self.chunk.position(),
            self.chunk.get_ref().len() as u64,
            "read_next_chunk called with data in the read buffer"
        );

        // If this is the very first time we've tried to read a chunk, read the header from the
        // input to get the output length. (Subsequent accesses are cached.) Doing this here helps
        // us avoid needing `&mut self` in some blocks below.
        let header = self.get_header()?;

        // If we're at the end of the output, short-circuit. Note that we leave the chunk buffer
        // and node stack in place in this case, to avoid wasting seek state.
        let output_position = self.chunk_start + self.chunk.get_ref().len() as u64;
        if output_position >= header.len {
            debug_assert_eq!(output_position, header.len, "seek past end of output");
            return Ok(());
        }

        // Clear the current chunk and bump the chunk start. Using the chunk len (which we're about
        // to clear) for the bump is important for keeping this idempotent, in case we encounter IO
        // errors and need to retry.
        self.chunk_start += self.chunk.get_ref().len() as u64;
        self.chunk.get_mut().clear();
        self.chunk.set_position(0);

        // If we're not at the very beginning of the input, there will be nodes on the stack that
        // we're finished with. Pop them off. As above, we're doing this as late as possible, to
        // avoid wasting seek state.
        while let Some(current_node) = self.node_stack.last().map(|n| *n) {
            if self.chunk_start == current_node.right.end() {
                self.node_stack.pop();
                debug_assert!(self.node_stack.len() > 0, "never pop the last node");
            } else {
                break;
            }
        }

        // Figure out the next region we're going to be reading. At this point we're still agnostic
        // about whether it's a node or a chunk.
        let mut next_region = if let Some(current_node) = self.node_stack.last() {
            // Normally the next region should be the right side of the current node, because
            // we gobble up left branches below, but it can be the left side if an IO error has
            // caused us to repeat a read.
            if self.chunk_start == current_node.left.start {
                current_node.left
            } else if self.chunk_start == current_node.right.start {
                current_node.right
            } else {
                panic!("next chunk start must match the current node")
            }
        } else {
            header
        };

        // Parse nodes and follow left branches all the way until we're about to read the next
        // chunk.
        while next_region.len > CHUNK_SIZE as u64 {
            let mut node_buf = [0; 2 * DIGEST_SIZE];
            self.inner.read_verified(next_region.hash, &mut node_buf)?;
            let left_len = left_plaintext_len(next_region.len);
            let node = Node {
                left: Region {
                    start: next_region.start,
                    len: left_len,
                    hash: *array_ref!(&node_buf, 0, DIGEST_SIZE),
                },
                right: Region {
                    start: next_region.start + left_len,
                    len: next_region.len - left_len,
                    hash: *array_ref!(&node_buf, DIGEST_SIZE, DIGEST_SIZE),
                },
            };
            self.node_stack.push(node);
            next_region = node.left;
        }

        // Read the next chunk! Note that the final chunk might be shorter than CHUNK_SIZE.
        let mut chunk_buf = [0; CHUNK_SIZE];
        let chunk_slice = &mut chunk_buf[0..next_region.len as usize];
        self.inner.read_verified(next_region.hash, chunk_slice)?;
        self.chunk.get_mut().extend_from_slice(chunk_slice);
        Ok(())
    }
}

impl<R: Read> Read for RadReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to read another chunk if we're out of bytes. Note that this is a no-op at EOF,
        // however.
        if self.chunk.position() == self.chunk.get_ref().len() as u64 {
            self.read_next_chunk()?;
        }
        self.chunk.read(buf)
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
        let cases = &[
            (CHUNK_SIZE + 1, CHUNK_SIZE),
            (2 * CHUNK_SIZE - 1, CHUNK_SIZE),
            (2 * CHUNK_SIZE, CHUNK_SIZE),
            (2 * CHUNK_SIZE + 2, 2 * CHUNK_SIZE),
        ];
        for &case in cases {
            println!("testing {} and {}", case.0, case.1);
            assert_eq!(::left_plaintext_len(case.0 as u64), case.1 as u64);
        }
    }

    fn read_verified_expecting<R: Read>(reader: &mut HashReader<R>, slice: &[u8]) {
        let mut buf = vec![0; slice.len()];
        reader.read_verified(::hash(slice), &mut buf[..]).expect(
            "read_verified failed",
        );
        assert_eq!(slice, &buf[..]);
    }

    fn read_verified_invalid<R: Read>(reader: &mut HashReader<R>, n: usize) {
        let mut buf = vec![0; n];
        let err = reader.read_verified(ZERO_HASH, &mut buf[..]).unwrap_err();
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

    fn decode_for_testing(encoded: &[u8]) -> Vec<u8> {
        let plaintext_len = <BigEndian>::read_u64(&encoded[..8]) as usize;
        let hash = *array_ref!(&encoded, 8, DIGEST_SIZE);
        let tree = &encoded[HEADER_SIZE..];
        decode_tree_for_testing(tree, plaintext_len, hash)
    }

    // Note that this does not include a header (40 additional bytes).
    fn tree_len_for_testing(plaintext_len: usize) -> usize {
        if plaintext_len <= CHUNK_SIZE {
            return plaintext_len;
        }
        let left = left_plaintext_len(plaintext_len as u64) as usize;
        let right = plaintext_len - left;
        tree_len_for_testing(left) + tree_len_for_testing(right) + 2 * DIGEST_SIZE
    }

    fn decode_tree_for_testing(tree: &[u8], plaintext_len: usize, hash: Digest) -> Vec<u8> {
        if plaintext_len <= CHUNK_SIZE {
            let chunk = &tree[..plaintext_len];
            verify(chunk, &hash).expect("bad hash");
            return chunk.to_vec();
        }
        assert_eq!(
            tree_len_for_testing(plaintext_len),
            tree.len(),
            "tree size doesn't match plaintext len ({})",
            plaintext_len,
        );
        verify(&tree[..2 * DIGEST_SIZE], &hash).expect("bad hash");
        let left_digest = *array_ref!(tree, 0, DIGEST_SIZE);
        let right_digest = *array_ref!(tree, DIGEST_SIZE, DIGEST_SIZE);
        let left_pl = left_plaintext_len(plaintext_len as u64) as usize;
        let right_pl = plaintext_len - left_pl;
        let left_tree_start = 2 * DIGEST_SIZE;
        let right_tree_start = left_tree_start + tree_len_for_testing(left_pl);
        let left_tree = &tree[left_tree_start..right_tree_start];
        let right_tree = &tree[right_tree_start..];
        let mut left_decoded = decode_tree_for_testing(left_tree, left_pl, left_digest);
        let right_decoded = decode_tree_for_testing(right_tree, right_pl, right_digest);
        left_decoded.extend_from_slice(&right_decoded);
        left_decoded
    }

    #[test]
    fn test_rad_reader_basic() {
        let mut cases: Vec<Vec<u8>> = Vec::new();
        cases.push(b"".to_vec());
        cases.push(b"a".to_vec());
        cases.push([b'a'; CHUNK_SIZE - 1].to_vec());
        cases.push([b'a'; CHUNK_SIZE].to_vec());
        cases.push([b'a'; CHUNK_SIZE + 1].to_vec());
        cases.push([b'a'; 2 * CHUNK_SIZE - 1].to_vec());
        cases.push([b'a'; 2 * CHUNK_SIZE].to_vec());
        cases.push([b'a'; 2 * CHUNK_SIZE + 1].to_vec());
        cases.push([b'a'; 4 * CHUNK_SIZE - 1].to_vec());
        cases.push([b'a'; 4 * CHUNK_SIZE].to_vec());
        cases.push([b'a'; 4 * CHUNK_SIZE + 1].to_vec());
        cases.push([b'a'; 1_000_000].to_vec());

        for (i, case) in cases.iter().enumerate() {
            println!("case {} ({} bytes)", i, case.len());
            let (encoded, hash) = encode(case);
            println!("output len {} bytes", encoded.len());
            let mut rad_reader = RadReader::new(hash, Cursor::new(&encoded));
            let mut output = Vec::new();
            rad_reader.read_to_end(&mut output).expect(
                "RadReader error",
            );
            assert_eq!(case, &output, "RadReader different from encoding input");

            // Confirm that the simpler all-at-once decoder gets the same answer.
            let decoded_simple = decode_for_testing(&encoded);
            assert_eq!(case, &decoded_simple, "simple decoder got the wrong answer");
        }
    }
}
