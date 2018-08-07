extern crate constant_time_eq;

use self::constant_time_eq::constant_time_eq;
use arrayvec::ArrayVec;

use encode;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, MAX_DEPTH, PARENT_SIZE};

use std;
use std::cmp;
use std::fmt;
use std::io;
use std::io::prelude::*;

#[derive(Clone, Debug)]
pub struct State {
    stack: ArrayVec<[Hash; MAX_DEPTH]>,
    root_hash: Hash,
    content_len: Option<u64>,
    length_verified: bool,
    at_root: bool,
    content_position: u64,
    encoded_offset: u128,
    next_chunk: u64,
    upcoming_parents: u8,
}

impl State {
    pub fn new(root_hash: Hash) -> Self {
        Self {
            stack: ArrayVec::new(),
            root_hash,
            content_len: None,
            length_verified: false,
            at_root: true,
            content_position: 0,
            encoded_offset: 0,
            next_chunk: 0,
            upcoming_parents: 0,
        }
    }

    pub fn position(&self) -> u64 {
        self.content_position
    }

    fn reset_to_root(&mut self) {
        self.encoded_offset = HEADER_SIZE as u128;
        self.stack.clear();
        self.stack.push(self.root_hash);
        self.at_root = true;
        self.next_chunk = 0;
        self.upcoming_parents = encode::pre_order_parent_nodes(0, self.content_len.unwrap());
    }

    pub fn read_next(&self) -> Option<StateNext> {
        let content_len;
        if let Some(len) = self.content_len {
            content_len = len;
        } else {
            return Some(StateNext::Header);
        }
        if self.stack.is_empty() {
            // If we somehow return EOF without having verified the root node, then we don't know
            // if the content length we read matches the hash we started with. If it doesn't,
            // that's a suprious EOF and a security issue.
            assert!(self.length_verified, "unverified EOF");
            None
        } else if self.upcoming_parents > 0 {
            Some(StateNext::Parent)
        } else {
            Some(StateNext::Chunk {
                size: encode::chunk_size(self.next_chunk, content_len),
                skip: (self.content_position % CHUNK_SIZE as u64) as usize,
                finalization: if content_len <= CHUNK_SIZE as u64 {
                    Root(content_len)
                } else {
                    NotRoot
                },
            })
        }
    }

    /// Note that if reading the length returns StateNext::Chunk (leading the caller to call
    /// feed_chunk), the content position will no longer be at the start, as with a standard read.
    /// Callers that don't buffer the last read chunk (as Reader does) might need to do an
    /// additional seek to compensate.
    pub fn len_next(&self) -> LenNext {
        if let (Some(len), true) = (self.content_len, self.length_verified) {
            LenNext::Len(len)
        } else {
            debug_assert!(self.at_root);
            let next = self.read_next().expect("unexpected EOF");
            LenNext::Next(next)
        }
    }

    pub fn seek_next(&mut self, content_position: u64) -> (u128, Option<StateNext>) {
        // Get the current content length. This will lead us to read the header and verify the root
        // node, if we haven't already.
        let content_len;
        match self.len_next() {
            LenNext::Len(len) => content_len = len,
            LenNext::Next(next) => return (self.encoded_offset, Some(next)),
        }

        // Record the target position, which we use in read_next() to compute the skip.
        self.content_position = content_position;

        // If we're already past EOF, either reset or short circuit.
        if self.stack.is_empty() {
            if content_position >= content_len {
                return (self.encoded_offset, None);
            } else {
                self.reset_to_root();
            }
        }

        // Also reset if we're in the tree but the seek is to our left.
        if content_position < self.subtree_start() {
            self.reset_to_root();
        }

        // The main loop. Pop subtrees out of the stack until we find one that contains the seek
        // target, and then descend into that tree. Repeat (through in subsequent calls) until the
        // next chunk contains the seek target, or until we hit EOF.
        loop {
            // If the target is within the next chunk, the seek is finished. Note that there may be
            // more parent nodes in front of the chunk, but read will process them as usual.
            let chunk_size = cmp::min(self.subtree_size(), CHUNK_SIZE as u64);
            let chunk_end = self.subtree_start() + chunk_size;
            if content_position < chunk_end {
                return (self.encoded_offset, None);
            }

            // If the target is outside the next chunk, but within the current subtree, then we
            // need to descend.
            if content_position < self.subtree_end() {
                return (self.encoded_offset, Some(StateNext::Parent));
            }

            // Otherwise pop the current tree and repeat.
            self.encoded_offset += encode::encoded_subtree_size(self.subtree_size());
            self.next_chunk += encode::count_chunks(self.subtree_size());
            self.stack.pop();
            if !self.stack.is_empty() {
                // upcoming_parents is only meaningful if we're before EOF.
                self.upcoming_parents =
                    encode::pre_order_parent_nodes(self.next_chunk, content_len);
            } else {
                // If we've emptied the stack, we're at EOF.
                return (self.encoded_offset, None);
            }
        }
    }

    pub fn feed_header(&mut self, header: [u8; HEADER_SIZE]) {
        assert!(self.content_len.is_none(), "second call to feed_header");
        let content_len = hash::decode_len(header);
        self.content_len = Some(content_len);
        self.reset_to_root();
    }

    pub fn feed_parent(&mut self, parent: hash::ParentNode) -> std::result::Result<(), ()> {
        assert!(self.upcoming_parents > 0, "too many calls to feed_parent");
        let content_len = self.content_len.expect("feed_parent before header");
        let finalization = if self.at_root {
            Root(content_len)
        } else {
            NotRoot
        };
        let expected_hash = *self.stack.last().expect("unexpectedly empty stack");
        let computed_hash = hash::hash_node(&parent, finalization);
        if !constant_time_eq(&expected_hash, &computed_hash) {
            return Err(());
        }
        let left_child = *array_ref!(parent, 0, HASH_SIZE);
        let right_child = *array_ref!(parent, HASH_SIZE, HASH_SIZE);
        self.stack.pop();
        self.stack.push(right_child);
        self.stack.push(left_child);
        self.upcoming_parents -= 1;
        self.encoded_offset += PARENT_SIZE as u128;
        self.length_verified = true;
        self.at_root = false;
        Ok(())
    }

    pub fn feed_chunk(&mut self, chunk_hash: Hash) -> std::result::Result<(), ()> {
        let expected_hash = *self.stack.last().expect("unexpectedly empty stack");
        if !constant_time_eq(&chunk_hash, &expected_hash) {
            return Err(());
        }
        self.content_position = self.subtree_end();
        self.encoded_offset += encode::encoded_subtree_size(self.subtree_size());
        self.next_chunk += encode::count_chunks(self.subtree_size());
        self.stack.pop();
        self.length_verified = true;
        self.at_root = false;
        if !self.stack.is_empty() {
            // upcoming_parents is only meaningful if we're before EOF.
            self.upcoming_parents =
                encode::pre_order_parent_nodes(self.next_chunk, self.content_len.unwrap());
        }
        Ok(())
    }

    fn subtree_start(&self) -> u64 {
        debug_assert!(!self.stack.is_empty(), "no subtree after EOF");
        self.next_chunk * CHUNK_SIZE as u64
    }

    fn subtree_size(&self) -> u64 {
        debug_assert!(!self.stack.is_empty(), "no subtree after EOF");
        let content_len = self.content_len.unwrap();
        // The following should avoid overflow even if content_len is 2^64-1. upcoming_parents was
        // computed from the chunk count, and as long as chunks are larger than 1 byte, it will
        // always be less than 64.
        let max_subtree_size = (1 << self.upcoming_parents) * CHUNK_SIZE as u64;
        cmp::min(content_len - self.subtree_start(), max_subtree_size)
    }

    fn subtree_end(&self) -> u64 {
        debug_assert!(!self.stack.is_empty(), "no subtree after EOF");
        self.subtree_start() + self.subtree_size()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StateNext {
    Header,
    Parent,
    Chunk {
        size: usize,
        skip: usize,
        finalization: Finalization,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum LenNext {
    Len(u64),
    Next(StateNext),
}

#[derive(Clone)]
pub struct Reader<T: Read> {
    inner: T,
    state: State,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
}

impl<T: Read> Reader<T> {
    pub fn new(inner: T, root_hash: Hash) -> Self {
        Self {
            inner,
            state: State::new(root_hash),
            buf: [0; CHUNK_SIZE],
            buf_start: 0,
            buf_end: 0,
        }
    }

    fn buf_len(&self) -> usize {
        self.buf_end - self.buf_start
    }

    fn read_header(&mut self) -> io::Result<()> {
        let mut header = [0; HEADER_SIZE];
        self.inner.read_exact(&mut header)?;
        self.state.feed_header(header);
        Ok(())
    }

    fn read_parent(&mut self) -> io::Result<()> {
        let mut parent = [0; PARENT_SIZE];
        self.inner.read_exact(&mut parent)?;
        into_io(self.state.feed_parent(parent))
    }

    fn read_chunk(
        &mut self,
        size: usize,
        skip: usize,
        finalization: Finalization,
    ) -> io::Result<()> {
        if !(skip == 0 && size == 0) {
            debug_assert!(skip < size, "impossible skip offset");
        }
        // Empty the buffer before doing any IO, so that in case of failure subsequent reads don't
        // think there's valid data there.
        self.buf_start = 0;
        self.buf_end = 0;
        self.inner.read_exact(&mut self.buf[..size])?;
        let hash = hash::hash_node(&self.buf[..size], finalization);
        into_io(self.state.feed_chunk(hash))?;
        self.buf_start = skip;
        self.buf_end = size;
        Ok(())
    }
}

impl<T: Read> Read for Reader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we need more data, loop on read_next() until we read a chunk.
        if self.buf_len() == 0 {
            loop {
                match self.state.read_next() {
                    Some(StateNext::Header) => self.read_header()?,
                    Some(StateNext::Parent) => self.read_parent()?,
                    Some(StateNext::Chunk {
                        size,
                        skip,
                        finalization,
                    }) => {
                        self.read_chunk(size, skip, finalization)?;
                        break;
                    }
                    None => return Ok(0), // EOF
                }
            }
        }
        let take = cmp::min(self.buf_len(), buf.len());
        buf[..take].copy_from_slice(&self.buf[self.buf_start..self.buf_start + take]);
        self.buf_start += take;
        Ok(take)
    }
}

impl<T: Read + Seek> Seek for Reader<T> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        // Compute the current position, which need to handle SeekFrom::Current. This both accounts
        // for our buffer position, and also snapshots state.position() before the length loop
        // below, which could change it.
        let starting_position = self.state.position() - self.buf_len() as u64;

        // Read and verify the length if we haven't already.
        let content_len = loop {
            match self.state.len_next() {
                LenNext::Len(len) => break len,
                LenNext::Next(StateNext::Header) => self.read_header()?,
                LenNext::Next(StateNext::Parent) => self.read_parent()?,
                LenNext::Next(StateNext::Chunk {
                    size,
                    skip,
                    finalization,
                }) => self.read_chunk(size, skip, finalization)?,
            }
        };

        // Compute the absolute position of the seek.
        let position = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(off) => add_offset(content_len, off)?,
            io::SeekFrom::Current(off) => add_offset(starting_position, off)?,
        };

        // Now, before entering the main loop, empty the buffer. It's important to do this after
        // getting the length above, because that can fill the buffer as a side effect.
        self.buf_start = 0;
        self.buf_end = 0;

        // Finally, loop over the seek_next() method until it's done.
        loop {
            let (seek_offset, next) = self.state.seek_next(position);
            let cast_offset = cast_offset(seek_offset)?;
            self.inner.seek(io::SeekFrom::Start(cast_offset))?;
            match next {
                Some(StateNext::Header) => {
                    self.read_header()?;
                }
                Some(StateNext::Parent) => {
                    self.read_parent()?;
                }
                Some(StateNext::Chunk {
                    size,
                    skip,
                    finalization,
                }) => {
                    self.read_chunk(size, skip, finalization)?;
                }
                None => {
                    debug_assert_eq!(position, self.state.position());
                    return Ok(position);
                }
            }
        }
    }
}

impl<T: Read> fmt::Debug for Reader<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Reader {{ inner: ..., state: {:?}, buf: [...], buf_start: {}, buf_end: {} }}",
            self.state, self.buf_start, self.buf_end
        )
    }
}

fn into_io<T>(r: std::result::Result<T, ()>) -> io::Result<T> {
    r.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hash mismatch"))
}

fn cast_offset(offset: u128) -> io::Result<u64> {
    if offset > u64::max_value() as u128 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "seek offset overflowed u64",
        ))
    } else {
        Ok(offset as u64)
    }
}

fn add_offset(position: u64, offset: i64) -> io::Result<u64> {
    let sum = position as i128 + offset as i128;
    if sum < 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek before beginning",
        ))
    } else if sum > u64::max_value() as i128 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek target overflowed u64",
        ))
    } else {
        Ok(sum as u64)
    }
}

#[cfg(test)]
mod test {
    extern crate byteorder;
    extern crate rand;

    use self::byteorder::{BigEndian, WriteBytesExt};
    use self::rand::{prng::chacha::ChaChaRng, Rng, SeedableRng};
    use super::*;
    use encode::encode;
    use std::io::Cursor;

    fn make_test_input(len: usize) -> Vec<u8> {
        // Fill the input with incrementing bytes, so that reads from different sections are very
        // unlikely to accidentally match.
        let mut ret = Vec::new();
        let mut counter = 0u64;
        while ret.len() < len {
            if counter < u8::max_value() as u64 {
                ret.write_u8(counter as u8).unwrap();
            } else if counter < u16::max_value() as u64 {
                ret.write_u16::<BigEndian>(counter as u16).unwrap();
            } else if counter < u32::max_value() as u64 {
                ret.write_u32::<BigEndian>(counter as u32).unwrap();
            } else {
                ret.write_u64::<BigEndian>(counter).unwrap();
            }
            counter += 1;
        }
        ret.truncate(len);
        ret
    }

    #[test]
    fn test_read() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (hash, encoded) = encode(&input);
            let mut decoder = Reader::new(&encoded[..], hash);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).expect("decoder error");
            assert_eq!(input, output, "output doesn't match input");
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in hash::TEST_CASES {
            println!();
            println!("input_len {}", input_len);
            let input = make_test_input(input_len);
            let (hash, encoded) = encode(&input);
            for &seek in hash::TEST_CASES {
                println!("seek {}", seek);
                // Test all three types of seeking.
                let mut seek_froms = Vec::new();
                seek_froms.push(io::SeekFrom::Start(seek as u64));
                seek_froms.push(io::SeekFrom::End(seek as i64 - input_len as i64));
                seek_froms.push(io::SeekFrom::Current(seek as i64));
                for seek_from in seek_froms {
                    println!("seek_from {:?}", seek_from);
                    let mut decoder = Reader::new(Cursor::new(&encoded), hash);
                    let mut output = Vec::new();
                    decoder.seek(seek_from).expect("seek error");
                    decoder.read_to_end(&mut output).expect("decoder error");
                    let input_start = cmp::min(seek, input.len());
                    assert_eq!(
                        &input[input_start..],
                        &output[..],
                        "output doesn't match input"
                    );
                }
            }
        }
    }

    #[test]
    fn test_repeated_random_seeks() {
        // A chunk number like this (37) with consecutive zeroes should exercise some of the more
        // interesting geometry cases.
        let input_len = 0b100101 * CHUNK_SIZE;
        println!("input_len {}", input_len);
        let mut prng = ChaChaRng::from_seed([0; 32]);
        let input = make_test_input(input_len);
        let (hash, encoded) = encode(&input);
        let mut decoder = Reader::new(Cursor::new(&encoded), hash);
        // Do ten thousand random seeks and chunk-sized reads.
        for _ in 0..10_000 {
            let seek = prng.gen_range(0, input_len + 1);
            println!("seek {}", seek);
            decoder
                .seek(io::SeekFrom::Start(seek as u64))
                .expect("seek error");
            // Clone the encoder before reading, to test repeated seeks on the same encoder.
            let mut output = Vec::new();
            decoder
                .clone()
                .take(CHUNK_SIZE as u64)
                .read_to_end(&mut output)
                .expect("decoder error");
            let input_start = cmp::min(seek, input_len);
            let input_end = cmp::min(input_start + CHUNK_SIZE, input_len);
            assert_eq!(
                &input[input_start..input_end],
                &output[..],
                "output doesn't match input"
            );
        }
    }
}
