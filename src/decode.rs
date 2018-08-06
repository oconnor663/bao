extern crate constant_time_eq;
extern crate either;

use self::constant_time_eq::constant_time_eq;
use self::either::Either::{self, Left, Right};
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
    stack: ArrayVec<[Subtree; MAX_DEPTH]>,
    root_hash: Hash,
    content_length: Option<u64>,
    length_verified: bool,
    content_position: u64,
    encoded_offset: u128,
}

impl State {
    pub fn new(root_hash: Hash) -> Self {
        Self {
            stack: ArrayVec::new(),
            root_hash,
            content_length: None,
            length_verified: false,
            content_position: 0,
            encoded_offset: 0,
        }
    }

    pub fn position(&self) -> u64 {
        self.content_position
    }

    fn reset_to_root(&mut self) {
        self.encoded_offset = HEADER_SIZE as u128;
        self.stack.clear();
        self.stack.push(Subtree {
            hash: self.root_hash,
            start: 0,
            end: self.content_length.expect("no header"),
        });
    }

    pub fn read_next(&self) -> Option<StateNext> {
        let content_length;
        match self.len_next() {
            Left(len) => content_length = len,
            Right(next) => return Some(next),
        }
        if let Some(subtree) = self.stack.last() {
            Some(subtree.state_next(content_length, self.content_position))
        } else {
            assert!(self.length_verified, "unverified EOF");
            None
        }
    }

    /// Note that if reading the length returns StateNext::Chunk (leading the caller to call
    /// feed_subtree), the content position will no longer be at the start, as with a standard
    /// read. Callers that don't buffer the last read chunk (as Reader does) might need to do an
    /// additional seek to compensate.
    pub fn len_next(&self) -> Either<u64, StateNext> {
        if let Some(content_length) = self.content_length {
            if self.length_verified {
                Left(content_length)
            } else {
                let current_subtree = *self.stack.last().expect("unverified EOF");
                let next = current_subtree.state_next(content_length, self.content_position);
                Right(next)
            }
        } else {
            Right(StateNext::Header)
        }
    }

    pub fn seek_next(&mut self, content_position: u64) -> (u128, Option<StateNext>) {
        // Get the current content length. This will lead us to read the header and verify the root
        // node, if we haven't already.
        let content_length;
        match self.len_next() {
            Left(len) => content_length = len,
            Right(next) => return (self.encoded_offset, Some(next)),
        }

        // Record the target position, which we use in read_next() to compute the skip.
        self.content_position = content_position;

        // If we're already past EOF, either reset or short circuit.
        if self.stack.is_empty() {
            if content_position >= content_length {
                return (self.encoded_offset, None);
            } else {
                self.reset_to_root();
            }
        }

        // Also reset if we're in the tree but the seek is to our left.
        if content_position < self.stack.last().unwrap().start {
            self.reset_to_root();
        }

        // The main loop. Pop subtrees out of the stack until we find one that contains the seek
        // target, and then descend into that tree. Repeat (through in subsequent calls) until the
        // next chunk contains the seek target, or until we hit EOF.
        while let Some(&current_subtree) = self.stack.last() {
            // If the target is within the next chunk, the seek is finished. Note that there may be
            // more parent nodes in front of the chunk, but read will process them as usual.
            let current_chunk_size = cmp::min(current_subtree.len(), CHUNK_SIZE as u64);
            if content_position < current_subtree.start + current_chunk_size {
                return (self.encoded_offset, None);
            }

            // If the target is outside the next chunk, but within the current subtree, then we
            // need to descend.
            if content_position < current_subtree.end {
                return (
                    self.encoded_offset,
                    Some(current_subtree.state_next(content_length, self.content_position)),
                );
            }

            // Otherwise pop the current tree and repeat.
            self.encoded_offset += encode::encoded_subtree_size(current_subtree.len());
            self.stack.pop();
        }

        // If we made it out the main loop, we're at EOF.
        (self.encoded_offset, None)
    }

    pub fn feed_header(&mut self, header: [u8; HEADER_SIZE]) {
        assert!(self.content_length.is_none(), "second call to feed_header");
        let content_length = hash::decode_len(header);
        self.content_length = Some(content_length);
        self.reset_to_root();
    }

    pub fn feed_parent(&mut self, parent: hash::ParentNode) -> std::result::Result<(), ()> {
        let content_length = self.content_length.expect("feed_parent before header");
        let current_subtree = *self.stack.last().expect("feed_parent after EOF");
        if current_subtree.len() <= CHUNK_SIZE as u64 {
            panic!("too many calls to feed_parent");
        }
        let computed_hash = hash::hash_node(&parent, current_subtree.finalization(content_length));
        if !constant_time_eq(&current_subtree.hash, &computed_hash) {
            return Err(());
        }
        let split = current_subtree.start + hash::left_len(current_subtree.len());
        let left_subtree = Subtree {
            hash: *array_ref!(parent, 0, HASH_SIZE),
            start: current_subtree.start,
            end: split,
        };
        let right_subtree = Subtree {
            hash: *array_ref!(parent, HASH_SIZE, HASH_SIZE),
            start: split,
            end: current_subtree.end,
        };
        self.stack.pop();
        self.stack.push(right_subtree);
        self.stack.push(left_subtree);
        self.encoded_offset += PARENT_SIZE as u128;
        self.length_verified = true;
        Ok(())
    }

    pub fn feed_subtree(&mut self, subtree: Hash) -> std::result::Result<(), ()> {
        let current_subtree = *self.stack.last().expect("feed_subtree after EOF");
        if !constant_time_eq(&subtree, &current_subtree.hash) {
            return Err(());
        }
        self.stack.pop();
        self.content_position = current_subtree.end;
        self.encoded_offset += encode::encoded_subtree_size(current_subtree.len());
        self.length_verified = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StateNext {
    Header,
    Subtree {
        size: u64,
        skip: u64,
        finalization: Finalization,
    },
    Chunk {
        size: usize,
        skip: usize,
        finalization: Finalization,
    },
}

// TODO: Abolish this type!
#[derive(Copy, Clone, Debug)]
struct Subtree {
    hash: Hash,
    start: u64,
    end: u64,
}

impl Subtree {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    fn is_root(&self, content_length: u64) -> bool {
        self.start == 0 && self.end == content_length
    }

    fn finalization(&self, content_length: u64) -> Finalization {
        if self.is_root(content_length) {
            Root(self.len())
        } else {
            NotRoot
        }
    }

    fn state_next(&self, content_length: u64, content_position: u64) -> StateNext {
        let skip = content_position - self.start;
        if self.len() <= CHUNK_SIZE as u64 {
            StateNext::Chunk {
                size: self.len() as usize,
                skip: skip as usize,
                finalization: self.finalization(content_length),
            }
        } else {
            StateNext::Subtree {
                size: self.len(),
                skip,
                finalization: self.finalization(content_length),
            }
        }
    }
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
        into_io(self.state.feed_subtree(hash))?;
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
                    Some(StateNext::Subtree { .. }) => self.read_parent()?,
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
        let content_length = loop {
            match self.state.len_next() {
                Left(len) => break len,
                Right(StateNext::Header) => self.read_header()?,
                Right(StateNext::Subtree { .. }) => self.read_parent()?,
                Right(StateNext::Chunk {
                    size,
                    skip,
                    finalization,
                }) => self.read_chunk(size, skip, finalization)?,
            }
        };

        // Compute the absolute position of the seek.
        let position = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(off) => add_offset(content_length, off)?,
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
                Some(StateNext::Subtree { .. }) => {
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

    use self::byteorder::{BigEndian, WriteBytesExt};
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
}
