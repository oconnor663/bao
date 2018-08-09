extern crate constant_time_eq;
extern crate rayon;

use self::constant_time_eq::constant_time_eq;
use arrayvec::ArrayVec;

use encode;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, MAX_DEPTH, PARENT_SIZE};

use std::cmp;
use std::fmt;
use std::io;
use std::io::prelude::*;

pub fn decode(encoded: &[u8], output: &mut [u8], hash: Hash) -> Result<(), ()> {
    let content_len = hash::decode_len(*array_ref!(encoded, 0, HEADER_SIZE));
    // Note that trailing garbage in the encoding is allowed.
    assert_eq!(
        output.len() as u64,
        content_len,
        "output is the wrong length"
    );
    if content_len <= hash::MAX_SINGLE_THREADED as u64 {
        decode_recurse(&encoded[HEADER_SIZE..], output, hash, Root(content_len))
    } else {
        decode_recurse_rayon(&encoded[HEADER_SIZE..], output, hash, Root(content_len))
    }
}

pub fn decode_single_threaded(encoded: &[u8], output: &mut [u8], hash: Hash) -> Result<(), ()> {
    let content_len = hash::decode_len(*array_ref!(encoded, 0, HEADER_SIZE));
    // Note that trailing garbage in the encoding is allowed.
    assert_eq!(
        output.len() as u64,
        content_len,
        "output is the wrong length"
    );
    decode_recurse(&encoded[HEADER_SIZE..], output, hash, Root(content_len))
}

pub fn decode_recurse(
    encoded: &[u8],
    output: &mut [u8],
    hash: Hash,
    finalization: Finalization,
) -> Result<(), ()> {
    let content_len = output.len();
    if content_len <= CHUNK_SIZE {
        let computed_hash = hash::hash_node(&encoded[..content_len], finalization);
        if !constant_time_eq(&hash, &computed_hash) {
            return Err(());
        }
        output.copy_from_slice(&encoded[..content_len]);
        return Ok(());
    }
    let left_hash = *array_ref!(encoded, 0, HASH_SIZE);
    let right_hash = *array_ref!(encoded, HASH_SIZE, HASH_SIZE);
    let computed_hash = hash::parent_hash(&left_hash, &right_hash, finalization);
    if !constant_time_eq(&hash, &computed_hash) {
        return Err(());
    }
    let left_len = hash::left_len(content_len as u64);
    let (left_output, right_output) = output.split_at_mut(left_len as usize);
    let left_encoded_len = encode::encoded_subtree_size(left_len);
    let (left_encoded, right_encoded) = encoded[PARENT_SIZE..].split_at(left_encoded_len as usize);
    decode_recurse(left_encoded, left_output, left_hash, NotRoot)?;
    decode_recurse(right_encoded, right_output, right_hash, NotRoot)
}

pub fn decode_recurse_rayon(
    encoded: &[u8],
    output: &mut [u8],
    hash: Hash,
    finalization: Finalization,
) -> Result<(), ()> {
    let content_len = output.len();
    if content_len <= CHUNK_SIZE {
        let computed_hash = hash::hash_node(&encoded[..content_len], finalization);
        if !constant_time_eq(&hash, &computed_hash) {
            return Err(());
        }
        output.copy_from_slice(&encoded[..content_len]);
        return Ok(());
    }
    let left_hash = *array_ref!(encoded, 0, HASH_SIZE);
    let right_hash = *array_ref!(encoded, HASH_SIZE, HASH_SIZE);
    let computed_hash = hash::parent_hash(&left_hash, &right_hash, finalization);
    if !constant_time_eq(&hash, &computed_hash) {
        return Err(());
    }
    let left_len = hash::left_len(content_len as u64);
    let (left_output, right_output) = output.split_at_mut(left_len as usize);
    let left_encoded_len = encode::encoded_subtree_size(left_len);
    let (left_encoded, right_encoded) = encoded[PARENT_SIZE..].split_at(left_encoded_len as usize);
    let (left_result, right_result) = rayon::join(
        || decode_recurse(left_encoded, left_output, left_hash, NotRoot),
        || decode_recurse(right_encoded, right_output, right_hash, NotRoot),
    );
    left_result.and(right_result)
}

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

    pub fn feed_parent(&mut self, parent: hash::ParentNode) -> Result<(), ()> {
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

    pub fn feed_chunk(&mut self, chunk_hash: Hash) -> Result<(), ()> {
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

fn into_io<T>(r: Result<T, ()>) -> io::Result<T> {
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
    use std::io;
    use std::io::prelude::*;
    use std::io::Cursor;

    use super::*;
    use encode;
    use hash;

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
    fn test_decoders() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let mut encoded = Vec::new();
            let hash = { encode::encode_to_vec(&input, &mut encoded) };

            let mut output = vec![0; case];
            decode_recurse(
                &encoded[HEADER_SIZE..],
                &mut output,
                hash,
                Root(case as u64),
            ).unwrap();
            assert_eq!(input, output);

            let mut output = vec![0; case];
            decode_recurse_rayon(
                &encoded[HEADER_SIZE..],
                &mut output,
                hash,
                Root(case as u64),
            ).unwrap();
            assert_eq!(input, output);

            let mut output = vec![0; case];
            decode(&encoded, &mut output, hash).unwrap();
            assert_eq!(input, output);

            let mut output = vec![0; case];
            decode_single_threaded(&encoded, &mut output, hash).unwrap();
            assert_eq!(input, output);

            let mut output = Vec::new();
            let mut decoder = Reader::new(&encoded[..], hash);
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(input, output);
        }
    }

    #[test]
    fn test_decoders_corrupted() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let mut encoded = Vec::new();
            let hash = encode::encode_to_vec(&input, &mut encoded);
            // Don't tweak the header in this test, because that usually causes a panic.
            let mut tweaks = Vec::new();
            if encoded.len() > HEADER_SIZE {
                tweaks.push(HEADER_SIZE);
            }
            if encoded.len() > HEADER_SIZE + PARENT_SIZE {
                tweaks.push(HEADER_SIZE + PARENT_SIZE);
            }
            if encoded.len() > CHUNK_SIZE {
                tweaks.push(CHUNK_SIZE);
            }
            for tweak in tweaks {
                println!("tweak {}", tweak);
                let mut bad_encoded = encoded.clone();
                bad_encoded[tweak] ^= 1;

                let mut output = vec![0; case];
                let res = decode_recurse(
                    &bad_encoded[HEADER_SIZE..],
                    &mut output,
                    hash,
                    Root(case as u64),
                );
                assert!(res.is_err());

                let mut output = vec![0; case];
                let res = decode_recurse_rayon(
                    &bad_encoded[HEADER_SIZE..],
                    &mut output,
                    hash,
                    Root(case as u64),
                );
                assert!(res.is_err());

                let mut output = vec![0; case];
                let res = decode(&bad_encoded, &mut output, hash);
                assert!(res.is_err());

                let mut output = vec![0; case];
                let res = decode_single_threaded(&bad_encoded, &mut output, hash);
                assert!(res.is_err());
            }
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in hash::TEST_CASES {
            println!();
            println!("input_len {}", input_len);
            let input = make_test_input(input_len);
            let mut encoded = Vec::new();
            let hash = encode::encode_to_vec(&input, &mut encoded);
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
        let mut encoded = Vec::new();
        let hash = encode::encode_to_vec(&input, &mut encoded);
        let mut decoder = Reader::new(Cursor::new(&encoded), hash);
        // Do a thousand random seeks and chunk-sized reads.
        for _ in 0..1000 {
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

    #[test]
    fn test_invalid_zero_length() {
        // There are different ways of structuring a decoder, and many of them are vulnerable to a
        // mistake where as soon as the decoder reads zero length, it believes it's finished. But
        // it's not finished, because it hasn't verified the hash! There must be something to
        // distinguish the state "just decoded the zero length" from the state "verified the hash
        // of the empty root node", and a decoder must not return EOF before the latter.

        let mut zero_encoded = Vec::new();
        let zero_hash = encode::encode_to_vec(b"", &mut zero_encoded);
        let one_hash = hash::hash(b"x");

        // Decoding the empty tree with the right hash should succeed.
        let mut output = Vec::new();
        let mut decoder = Reader::new(&*zero_encoded, zero_hash);
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(&output, &[]);

        // Decoding the empty tree with any other hash should fail.
        let mut output = Vec::new();
        let mut decoder = Reader::new(&*zero_encoded, one_hash);
        let result = decoder.read_to_end(&mut output);
        assert!(result.is_err(), "a bad hash is supposed to fail!");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_seeking_around_invalid_data() {
        for &case in hash::TEST_CASES {
            // Skip the cases with only one chunk, so that the root stays valid.
            if case <= CHUNK_SIZE {
                continue;
            }

            println!("case {}", case);
            let input = make_test_input(case);
            let mut encoded = Vec::new();
            let hash = encode::encode_to_vec(&input, &mut encoded);
            println!("encoded len {}", encoded.len());

            // Tweak a bit at the start of a chunk about halfway through. Loop over prior parent
            // nodes and chunks to figure out where the target chunk actually starts.
            let tweak_chunk = (case / CHUNK_SIZE / 2) as u64;
            let tweak_position = tweak_chunk as usize * CHUNK_SIZE;
            println!("tweak position {}", tweak_position);
            let mut tweak_encoded_offset = HEADER_SIZE;
            for chunk in 0..tweak_chunk {
                tweak_encoded_offset +=
                    encode::pre_order_parent_nodes(chunk, case as u64) as usize * PARENT_SIZE;
                tweak_encoded_offset += CHUNK_SIZE;
            }
            tweak_encoded_offset +=
                encode::pre_order_parent_nodes(tweak_chunk, case as u64) as usize * PARENT_SIZE;
            println!("tweak encoded offset {}", tweak_encoded_offset);
            encoded[tweak_encoded_offset] ^= 1;

            // Read all the bits up to that tweak. Because it's right after a chunk boundary, the
            // read should succeed.
            let mut decoder = Reader::new(Cursor::new(&encoded), hash);
            let mut output = vec![0; tweak_position as usize];
            decoder.read_exact(&mut output).unwrap();
            assert_eq!(&input[..tweak_position], &*output);

            // Further reads at this point should fail.
            let mut buf = [0; CHUNK_SIZE];
            let res = decoder.read(&mut buf);
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);

            // But now if we seek past the bad chunk, things should succeed again.
            let new_start = tweak_position + CHUNK_SIZE;
            decoder.seek(io::SeekFrom::Start(new_start as u64)).unwrap();
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(&input[new_start..], &*output);
        }
    }

    #[test]
    fn test_invalid_hash_with_eof_seek() {
        // Similar to above, the decoder must keep track of whether it's validated the root node,
        // even if the caller attempts to seek past the end of the file before reading anything.
        for &case in hash::TEST_CASES {
            let input = vec![0; case];
            let mut encoded = Vec::new();
            let hash = encode::encode_to_vec(&input, &mut encoded);
            let mut bad_hash = hash;
            bad_hash[0] ^= 1;

            // Seeking past the end of a tree should succeed with the right hash.
            let mut output = Vec::new();
            let mut decoder = Reader::new(Cursor::new(&encoded), hash);
            decoder.seek(io::SeekFrom::Start(case as u64)).unwrap();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(&output, &[]);

            // Seeking past the end of a tree should fail if the root hash is wrong.
            let mut decoder = Reader::new(Cursor::new(&encoded), bad_hash);
            let result = decoder.seek(io::SeekFrom::Start(case as u64));
            assert!(result.is_err(), "a bad hash is supposed to fail!");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}
