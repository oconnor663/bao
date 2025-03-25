//! Decode the Bao format, or decode a slice.
//!
//! Decoding verifies that all the bytes of the encoding match the root hash given from the caller.
//! If there's a mismatch, decoding will return an error. It's possible for incremental decoding to
//! return some valid bytes before encountering a error, but it will never return unverified bytes.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::prelude::*;
//!
//! // Encode some example bytes.
//! let input = b"some input";
//! let (encoded, hash) = bao::encode(input);
//!
//! // Decode them with one of the all-at-once functions.
//! let decoded_at_once = bao::decode(&encoded, &hash)?;
//!
//! // Also decode them incrementally.
//! let mut decoded_incrementally = Vec::new();
//! let mut decoder = bao::Decoder::new(&*encoded, &hash);
//! decoder.read_to_end(&mut decoded_incrementally)?;
//!
//! // Assert that we got the same results both times.
//! assert_eq!(decoded_at_once, decoded_incrementally);
//!
//! // Flipping a bit in encoding will cause a decoding error.
//! let mut bad_encoded = encoded.clone();
//! let last_index = bad_encoded.len() - 1;
//! bad_encoded[last_index] ^= 1;
//! let err = bao::decode(&bad_encoded, &hash).unwrap_err();
//! assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
//! # Ok(())
//! # }
//! ```

use crate::encode;
use crate::encode::NextRead;
use crate::{
    Config, DecodeError, Decoder, Hash, ParentNode, SliceDecoder, HEADER_SIZE, PARENT_SIZE,
};
use blake3::hazmat::{ChainingValue, HasherExt};
use blake3::Hasher;
use std::cmp;
use std::error;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

// This incremental verifier layers on top of encode::ParseState, and supports
// both the Decoder and the SliceDecoder.
#[derive(Clone)]
struct VerifyState {
    stack: Vec<ChainingValue>,
    parser: encode::ParseState,
    root_hash: Hash,
}

impl VerifyState {
    fn new(config: Config, hash: &Hash) -> Self {
        let mut stack = Vec::new();
        stack.push(*hash.as_bytes());
        Self {
            stack,
            parser: encode::ParseState::new(config),
            root_hash: *hash,
        }
    }

    fn content_position(&self) -> u64 {
        self.parser.content_position()
    }

    fn read_next(&self) -> NextRead {
        self.parser.read_next()
    }

    fn seek_next(&self, seek_to: u64) -> encode::SeekBookkeeping {
        self.parser.seek_next(seek_to)
    }

    fn seek_bookkeeping_done(&mut self, bookkeeping: encode::SeekBookkeeping) -> encode::NextRead {
        // Leftward seeks require resetting the stack to the beginning.
        if bookkeeping.reset_to_root() {
            self.stack.clear();
            self.stack.push(*self.root_hash.as_bytes());
        }
        // Rightward seeks require popping subtrees off the stack.
        debug_assert!(self.stack.len() >= bookkeeping.stack_depth());
        while self.stack.len() > bookkeeping.stack_depth() {
            self.stack.pop();
        }
        self.parser.seek_bookkeeping_done(bookkeeping)
    }

    fn len_next(&self) -> encode::LenNext {
        self.parser.len_next()
    }

    fn feed_header(&mut self, header: &[u8; HEADER_SIZE]) {
        self.parser.feed_header(header);
    }

    fn feed_parent(&mut self, parent: &ParentNode) -> Result<(), DecodeError> {
        let expected_cv: &ChainingValue = self.stack.last().expect("unexpectedly empty stack");
        let left_child: ChainingValue = (*parent.first_chunk::<32>().unwrap()).into();
        let right_child: ChainingValue = (*parent.last_chunk::<32>().unwrap()).into();
        let computed_cv = if self.parser.at_root() {
            *blake3::hazmat::merge_subtrees_root(
                &left_child,
                &right_child,
                blake3::hazmat::Mode::Hash,
            )
            .as_bytes()
        } else {
            blake3::hazmat::merge_subtrees_non_root(
                &left_child,
                &right_child,
                blake3::hazmat::Mode::Hash,
            )
        };
        // Hash implements constant time equality.
        if Hash::from(*expected_cv) != Hash::from(computed_cv) {
            return Err(DecodeError::HashMismatch);
        }
        self.stack.pop();
        self.stack.push(right_child.into());
        self.stack.push(left_child.into());
        self.parser.advance_parent();
        Ok(())
    }

    fn feed_group(&mut self, group_cv: &ChainingValue) -> Result<(), DecodeError> {
        let expected_cv = self.stack.last().expect("unexpectedly empty stack");
        // Hash implements constant time equality.
        if Hash::from(*expected_cv) != Hash::from(*group_cv) {
            return Err(DecodeError::HashMismatch);
        }
        self.stack.pop();
        self.parser.advance_group();
        Ok(())
    }
}

// It's important to manually implement Debug for VerifyState, because it holds hashes that
// might be secret, and it would be bad to leak them to some debug log somewhere.
impl fmt::Debug for VerifyState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "VerifyState {{ stack_size: {}, parser: {:?} }}",
            self.stack.len(), // *Only* the stack size, not the hashes themselves.
            self.parser,      // The parser state only reveals the content length.
        )
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::HashMismatch => write!(f, "hash mismatch"),
            DecodeError::Truncated => write!(f, "truncated encoding"),
        }
    }
}

impl error::Error for DecodeError {}

impl From<DecodeError> for io::Error {
    fn from(e: DecodeError) -> io::Error {
        match e {
            DecodeError::HashMismatch => {
                io::Error::new(io::ErrorKind::InvalidData, "hash mismatch")
            }
            DecodeError::Truncated => {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated encoding")
            }
        }
    }
}

// Shared between Decoder and SliceDecoder.
#[derive(Clone)]
pub struct DecoderShared<T: Read, O: Read> {
    input: T,
    outboard: Option<O>,
    state: VerifyState,
    buf: Vec<u8>,
    buf_start: usize,
    buf_end: usize,
}

impl<T: Read, O: Read> DecoderShared<T, O> {
    pub fn new(config: Config, input: T, outboard: Option<O>, hash: &Hash) -> Self {
        Self {
            input,
            outboard,
            state: VerifyState::new(config, hash),
            buf: vec![0; config.group_size],
            buf_start: 0,
            buf_end: 0,
        }
    }

    fn adjusted_content_position(&self) -> u64 {
        // If the current buffer_len is non-empty, then it contains the bytes
        // immediately prior to the next read.
        self.state.content_position() - self.buf_len() as u64
    }

    fn buf_len(&self) -> usize {
        self.buf_end - self.buf_start
    }

    fn clear_buf(&mut self) {
        self.buf_start = 0;
        self.buf_end = 0;
    }

    // These bytes are always verified before going in the buffer.
    fn take_buffered_bytes(&mut self, output: &mut [u8]) -> usize {
        let take = cmp::min(self.buf_len(), output.len());
        output[..take].copy_from_slice(&self.buf[self.buf_start..self.buf_start + take]);
        self.buf_start += take;
        take
    }

    fn get_and_feed_header(&mut self) -> io::Result<()> {
        debug_assert_eq!(0, self.buf_len());
        let mut header = [0; HEADER_SIZE];
        if let Some(outboard) = &mut self.outboard {
            outboard.read_exact(&mut header)?;
        } else {
            self.input.read_exact(&mut header)?;
        }
        self.state.feed_header(&header);
        Ok(())
    }

    fn get_parent(&mut self) -> io::Result<ParentNode> {
        debug_assert_eq!(0, self.buf_len());
        let mut parent = [0; PARENT_SIZE];
        if let Some(outboard) = &mut self.outboard {
            outboard.read_exact(&mut parent)?;
        } else {
            self.input.read_exact(&mut parent)?;
        }
        Ok(parent)
    }

    fn get_and_feed_parent(&mut self) -> io::Result<()> {
        let parent = self.get_parent()?;
        self.state.feed_parent(&parent)?;
        Ok(())
    }

    fn buffer_verified_group(
        &mut self,
        size: usize,
        is_root: bool,
        skip: usize,
        input_offset: u64,
        parents_to_read: usize,
    ) -> io::Result<()> {
        debug_assert_eq!(0, self.buf_len());
        self.buf_start = 0;
        self.buf_end = 0;
        for _ in 0..parents_to_read {
            // Making a separate read call for each parent isn't ideal, but
            // this is the slow path anyway. The fast path's read ahead
            // approach optimizes parent reads better.
            self.get_and_feed_parent()?;
        }
        let buf_slice = &mut self.buf[..size];
        self.input.read_exact(buf_slice)?;
        let mut hasher = Hasher::new();
        hasher.set_input_offset(input_offset);
        hasher.update(buf_slice);
        let group_cv: ChainingValue = if is_root {
            hasher.finalize().into()
        } else {
            hasher.finalize_non_root()
        };
        self.state.feed_group(&group_cv)?;
        self.buf_start = skip;
        self.buf_end = size;
        Ok(())
    }

    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // Explicitly short-circuit zero-length reads. We're within our rights
        // to buffer an internal chunk in this case, or to make progress if
        // there's an empty chunk, but this matches the current behavior of
        // SliceExtractor for zero-length slices. This might change in the
        // future.
        if output.is_empty() {
            return Ok(0);
        }

        // If there are bytes in the internal buffer, just return those.
        if self.buf_len() > 0 {
            return Ok(self.take_buffered_bytes(output));
        }

        // Otherwise try to verify a new chunk.
        loop {
            match self.state.read_next() {
                NextRead::Done => {
                    // This is EOF. We know the internal buffer is empty,
                    // because we checked it before this loop.
                    return Ok(0);
                }
                NextRead::Header => {
                    self.get_and_feed_header()?;
                }
                NextRead::Parent => {
                    self.get_and_feed_parent()?;
                }
                NextRead::ChunkGroup {
                    size,
                    is_root,
                    skip,
                    input_offset,
                } => {
                    debug_assert_eq!(self.buf_len(), 0);

                    // If we can, read the group directly into the `output`
                    // buffer, to avoid extra copies. If there's a verification
                    // error, the caller won't read the invalid bytes, because
                    // we won't return a length.
                    let (read_buf, direct_output) = if output.len() >= size && skip == 0 {
                        (&mut output[..size], true)
                    } else {
                        (&mut self.buf[..size], false)
                    };

                    // Read the unverified group.
                    self.input.read_exact(read_buf)?;

                    // Hash it and push its hash into the VerifyState. This
                    // returns an error if the hash is bad. Otherwise, the
                    // group is verifiied.
                    let mut group_hasher = Hasher::new();
                    group_hasher.set_input_offset(input_offset);
                    group_hasher.update(read_buf);
                    let group_cv = if is_root {
                        group_hasher.finalize().into()
                    } else {
                        group_hasher.finalize_non_root()
                    };
                    self.state.feed_group(&group_cv)?;

                    // If the output buffer was large enough for direct output,
                    // we're done. Otherwise, we need to update the internal
                    // buffer state and return some bytes.
                    if direct_output {
                        return Ok(size);
                    } else {
                        self.buf_start = skip;
                        self.buf_end = size;
                        return Ok(self.take_buffered_bytes(output));
                    }
                }
            }
        }
    }

    // Returns Ok(true) to indicate the seek is finished. Note that both the
    // Decoder and the SliceDecoder will use this method (which doesn't depend on
    // io::Seek), but only the Decoder will call handle_seek_bookkeeping first.
    // This may read a group, but it never leaves output bytes in the buffer,
    // because the only time seeking reads a group it also skips the entire
    // thing.
    fn handle_seek_read(&mut self, next: NextRead) -> io::Result<bool> {
        debug_assert_eq!(0, self.buf_len());
        match next {
            NextRead::Header => self.get_and_feed_header()?,
            NextRead::Parent => self.get_and_feed_parent()?,
            NextRead::ChunkGroup {
                size,
                is_root,
                skip,
                input_offset,
            } => {
                self.buffer_verified_group(
                    size,
                    is_root,
                    skip,
                    input_offset,
                    0, /* parents_to_read */
                )?;
                debug_assert_eq!(0, self.buf_len());
            }
            NextRead::Done => return Ok(true), // The seek is done.
        }
        Ok(false)
    }
}

impl<T: Read + Seek, O: Read + Seek> DecoderShared<T, O> {
    // The Decoder will call this as part of seeking, but note that the
    // SliceDecoder won't, because all the seek bookkeeping has already been
    // taken care of during slice extraction.
    fn handle_seek_bookkeeping(
        &mut self,
        bookkeeping: encode::SeekBookkeeping,
    ) -> io::Result<NextRead> {
        // The VerifyState handles all the subtree stack management. We just
        // need to handle the underlying seek. This is done differently
        // depending on whether the encoding is combined or outboard.
        if let Some(outboard) = &mut self.outboard {
            if let Some((content_pos, outboard_pos)) = bookkeeping.underlying_seek_outboard() {
                // As with Decoder in the outboard case, the outboard extractor has to seek both of
                // its inner readers. The content position of the state goes into the content
                // reader, and the rest of the reported seek offset goes into the outboard reader.
                self.input.seek(SeekFrom::Start(content_pos))?;
                outboard.seek(SeekFrom::Start(outboard_pos))?;
            }
        } else {
            if let Some(encoding_position) = bookkeeping.underlying_seek() {
                self.input.seek(SeekFrom::Start(encoding_position))?;
            }
        }
        let next = self.state.seek_bookkeeping_done(bookkeeping);
        Ok(next)
    }
}

impl<T: Read, O: Read> fmt::Debug for DecoderShared<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DecoderShared {{ is_outboard: {}, state: {:?}, buf_start: {}, buf_end: {} }}",
            self.outboard.is_some(),
            self.state,
            self.buf_start,
            self.buf_end,
        )
    }
}

impl<T: Read> Decoder<T, T> {
    pub fn new(inner: T, hash: &Hash) -> Self {
        Config::default().new_decoder(inner, hash)
    }
}

impl<T: Read, O: Read> Decoder<T, O> {
    pub fn new_outboard(inner: T, outboard: O, hash: &Hash) -> Self {
        Config::default().new_outboard_decoder(inner, outboard, hash)
    }

    /// Return the underlying reader and the outboard reader, if any. If the `Decoder` was created
    /// with `Decoder::new`, the outboard reader will be `None`.
    pub fn into_inner(self) -> (T, Option<O>) {
        (self.shared.input, self.shared.outboard)
    }
}

impl<T: Read, O: Read> Read for Decoder<T, O> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.shared.read(output)
    }
}

impl<T: Read + Seek, O: Read + Seek> Seek for Decoder<T, O> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Clear the internal buffer when seeking. The buffered bytes won't be
        // valid reads at the new offset.
        self.shared.clear_buf();

        // Get the absolute seek offset. If the caller passed in
        // SeekFrom::Start, that's what we've got. If not, we need to compute
        // it.
        let seek_to = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                // To seek from the end we have to get the length, and that may
                // require as a seek loop of its own to verify the length.
                let content_len = loop {
                    match self.shared.state.len_next() {
                        encode::LenNext::Seek(bookkeeping) => {
                            let next_read = self.shared.handle_seek_bookkeeping(bookkeeping)?;
                            let done = self.shared.handle_seek_read(next_read)?;
                            debug_assert!(!done);
                        }
                        encode::LenNext::Len(len) => break len,
                    }
                };
                add_offset(content_len, offset)?
            }
            SeekFrom::Current(offset) => {
                add_offset(self.shared.adjusted_content_position(), offset)?
            }
        };

        // Now with the absolute seek offset, we perform the real (possibly
        // second) seek loop.
        loop {
            let bookkeeping = self.shared.state.seek_next(seek_to);
            let next_read = self.shared.handle_seek_bookkeeping(bookkeeping)?;
            let done = self.shared.handle_seek_read(next_read)?;
            if done {
                return Ok(seek_to);
            }
        }
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

impl<T: Read> SliceDecoder<T> {
    pub fn new(inner: T, hash: &Hash, slice_start: u64, slice_len: u64) -> Self {
        Config::default().new_slice_decoder(inner, hash, slice_start, slice_len)
    }

    /// Return the underlying reader.
    pub fn into_inner(self) -> T {
        self.shared.input
    }
}

impl<T: Read> Read for SliceDecoder<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // If we haven't done the initial seek yet, do the full seek loop
        // first. Note that this will never leave any buffered output. The only
        // scenario where handle_seek_read reads a group is if it needs to
        // validate the final group, and then it skips the whole thing.
        if self.shared.state.content_position() < self.slice_start {
            loop {
                let bookkeeping = self.shared.state.seek_next(self.slice_start);
                // Note here, we skip to seek_bookkeeping_done without
                // calling handle_seek_bookkeeping. That is, we never
                // perform any underlying seeks. The slice extractor
                // already took care of lining everything up for us.
                let next = self.shared.state.seek_bookkeeping_done(bookkeeping);
                let done = self.shared.handle_seek_read(next)?;
                if done {
                    break;
                }
            }
            debug_assert_eq!(0, self.shared.buf_len());
        }

        // We either just finished the seek (if any), or already did it during
        // a previous call. Continue the read. Cap the output buffer to be at
        // most the slice bytes remaining.
        if self.need_fake_read {
            // Read one byte and throw it away, just to verify something.
            self.shared.read(&mut [0])?;
            self.need_fake_read = false;
            Ok(0)
        } else {
            let cap = cmp::min(self.slice_remaining, output.len() as u64) as usize;
            let capped_output = &mut output[..cap];
            let n = self.shared.read(capped_output)?;
            self.slice_remaining -= n as u64;
            Ok(n)
        }
    }
}

#[cfg(test)]
pub fn make_test_input(len: usize) -> Vec<u8> {
    // Fill the input with incrementing bytes, so that reads from different sections are very
    // unlikely to accidentally match.
    let mut ret = Vec::new();
    let mut counter = 0u64;
    while ret.len() < len {
        if counter < u8::max_value() as u64 {
            ret.push(counter as u8);
        } else if counter < u16::max_value() as u64 {
            ret.extend_from_slice(&(counter as u16).to_be_bytes());
        } else if counter < u32::max_value() as u64 {
            ret.extend_from_slice(&(counter as u32).to_be_bytes());
        } else {
            ret.extend_from_slice(&(counter as u64).to_be_bytes());
        }
        counter += 1;
    }
    ret.truncate(len);
    ret
}

#[cfg(test)]
mod test {
    use rand::prelude::*;
    use rand_chacha::ChaChaRng;
    use std::io::prelude::*;
    use std::io::Cursor;

    use super::*;
    use crate::SliceExtractor;

    #[test]
    fn test_decode() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, hash) = { crate::encode(&input) };
            let output = crate::decode(&encoded, &hash).unwrap();
            assert_eq!(input, output);
            assert_eq!(output.len(), output.capacity());
        }
    }

    #[test]
    fn test_decode_outboard() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (outboard, hash) = { Config::default().encode_outboard(&input) };
            let mut output = Vec::new();
            let mut reader = Decoder::new_outboard(&input[..], &outboard[..], &hash);
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(input, output);
        }
    }

    #[test]
    fn test_decoders_corrupted() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, hash) = crate::encode(&input);
            // Don't tweak the header in this test, because that usually causes a panic.
            let mut tweaks = Vec::new();
            if encoded.len() > HEADER_SIZE {
                tweaks.push(HEADER_SIZE);
            }
            if encoded.len() > HEADER_SIZE + PARENT_SIZE {
                tweaks.push(HEADER_SIZE + PARENT_SIZE);
            }
            if encoded.len() > crate::CHUNK_SIZE {
                tweaks.push(crate::CHUNK_SIZE);
            }
            for tweak in tweaks {
                println!("tweak {}", tweak);
                let mut bad_encoded = encoded.clone();
                bad_encoded[tweak] ^= 1;

                let err = crate::decode(&bad_encoded, &hash).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in crate::test::TEST_CASES {
            println!();
            println!("input_len {}", input_len);
            let input = make_test_input(input_len);
            let (encoded, hash) = crate::encode(&input);
            for &seek in crate::test::TEST_CASES {
                println!("seek {}", seek);
                // Test all three types of seeking.
                let mut seek_froms = Vec::new();
                seek_froms.push(SeekFrom::Start(seek as u64));
                seek_froms.push(SeekFrom::End(seek as i64 - input_len as i64));
                seek_froms.push(SeekFrom::Current(seek as i64));
                for seek_from in seek_froms {
                    println!("seek_from {:?}", seek_from);
                    let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
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
        for &group_size in encode::test::INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            // A group count like this (37) with consecutive zeroes should exercise some of the more
            // interesting geometry cases.
            let input_len = 0b100101 * group_size;
            println!("\n\ninput_len {}", input_len);
            let mut prng = ChaChaRng::from_seed([0; 32]);
            let input = make_test_input(input_len);
            let (encoded, hash) = config.encode(&input);
            let mut decoder = config.new_decoder(Cursor::new(&encoded), &hash);
            // Do a thousand random seeks and group-sized reads.
            for _ in 0..1000 {
                let seek = prng.random_range(0..input_len + 1);
                println!("\nseek {}", seek);
                decoder
                    .seek(SeekFrom::Start(seek as u64))
                    .expect("seek error");
                // Clone the encoder before reading, to test repeated seeks on the same encoder.
                let mut output = Vec::new();
                decoder
                    .clone()
                    .take(group_size as u64)
                    .read_to_end(&mut output)
                    .expect("decoder error");
                let input_start = cmp::min(seek, input_len);
                let input_end = cmp::min(input_start + group_size, input_len);
                assert_eq!(
                    &input[input_start..input_end],
                    &output[..],
                    "output doesn't match input"
                );
            }
        }
    }

    #[test]
    fn test_invalid_zero_length() {
        // There are different ways of structuring a decoder, and many of them are vulnerable to a
        // mistake where as soon as the decoder reads zero length, it believes it's finished. But
        // it's not finished, because it hasn't verified the hash! There must be something to
        // distinguish the state "just decoded the zero length" from the state "verified the hash
        // of the empty root node", and a decoder must not return EOF before the latter.

        let (zero_encoded, zero_hash) = crate::encode(b"");
        let one_hash = blake3::hash(b"x");

        // Decoding the empty tree with the right hash should succeed.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &zero_hash);
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(&output, b"");

        // Decoding the empty tree with any other hash should fail.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &one_hash);
        let result = decoder.read_to_end(&mut output);
        assert!(result.is_err(), "a bad hash is supposed to fail!");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_seeking_around_invalid_data() {
        for &group_size in encode::test::INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            for &case in crate::test::TEST_CASES {
                // Skip the cases with only one or two groups, so we have valid
                // reads before and after the tweak.
                if case <= 2 * config.group_size {
                    continue;
                }

                dbg!(case);
                let input = make_test_input(case);
                let (mut encoded, hash) = config.encode(&input);
                dbg!(encoded.len());

                // Tweak a bit at the start of a group about halfway through. Loop
                // over prior parent nodes and groups to figure out where the
                // target group actually starts.
                let tweak_group = config.count_groups(case as u64) / 2;
                let tweak_position = tweak_group as usize * config.group_size;
                dbg!(tweak_position);
                let mut tweak_encoded_offset = HEADER_SIZE;
                for group_index in 0..tweak_group {
                    tweak_encoded_offset +=
                        encode::pre_order_parent_nodes(config, group_index, case as u64) as usize
                            * PARENT_SIZE;
                    tweak_encoded_offset += config.group_size;
                }
                tweak_encoded_offset +=
                    encode::pre_order_parent_nodes(config, tweak_group, case as u64) as usize
                        * PARENT_SIZE;
                println!("tweak encoded offset {}", tweak_encoded_offset);
                encoded[tweak_encoded_offset] ^= 1;

                // Read all the bits up to that tweak. Because it's right after a group boundary, the
                // read should succeed.
                let mut decoder = config.new_decoder(Cursor::new(&encoded), &hash);
                let mut output = vec![0; tweak_position as usize];
                decoder.read_exact(&mut output).unwrap();
                assert_eq!(&input[..tweak_position], &*output);

                // Further reads at this point should fail.
                let mut buf = vec![0; config.group_size];
                let res = decoder.read(&mut buf);
                assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);

                // But now if we seek past the bad group, things should succeed again.
                let new_start = tweak_position + config.group_size;
                decoder.seek(SeekFrom::Start(new_start as u64)).unwrap();
                let mut output = Vec::new();
                decoder.read_to_end(&mut output).unwrap();
                assert_eq!(&input[new_start..], &*output);
            }
        }
    }

    #[test]
    fn test_invalid_eof_seek() {
        // The decoder must validate the final group as part of seeking to or
        // past EOF.
        for &group_size in encode::test::INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            for &case in crate::test::TEST_CASES {
                dbg!(case);
                let input = make_test_input(case);
                let (encoded, hash) = config.encode(&input);

                // Seeking to EOF should succeed with the right hash.
                let mut output = Vec::new();
                let mut decoder = config.new_decoder(Cursor::new(&encoded), &hash);
                decoder.seek(SeekFrom::Start(case as u64)).unwrap();
                decoder.read_to_end(&mut output).unwrap();
                assert_eq!(&output, b"");

                // Seeking to EOF should fail if the root hash is wrong.
                let mut bad_hash_bytes = *hash.as_bytes();
                bad_hash_bytes[0] ^= 1;
                let bad_hash = bad_hash_bytes.into();
                let mut decoder = config.new_decoder(Cursor::new(&encoded), &bad_hash);
                let result = decoder.seek(SeekFrom::Start(case as u64));
                assert!(result.is_err(), "a bad hash is supposed to fail!");
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);

                // It should also fail if the final group has been corrupted.
                if case > 0 {
                    let mut bad_encoded = encoded.clone();
                    *bad_encoded.last_mut().unwrap() ^= 1;
                    let mut decoder = config.new_decoder(Cursor::new(&bad_encoded), &hash);
                    let result = decoder.seek(SeekFrom::Start(case as u64));
                    assert!(result.is_err(), "a bad hash is supposed to fail!");
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                }
            }
        }
    }

    #[test]
    fn test_slices() {
        for &group_size in encode::test::INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            for &case in crate::test::TEST_CASES {
                dbg!(case);
                let input = make_test_input(case);
                let (encoded, hash) = config.encode(&input);
                // Also make an outboard encoding, to test that case.
                let (outboard, outboard_hash) = config.encode_outboard(&input);
                assert_eq!(hash, outboard_hash);
                for &slice_start in crate::test::TEST_CASES {
                    let expected_start = cmp::min(input.len(), slice_start);
                    let slice_lens = [0, 1, 2, group_size - 1, group_size, group_size + 1];
                    for &slice_len in slice_lens.iter() {
                        println!("\ncase {} start {} len {}", case, slice_start, slice_len);
                        let expected_end = cmp::min(input.len(), slice_start + slice_len);
                        let expected_output = &input[expected_start..expected_end];
                        let mut slice = Vec::new();
                        let mut extractor = config.new_slice_extractor(
                            Cursor::new(&encoded),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice).unwrap();

                        // Make sure the outboard extractor produces the same output.
                        let mut slice_from_outboard = Vec::new();
                        let mut extractor = config.new_outboard_slice_extractor(
                            Cursor::new(&input),
                            Cursor::new(&outboard),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice_from_outboard).unwrap();
                        assert_eq!(slice, slice_from_outboard);

                        let mut output = Vec::new();
                        let mut reader = config.new_slice_decoder(
                            &*slice,
                            &hash,
                            slice_start as u64,
                            slice_len as u64,
                        );
                        reader.read_to_end(&mut output).unwrap();
                        assert_eq!(expected_output, &*output);
                    }
                }
            }
        }
    }

    #[test]
    fn test_corrupted_slice() {
        for &group_size in encode::test::INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            let input = make_test_input(20_000);
            let slice_start = 5_000;
            let slice_len = 10_000;
            let (encoded, hash) = config.encode(&input);

            // Slice out the middle 10_000 bytes;
            let mut slice = Vec::new();
            let mut extractor = config.new_slice_extractor(
                Cursor::new(&encoded),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice).unwrap();

            // First confirm that the regular decode works.
            let mut output = Vec::new();
            let mut reader =
                config.new_slice_decoder(&*slice, &hash, slice_start as u64, slice_len as u64);
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(&input[slice_start..][..slice_len], &*output);

            // Also confirm that the outboard slice extractor gives the same slice.
            let (outboard, outboard_hash) = config.encode_outboard(&input);
            assert_eq!(hash, outboard_hash);
            let mut slice_from_outboard = Vec::new();
            let mut extractor = config.new_outboard_slice_extractor(
                Cursor::new(&input),
                Cursor::new(&outboard),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice_from_outboard).unwrap();
            assert_eq!(slice, slice_from_outboard);

            // Now confirm that flipping bits anywhere in the slice other than the
            // length header will corrupt it. Tweaking the length header doesn't
            // always break slice decoding, because the only thing its guaranteed
            // to break is the final chunk, and this slice doesn't include the
            // final chunk.
            let mut i = HEADER_SIZE;
            while i < slice.len() {
                let mut slice_clone = slice.clone();
                slice_clone[i] ^= 1;
                let mut reader = config.new_slice_decoder(
                    &*slice_clone,
                    &hash,
                    slice_start as u64,
                    slice_len as u64,
                );
                output.clear();
                let err = reader.read_to_end(&mut output).unwrap_err();
                assert_eq!(io::ErrorKind::InvalidData, err.kind());
                i += 32;
            }
        }
    }

    #[test]
    fn test_slice_entire() {
        // If a slice starts at the beginning (actually anywere in the first chunk) and includes
        // entire length of the content (or at least one byte in the last chunk), the slice should
        // be exactly the same as the entire encoded tree. This can act as a cheap way to convert
        // an outboard tree to a combined one.
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, _) = crate::encode(&input);
            let (outboard, _) = Config::default().encode_outboard(&input);
            let mut slice = Vec::new();
            let mut extractor = SliceExtractor::new_outboard(
                Cursor::new(&input),
                Cursor::new(&outboard),
                0,
                case as u64,
            );
            extractor.read_to_end(&mut slice).unwrap();
            assert_eq!(encoded, slice);
        }
    }

    #[test]
    fn test_into_inner() {
        let v = vec![1u8, 2, 3];
        let hash = [0; 32].into();

        let decoder = Decoder::new(io::Cursor::new(v.clone()), &hash);
        let (inner_reader, outboard_reader) = decoder.into_inner();
        assert!(outboard_reader.is_none());
        let slice_decoder = SliceDecoder::new(inner_reader, &hash, 0, 0);
        assert_eq!(slice_decoder.into_inner().into_inner(), v);

        let outboard_decoder = Decoder::new_outboard(&b""[..], &b""[..], &hash);
        let (_, outboard_reader) = outboard_decoder.into_inner();
        assert!(outboard_reader.is_some());
    }
}
