//! Decode the Bao format, or decode a slice.
//!
//! Decoding verifies that all the bytes of the encoding match the root hash given from the caller.
//! If there's a mismatch, decoding will return an error. It's possible for incremental decoding to
//! return some valid bytes before encountering a error, but it will never return unverified bytes.
//!
//! This module requires the `std` feature, which is enabled by default. The
//! standard library is only used for the `std::io::{Read, Write, Seek}`
//! traits. This implementation does not allocate.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<std::error::Error>> {
//! use std::io::prelude::*;
//!
//! // Encode some example bytes.
//! let input = b"some input";
//! let (encoded, hash) = bao::encode::encode(input);
//!
//! // Decode them with one of the all-at-once functions.
//! let decoded_at_once = bao::decode::decode(&encoded, &hash)?;
//!
//! // Also decode them incrementally.
//! let mut decoded_incrementally = Vec::new();
//! {
//!     let mut decoder = bao::decode::Decoder::new(&*encoded, &hash);
//!     // The inner block here limits the lifetime of this mutable borrow.
//!     decoder.read_to_end(&mut decoded_incrementally)?;
//! }
//!
//! // Assert that we got the same results both times.
//! assert_eq!(decoded_at_once, decoded_incrementally);
//!
//! // Flipping a bit in encoding will cause a decoding error.
//! let mut bad_encoded = encoded.clone();
//! let last_index = bad_encoded.len() - 1;
//! bad_encoded[last_index] ^= 1;
//! let err = bao::decode::decode(&bad_encoded, &hash).unwrap_err();
//! assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
//! # Ok(())
//! # }
//! ```

use crate::encode;
use crate::encode::NextRead;
use crate::hash::{
    self, chunk_params, parent_params, Finalization, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE,
    MAX_DEPTH, PARENT_SIZE,
};
use arrayref::{array_ref, array_refs};
use arrayvec::ArrayVec;
use blake2s_simd::many::{HashManyJob, MAX_DEGREE as MAX_SIMD_DEGREE};
use std::cmp;
use std::error;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

/// Decode an entire slice in the default combined mode into a bytes vector.
/// This is a convenience wrapper around `Decoder`.
pub fn decode(encoded: impl AsRef<[u8]>, hash: &Hash) -> io::Result<Vec<u8>> {
    let bytes = encoded.as_ref();
    if bytes.len() < HEADER_SIZE {
        return Err(Error::Truncated.into());
    }
    let content_len = hash::decode_len(array_ref!(bytes, 0, HEADER_SIZE));
    // Sanity check the length before making a potentially large allocation.
    if (bytes.len() as u128) < encode::encoded_size(content_len) {
        return Err(Error::Truncated.into());
    }
    // There's no way to avoid zeroing this vector without unsafe code, because
    // Decoder::initializer is the default (safe) zeroing implementation anyway.
    let mut vec = vec![0; content_len as usize];
    let mut reader = Decoder::new(bytes, hash);
    reader.read_exact(&mut vec)?;
    // One more read to confirm EOF. This is redundant in most cases, but in
    // the empty encoding case read_exact won't do any reads at all, and the Ok
    // return from this call will be the only thing that verifies the hash.
    // Note that this will never hit the inner reader; we'll receive EOF from
    // the VerifyState.
    let n = reader.read(&mut [0])?;
    debug_assert_eq!(n, 0, "must be EOF");
    Ok(vec)
}

// This incremental verifier layers on top of encode::ParseState, and supports
// both the Decoder and the SliceDecoder.
#[derive(Clone)]
struct VerifyState {
    stack: ArrayVec<[Hash; MAX_DEPTH]>,
    parser: encode::ParseState,
    root_hash: Hash,
}

impl VerifyState {
    fn new(hash: &Hash) -> Self {
        let mut stack = ArrayVec::new();
        stack.push(*hash);
        Self {
            stack,
            parser: encode::ParseState::new(),
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
            self.stack.push(self.root_hash);
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

    fn feed_parent(&mut self, parent: &hash::ParentNode) -> Result<(), Error> {
        let finalization = self.parser.finalization();
        let expected_hash = self.stack.last().expect("unexpectedly empty stack");
        let computed_hash: Hash = parent_params(finalization).hash(parent).into();
        // Hash implements constant time equality.
        if expected_hash != &computed_hash {
            return Err(Error::HashMismatch);
        }
        let (&left_child, &right_child) = array_refs!(parent, HASH_SIZE, HASH_SIZE);
        self.stack.pop();
        self.stack.push(right_child.into());
        self.stack.push(left_child.into());
        self.parser.advance_parent();
        Ok(())
    }

    fn feed_chunk(&mut self, chunk_hash: &Hash) -> Result<(), Error> {
        let expected_hash = self.stack.last().expect("unexpectedly empty stack");
        // Hash implements constant time equality.
        if chunk_hash != expected_hash {
            return Err(Error::HashMismatch);
        }
        self.stack.pop();
        self.parser.advance_chunk();
        Ok(())
    }

    // Making a copy of the ParseState (which is small, since it doesn't
    // contain a subtree stack) allows the caller to read ahead and hash chunks
    // in batches with good SIMD performance. At the same time, this
    // VerifyState is untouched, and it cannot advance without correct input.
    fn clone_parser(&self) -> encode::ParseState {
        self.parser.clone()
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

/// Errors that can happen during decoding.
///
/// Two errors are possible when decoding, apart from the usual IO issues: the content bytes might
/// not have the right hash, or the encoding might not be as long as it's supposed to be. In
/// `std::io::Read` interfaces where we have to return `std::io::Error`, these variants are
/// converted to `ErrorKind::InvalidData` and `ErrorKind::UnexpectedEof` respectively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    HashMismatch,
    Truncated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HashMismatch => write!(f, "hash mismatch"),
            Error::Truncated => write!(f, "truncated encoding"),
        }
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::HashMismatch => io::Error::new(io::ErrorKind::InvalidData, "hash mismatch"),
            Error::Truncated => io::Error::new(io::ErrorKind::UnexpectedEof, "truncated encoding"),
        }
    }
}

// Shared between Decoder and SliceDecoder.
#[derive(Clone)]
struct DecoderShared<T: Read, O: Read> {
    input: T,
    outboard: Option<O>,
    state: VerifyState,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
}

fn read_exact_vectored(
    mut reader: impl Read,
    mut buf1: &mut [u8],
    mut buf2: &mut [u8],
) -> io::Result<()> {
    while !buf1.is_empty() {
        let bufs = &mut [io::IoSliceMut::new(buf1), io::IoSliceMut::new(buf2)];
        match reader.read_vectored(bufs) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => {
                if n < buf1.len() {
                    buf1 = &mut buf1[n..];
                } else {
                    buf2 = &mut buf2[n - buf1.len()..];
                    buf1 = &mut [];
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if !buf2.is_empty() {
        reader.read_exact(buf2)?;
    }
    Ok(())
}

// If the caller's buffer isn't big enough for a chunk, just use the whole
// thing, and we'll probably end up copying from our internal chunk buffer
// (unless what's coming up happens to be the the final short chunk). If the
// caller's buffer is bigger than MAX_SIMD_DEGREE chunks, just use
// MAX_SIMD_DEGREE chunks, since that's how many ArrayVec slots we'll allocate
// on the stack for HashManyJobs.
//
// In between we want to target the largest power of 2 number of chunks that
// fits in the caller's buffer. For example, if the caller's buffer is 5 chunks
// long, we want to read 4 chunks. That's because it's more efficient to hash 4
// chunks in parallel with SIMD than it is to hash 1. If the caller wants
// exactly those 5 chunks, they'll call read() again with a 1 chunk buffer, and
// we'll hash the 5th chunk by itself at that time. But if the caller keeps
// using the 5-chunk buffer, they'll get 4 chunks every time, and that'll be
// more efficient.
fn efficient_output_len(len: usize) -> usize {
    if len <= CHUNK_SIZE {
        len
    } else if len >= MAX_SIMD_DEGREE * CHUNK_SIZE {
        MAX_SIMD_DEGREE * CHUNK_SIZE
    } else {
        let num_chunks = len / CHUNK_SIZE;
        let power_of_2 = hash::largest_power_of_two_leq(num_chunks as u64) as usize;
        power_of_2 * CHUNK_SIZE
    }
}

impl<T: Read, O: Read> DecoderShared<T, O> {
    fn new(input: T, outboard: Option<O>, hash: &Hash) -> Self {
        Self {
            input,
            outboard,
            state: VerifyState::new(hash),
            buf: [0; CHUNK_SIZE],
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

    fn get_parent(&mut self) -> io::Result<hash::ParentNode> {
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

    fn buffer_verified_chunk(
        &mut self,
        size: usize,
        finalization: Finalization,
        skip: usize,
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
        let hash = chunk_params(finalization).hash(buf_slice).into();
        self.state.feed_chunk(&hash)?;
        self.buf_start = skip;
        self.buf_end = size;
        Ok(())
    }

    // A helper function for read() below. Reads a single chunk, along with
    // whatever number of parent nodes come before it. We read the parents all
    // at once, to avoid the cost of a syscall for every parent. We read
    // parents into the internal chunk buffer (which must be empty at this
    // point) to avoid the cost of zeroing a new stack buffer.
    fn read_ahead_unverified_one_chunk(
        &mut self,
        chunk_output: &mut [u8],
        parents_to_read: usize,
        parents_vec: &mut ArrayVec<[hash::ParentNode; hash::MAX_DEPTH + MAX_SIMD_DEGREE]>,
    ) -> io::Result<()> {
        debug_assert_eq!(self.buf_len(), 0);
        debug_assert!(hash::MAX_DEPTH <= self.buf.len() / PARENT_SIZE);
        debug_assert!(parents_to_read <= hash::MAX_DEPTH);
        let parents_slice = &mut self.buf[..parents_to_read * PARENT_SIZE];
        // Fill the parents_slice and the chunk_output. If we're in outboard
        // mode, we have to use two reads to do this, because we have two
        // streams. But if we're in combined mode, we can do it with a single
        // vectored read.
        if let Some(outboard) = &mut self.outboard {
            outboard.read_exact(parents_slice)?;
            self.input.read_exact(chunk_output)?;
        } else {
            read_exact_vectored(&mut self.input, parents_slice, chunk_output)?;
        }
        // Insert all the parents we just read into the parents_vec. Note that
        // the caller can't just read them straight out of the internal buffer,
        // because (in the very large input case) there might end up being more
        // parents than that buffer can hold. At the same time, we don't want
        // to pay the cost of zeroing a larger buffer, because usually there
        // are very few parents. Nor do we want to pay the cost of reading
        // everything into the caller's buffer and then memmove'ing chunks to
        // the front. Nor do we want to write unsafe code. The compromise here
        // is to pay the cost of copying however many parents we did read,
        // which is usually small.
        for parent in self.buf.chunks_exact(PARENT_SIZE).take(parents_to_read) {
            parents_vec.push(*array_ref!(parent, 0, PARENT_SIZE));
        }
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

        // Figure out how much of the caller's buffer we actually want to fill.
        // If the buffer is an uneven size, or larger than the MAX_SIMD_DEGREE
        // jobs we're allocating stack space for in the ArrayVecs below, then
        // we'll ignore the tail.
        let efficient_len = efficient_output_len(output.len());
        let mut remaining_output = &mut output[..efficient_len];

        // The main read loop. For each chunk, count the number of parents
        // we'll need to read without actually reading them. When we get to a
        // chunk, we'll read all the parents and the chunk together (with a
        // single vectorized read, if we're in combined mode). If the
        // remaining_output has enough space for the chunk, we'll read it
        // directly into the output, and possibly continue on to read more
        // chunks. If not, we'll read it into the internal chunk buffer
        // instead. However many chunks we read, hash them all in parallel in a
        // single batch.
        //
        // We coordinate all of this by making a copy of the VerifyState's
        // internal ParseState, which is small and cheap, and advancing the
        // copied parser to count parents. That lets us advance parsing past a
        // chunk before we've computed its hash, while the actual VerifyState
        // stays put and waits to receive all hashes in order as usual. That's
        // a pretty important property, because it means that any successful
        // reads will be contiguous, even if the caller retries errors.
        //
        // This parents_vec is large, possibly larger than the internal chunk
        // buffer. But it's mostly uninitialized, and it never moves.
        let mut chunk_bytes_read: usize = 0;
        let mut parents_to_read = 0;
        let mut parents_vec: ArrayVec<[hash::ParentNode; hash::MAX_DEPTH + MAX_SIMD_DEGREE]> =
            ArrayVec::new();
        let mut chunk_jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = ArrayVec::new();
        let mut parser = self.state.clone_parser();
        loop {
            match parser.read_next() {
                NextRead::Header => {
                    // If the header wasn't read before, read it now, and then
                    // re-clone the parser to get the post-header version.
                    self.get_and_feed_header()?;
                    parser = self.state.clone_parser();
                }
                NextRead::Parent => {
                    parents_to_read += 1;
                    parser.advance_parent();
                }
                NextRead::Chunk {
                    size,
                    finalization,
                    skip,
                } => {
                    // On the first chunk, we might find that we either we
                    // don't have enough output buffer space or that we need to
                    // skip partway through a chunk. In those cases, fall back
                    // to reading to the internal buffer.
                    if size > remaining_output.len() || skip > 0 {
                        debug_assert!(chunk_jobs.is_empty(), "first chunk");
                        self.buffer_verified_chunk(size, finalization, skip, parents_to_read)?;
                        return Ok(self.take_buffered_bytes(remaining_output));
                    }
                    // Otherwise this is the fast path. Try to read as many
                    // chunks as possible into the remaining output space
                    // (which, remember, may have been capped at the start for
                    // efficiency).
                    let chunk_params = hash::chunk_params(finalization);
                    let (chunk, remaining) = remaining_output.split_at_mut(size);
                    remaining_output = remaining;
                    self.read_ahead_unverified_one_chunk(chunk, parents_to_read, &mut parents_vec)?;
                    parents_to_read = 0;
                    chunk_bytes_read += size;
                    parser.advance_chunk();
                    chunk_jobs.push(HashManyJob::new(&chunk_params, chunk));
                    // If we've exhausted all the output buffer space, break
                    // this loop and move on to verification.
                    if remaining_output.is_empty() {
                        break;
                    }
                }
                // We will either exhaust the remaining_output above, or break
                // here at EOF.
                NextRead::Done => break,
            }
        }

        // Hash all the chunks we just read, if we didn't fall back to reading
        // to the internal buffer.
        blake2s_simd::many::hash_many(&mut chunk_jobs);

        // Feed each parent node and chunk hash into the VerifyState. Up until
        // this point the VerifyState wasn't modified, except maybe to hash the
        // header.
        let mut parents_iter = parents_vec.iter();
        for job in &chunk_jobs {
            while let NextRead::Parent = self.state.read_next() {
                let parent = parents_iter.next().expect("ran out of parents");
                self.state.feed_parent(parent)?;
            }
            self.state.feed_chunk(&job.to_hash().into())?;
        }
        debug_assert!(parents_iter.next().is_none(), "didn't use all parents");

        // All the state operations above passed, so the chunks in the caller's
        // buffer are good.
        Ok(chunk_bytes_read)
    }

    // Returns Ok(true) to indicate the seek is finished. Note that both the
    // Decoder and the SliceDecoder will use this method (which doesn't depend on
    // io::Seek), but only the Decoder will call handle_seek_bookkeeping first.
    // This may read a chunk, but it never leaves output bytes in the buffer,
    // because the only time seeking reads a chunk it also skips the entire
    // thing.
    fn handle_seek_read(&mut self, next: NextRead) -> io::Result<bool> {
        debug_assert_eq!(0, self.buf_len());
        match next {
            NextRead::Header => self.get_and_feed_header()?,
            NextRead::Parent => self.get_and_feed_parent()?,
            NextRead::Chunk {
                size,
                finalization,
                skip,
            } => {
                self.buffer_verified_chunk(size, finalization, skip, 0 /* parents_to_read */)?;
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
                let position_u64: u64 = encode::cast_offset(encoding_position)?;
                self.input.seek(SeekFrom::Start(position_u64))?;
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

/// An incremental decoder, which reads and verifies the output of `bao::encocde::Writer`. This can
/// work with both combined and outboard encodings, depending on which constructor you use.
///
/// This reader supports `Seek` if the underlying readers do, but it's not a requirement.
///
/// This implementation is single-threaded.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Create both combined and outboard encodings.
/// let input = b"some input";
/// let (encoded, hash) = bao::encode::encode(input);
/// let (outboard, _) = bao::encode::outboard(input);
///
/// // Decode the combined mode.
/// let mut combined_output = Vec::new();
/// {
///     let mut decoder = bao::decode::Decoder::new(&*encoded, &hash);
///     decoder.read_to_end(&mut combined_output)?;
/// }
///
/// // Decode the outboard mode.
/// let mut outboard_output = Vec::new();
/// {
///     let mut decoder = bao::decode::Decoder::new_outboard(&input[..], &*outboard, &hash);
///     decoder.read_to_end(&mut outboard_output)?;
/// }
///
/// assert_eq!(input, &*combined_output);
/// assert_eq!(input, &*outboard_output);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Decoder<T: Read, O: Read> {
    shared: DecoderShared<T, O>,
}

impl<T: Read> Decoder<T, T> {
    pub fn new(inner: T, hash: &Hash) -> Self {
        Self {
            shared: DecoderShared::new(inner, None, hash),
        }
    }
}

impl<T: Read, O: Read> Decoder<T, O> {
    pub fn new_outboard(inner: T, outboard: O, hash: &Hash) -> Self {
        Self {
            shared: DecoderShared::new(inner, Some(outboard), hash),
        }
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

/// An incremental slice decoder. This reads and verifies the output of the
/// `bao::encode::SliceExtractor`.
///
/// Note that there is no such thing as an "outboard slice". All slices include the content chunks
/// and intermediate hashes intermixed, as in the combined encoding mode.
///
/// This reader doesn't implement `Seek`, regardless of the underlying reader. In theory seeking
/// inside a slice is possible, but in practice if you only want part of a slice, you should
/// request a different slice with the parameters you actually want.
///
/// This implementation is single-threaded.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Start by encoding some input.
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = bao::encode::encode(&input);
///
/// // Slice the encoding. These parameters are multiples of the chunk size, which avoids
/// // unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 8192;
/// let encoded_cursor = std::io::Cursor::new(&encoded);
/// let mut extractor = bao::encode::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice)?;
///
/// // Decode the slice. The result should be the same as the part of the input that the slice
/// // represents. Note that we're using the same hash that encoding produced, which is
/// // independent of the slice parameters. That's the whole point; if we just wanted to re-encode
/// // a portion of the input and wind up with a different hash, we wouldn't need slicing.
/// let mut decoded = Vec::new();
/// let mut decoder = bao::decode::SliceDecoder::new(&*slice, &hash, slice_start, slice_len);
/// {
///     decoder.read_to_end(&mut decoded)?;
/// }
/// assert_eq!(&input[slice_start as usize..][..slice_len as usize], &*decoded);
///
/// // Like regular decoding, slice decoding will fail if the hash doesn't match.
/// let mut bad_slice = slice.clone();
/// let last_index = bad_slice.len() - 1;
/// bad_slice[last_index] ^= 1;
/// let mut decoder = bao::decode::SliceDecoder::new(&*bad_slice, &hash, slice_start, slice_len);
/// let err = decoder.read_to_end(&mut Vec::new()).unwrap_err();
/// assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
/// # Ok(())
/// # }
/// ```
pub struct SliceDecoder<T: Read> {
    shared: DecoderShared<T, T>,
    slice_start: u64,
    slice_remaining: u64,
}

impl<T: Read> SliceDecoder<T> {
    pub fn new(inner: T, hash: &Hash, slice_start: u64, slice_len: u64) -> Self {
        Self {
            shared: DecoderShared::new(inner, None, hash),
            slice_start,
            slice_remaining: slice_len,
        }
    }
}

impl<T: Read> Read for SliceDecoder<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // If we haven't done the initial seek yet, do the full seek loop
        // first. Note that this will never leave any buffered output. The only
        // scenario where handle_seek_read reads a chunk is if it needs to
        // validate the final chunk, and then it skips the whole thing.
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
        let cap = cmp::min(self.slice_remaining, output.len() as u64) as usize;
        let capped_output = &mut output[..cap];
        let n = self.shared.read(capped_output)?;
        self.slice_remaining -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) fn make_test_input(len: usize) -> Vec<u8> {
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
    use std::io;
    use std::io::prelude::*;
    use std::io::Cursor;

    use super::*;
    use crate::encode;
    use crate::hash;

    #[test]
    fn test_decode() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, hash) = { encode::encode(&input) };
            let output = decode(&encoded, &hash).unwrap();
            assert_eq!(input, output);
            assert_eq!(output.len(), output.capacity());
        }
    }

    #[test]
    fn test_decode_outboard() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (outboard, hash) = { encode::outboard(&input) };
            let mut output = Vec::new();
            let mut reader = Decoder::new_outboard(&input[..], &outboard[..], &hash);
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(input, output);
        }
    }

    #[test]
    fn test_decoders_corrupted() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, hash) = encode::encode(&input);
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

                let err = decode(&bad_encoded, &hash).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in hash::TEST_CASES {
            println!();
            println!("input_len {}", input_len);
            let input = make_test_input(input_len);
            let (encoded, hash) = encode::encode(&input);
            for &seek in hash::TEST_CASES {
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
        // A chunk number like this (37) with consecutive zeroes should exercise some of the more
        // interesting geometry cases.
        let input_len = 0b100101 * CHUNK_SIZE;
        println!("\n\ninput_len {}", input_len);
        let mut prng = ChaChaRng::from_seed([0; 32]);
        let input = make_test_input(input_len);
        let (encoded, hash) = encode::encode(&input);
        let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
        // Do a thousand random seeks and chunk-sized reads.
        for _ in 0..1000 {
            let seek = prng.gen_range(0, input_len + 1);
            println!("\nseek {}", seek);
            decoder
                .seek(SeekFrom::Start(seek as u64))
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

        let (zero_encoded, zero_hash) = encode::encode(b"");
        let one_hash = hash::hash(b"x");

        // Decoding the empty tree with the right hash should succeed.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &zero_hash);
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(&output, &[]);

        // Decoding the empty tree with any other hash should fail.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &one_hash);
        let result = decoder.read_to_end(&mut output);
        assert!(result.is_err(), "a bad hash is supposed to fail!");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_seeking_around_invalid_data() {
        for &case in hash::TEST_CASES {
            // Skip the cases with only one or two chunks, so we have valid
            // reads before and after the tweak.
            if case <= 2 * CHUNK_SIZE {
                continue;
            }

            println!("\ncase {}", case);
            let input = make_test_input(case);
            let (mut encoded, hash) = encode::encode(&input);
            println!("encoded len {}", encoded.len());

            // Tweak a bit at the start of a chunk about halfway through. Loop
            // over prior parent nodes and chunks to figure out where the
            // target chunk actually starts.
            let tweak_chunk = encode::count_chunks(case as u64) / 2;
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
            let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
            let mut output = vec![0; tweak_position as usize];
            decoder.read_exact(&mut output).unwrap();
            assert_eq!(&input[..tweak_position], &*output);

            // Further reads at this point should fail.
            let mut buf = [0; CHUNK_SIZE];
            let res = decoder.read(&mut buf);
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);

            // But now if we seek past the bad chunk, things should succeed again.
            let new_start = tweak_position + CHUNK_SIZE;
            decoder.seek(SeekFrom::Start(new_start as u64)).unwrap();
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(&input[new_start..], &*output);
        }
    }

    #[test]
    fn test_invalid_eof_seek() {
        // The decoder must validate the final chunk as part of seeking to or
        // past EOF.
        for &case in hash::TEST_CASES {
            let input = make_test_input(case);
            let (encoded, hash) = encode::encode(&input);

            // Seeking to EOF should succeed with the right hash.
            let mut output = Vec::new();
            let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
            decoder.seek(SeekFrom::Start(case as u64)).unwrap();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(&output, &[]);

            // Seeking to EOF should fail if the root hash is wrong.
            let mut bad_hash_bytes = *hash.as_bytes();
            bad_hash_bytes[0] ^= 1;
            let bad_hash = bad_hash_bytes.into();
            let mut decoder = Decoder::new(Cursor::new(&encoded), &bad_hash);
            let result = decoder.seek(SeekFrom::Start(case as u64));
            assert!(result.is_err(), "a bad hash is supposed to fail!");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);

            // It should also fail if the final chunk has been corrupted.
            if case > 0 {
                let mut bad_encoded = encoded.clone();
                *bad_encoded.last_mut().unwrap() ^= 1;
                let mut decoder = Decoder::new(Cursor::new(&bad_encoded), &hash);
                let result = decoder.seek(SeekFrom::Start(case as u64));
                assert!(result.is_err(), "a bad hash is supposed to fail!");
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn test_slices() {
        for &case in hash::TEST_CASES {
            let input = make_test_input(case);
            let (encoded, hash) = encode::encode(&input);
            // Also make an outboard encoding, to test that case.
            let (outboard, outboard_hash) = encode::outboard(&input);
            assert_eq!(hash, outboard_hash);
            for &slice_start in hash::TEST_CASES {
                let expected_start = cmp::min(input.len(), slice_start);
                let slice_lens = [0, 1, 2, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1];
                for &slice_len in slice_lens.iter() {
                    println!("\ncase {} start {} len {}", case, slice_start, slice_len);
                    let expected_end = cmp::min(input.len(), slice_start + slice_len);
                    let expected_output = &input[expected_start..expected_end];
                    let mut slice = Vec::new();
                    {
                        let mut extractor = encode::SliceExtractor::new(
                            Cursor::new(&encoded),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice).unwrap();
                    }
                    // Make sure the outboard extractor produces the same output.
                    {
                        let mut slice_from_outboard = Vec::new();
                        let mut extractor = encode::SliceExtractor::new_outboard(
                            Cursor::new(&input),
                            Cursor::new(&outboard),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice_from_outboard).unwrap();
                        assert_eq!(slice, slice_from_outboard);
                    }
                    let mut output = Vec::new();
                    let mut reader =
                        SliceDecoder::new(&*slice, &hash, slice_start as u64, slice_len as u64);
                    reader.read_to_end(&mut output).unwrap();
                    assert_eq!(expected_output, &*output);
                }
            }
        }
    }

    #[test]
    fn test_corrupted_slice() {
        let input = make_test_input(20_000);
        let slice_start = 5_000;
        let slice_len = 10_000;
        let (encoded, hash) = encode::encode(&input);

        // Slice out the middle 10_000 bytes;
        let mut slice = Vec::new();
        {
            let mut extractor = encode::SliceExtractor::new(
                Cursor::new(&encoded),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice).unwrap();
        }

        // First confirm that the regular decode works.
        let mut output = Vec::new();
        let mut reader = SliceDecoder::new(&*slice, &hash, slice_start as u64, slice_len as u64);
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(&input[slice_start..][..slice_len], &*output);

        // Also confirm that the outboard slice extractor gives the same slice.
        {
            let (outboard, outboard_hash) = encode::outboard(&input);
            assert_eq!(hash, outboard_hash);
            let mut slice_from_outboard = Vec::new();
            let mut extractor = encode::SliceExtractor::new_outboard(
                Cursor::new(&input),
                Cursor::new(&outboard),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice_from_outboard).unwrap();
            assert_eq!(slice, slice_from_outboard);
        }

        // Now confirm that flipping bits anywhere in the slice other than the
        // length header will corrupt it. Tweaking the length header doesn't
        // always break slice decoding, because the only thing its guaranteed
        // to break is the final chunk, and this slice doesn't include the
        // final chunk.
        let mut i = HEADER_SIZE;
        while i < slice.len() {
            let mut slice_clone = slice.clone();
            slice_clone[i] ^= 1;
            let mut reader =
                SliceDecoder::new(&*slice_clone, &hash, slice_start as u64, slice_len as u64);
            output.clear();
            let err = reader.read_to_end(&mut output).unwrap_err();
            assert_eq!(io::ErrorKind::InvalidData, err.kind());
            i += 32;
        }
    }

    #[test]
    fn test_slice_entire() {
        // If a slice starts at the beginning (actually anywere in the first chunk) and includes
        // entire length of the content (or at least one byte in the last chunk), the slice should
        // be exactly the same as the entire encoded tree. This can act as a cheap way to convert
        // an outboard tree to a combined one.
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (encoded, _) = encode::encode(&input);
            let (outboard, _) = encode::outboard(&input);
            let mut slice = Vec::new();
            {
                let mut extractor = encode::SliceExtractor::new_outboard(
                    Cursor::new(&input),
                    Cursor::new(&outboard),
                    0,
                    case as u64,
                );
                extractor.read_to_end(&mut slice).unwrap();
            }
            assert_eq!(encoded, slice);
        }
    }
}
