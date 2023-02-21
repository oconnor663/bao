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
//! let (encoded, hash) = abao::encode::encode(input);
//!
//! // Decode them with one of the all-at-once functions.
//! let decoded_at_once = abao::decode::decode(&encoded, &hash)?;
//!
//! // Also decode them incrementally.
//! let mut decoded_incrementally = Vec::new();
//! let mut decoder = abao::decode::Decoder::new(&*encoded, &hash);
//! decoder.read_to_end(&mut decoded_incrementally)?;
//!
//! // Assert that we got the same results both times.
//! assert_eq!(decoded_at_once, decoded_incrementally);
//!
//! // Flipping a bit in encoding will cause a decoding error.
//! let mut bad_encoded = encoded.clone();
//! let last_index = bad_encoded.len() - 1;
//! bad_encoded[last_index] ^= 1;
//! let err = abao::decode::decode(&bad_encoded, &hash).unwrap_err();
//! assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
//! # Ok(())
//! # }
//! ```

use crate::encode::NextRead;
use crate::{encode, ChunkGroupState};
use crate::{Finalization, Hash, GROUP_SIZE, HEADER_SIZE, MAX_DEPTH, PARENT_SIZE};
use arrayref::array_ref;
use arrayvec::ArrayVec;
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
    let content_len = crate::decode_len(array_ref!(bytes, 0, HEADER_SIZE));
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
    stack: ArrayVec<Hash, MAX_DEPTH>,
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

    fn feed_parent(&mut self, parent: &crate::ParentNode) -> Result<(), Error> {
        let finalization = self.parser.finalization();
        let expected_hash: &Hash = self.stack.last().expect("unexpectedly empty stack");
        let left_child: Hash = (*array_ref!(parent, 0, 32)).into();
        let right_child: Hash = (*array_ref!(parent, 32, 32)).into();
        let computed_hash: Hash =
            blake3::guts::parent_cv(&left_child, &right_child, finalization.is_root());
        // Hash implements constant time equality.
        if expected_hash != &computed_hash {
            return Err(Error::HashMismatch);
        }
        self.stack.pop();
        self.stack.push(right_child);
        self.stack.push(left_child);
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
    /// Hash does not match the expected hash.
    HashMismatch,
    /// Data was shorter than expected.
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
struct DecoderShared<T, O> {
    input: T,
    outboard: Option<O>,
    state: VerifyState,
    buf: [u8; GROUP_SIZE],
    buf_start: usize,
    buf_end: usize,
}

impl<T, O> DecoderShared<T, O> {
    fn new(input: T, outboard: Option<O>, hash: &Hash) -> Self {
        Self {
            input,
            outboard,
            state: VerifyState::new(hash),
            buf: [0; GROUP_SIZE],
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
}

impl<T: Read, O: Read> DecoderShared<T, O> {
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

    fn get_parent(&mut self) -> io::Result<crate::ParentNode> {
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
        index: u64,
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
        let hash = ChunkGroupState::new(index)
            .update(buf_slice)
            .finalize(finalization.is_root());
        self.state.feed_chunk(&hash)?;
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
                NextRead::Chunk {
                    size,
                    finalization,
                    skip,
                    index,
                } => {
                    debug_assert_eq!(self.buf_len(), 0);

                    // If we can, read the chunk directly into the `output`
                    // buffer, to avoid extra copies. If there's a verification
                    // error, the caller won't read the invalid bytes, because
                    // we won't return a length.
                    let (read_buf, direct_output) = if output.len() >= size && skip == 0 {
                        (&mut output[..size], true)
                    } else {
                        (&mut self.buf[..size], false)
                    };

                    // Read the unverified chunk.
                    self.input.read_exact(read_buf)?;

                    // Hash it and push its hash into the VerifyState. This
                    // returns an error if the hash is bad. Otherwise, the
                    // chunk is verifiied.
                    let chunk_hash = ChunkGroupState::new(index)
                        .update(read_buf)
                        .finalize(finalization.is_root());
                    self.state.feed_chunk(&chunk_hash)?;

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
                index,
            } => {
                self.buffer_verified_chunk(
                    size,
                    finalization,
                    skip,
                    index,
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
        } else if let Some(encoding_position) = bookkeeping.underlying_seek() {
            let position_u64: u64 = encode::cast_offset(encoding_position)?;
            self.input.seek(SeekFrom::Start(position_u64))?;
        }
        let next = self.state.seek_bookkeeping_done(bookkeeping);
        Ok(next)
    }
}

impl<T, O> fmt::Debug for DecoderShared<T, O> {
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

#[cfg(feature = "tokio_io")]
mod tokio_io {

    use crate::ChunkGroupState;

    use super::{DecoderShared, Hash, NextRead};
    use futures::{future, ready};
    use std::{
        cmp,
        convert::TryInto,
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, ReadBuf};

    // tokio flavour async io utilities, requiing AsyncRead
    impl<T: AsyncRead + Unpin, O: AsyncRead + Unpin> DecoderShared<T, O> {
        /// write from the internal buffer to the output buffer
        fn write_output(&mut self, buf: &mut ReadBuf<'_>) {
            let n = cmp::min(buf.remaining(), self.buf_len());
            buf.put_slice(&self.buf[self.buf_start..self.buf_start + n]);
            self.buf_start += n;
        }

        /// read just the header from the input or outboard, if needed
        fn poll_read_header(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
            if let NextRead::Header = self.state.read_next() {
                // read 8 bytes
                // header comes from outboard if we have one, otherwise from input
                ready!(self.poll_fill_buffer_from_input_or_outboard(8, cx))?;
                self.state.feed_header(self.buf[0..8].try_into().unwrap());
                // we don't want to write the header, so we are done with the buffer contents
                self.clear_buf();
            }
            Poll::Ready(Ok(()))
        }

        /// fills the internal buffer from the input or outboard
        ///
        /// will return Poll::Pending until we have a chunk in the internal buffer to be read,
        /// or we reach EOF
        fn poll_input(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
            loop {
                match self.state.read_next() {
                    NextRead::Done => {
                        // This is EOF.
                        break Poll::Ready(Ok(()));
                    }
                    NextRead::Header => {
                        // read 8 bytes
                        // header comes from outboard if we have one, otherwise from input
                        ready!(self.poll_fill_buffer_from_input_or_outboard(8, cx))?;
                        self.state.feed_header(self.buf[0..8].try_into().unwrap());
                        // we don't want to write the header, so we are done with the buffer contents
                        self.clear_buf();
                    }
                    NextRead::Parent => {
                        // read 64 bytes
                        // parent comes from outboard if we have one, otherwise from input
                        ready!(self.poll_fill_buffer_from_input_or_outboard(64, cx))?;
                        self.state
                            .feed_parent(&self.buf[0..64].try_into().unwrap())?;
                        // we don't want to write the parent, so we are done with the buffer contents
                        self.clear_buf();
                    }
                    NextRead::Chunk {
                        size,
                        finalization,
                        skip,
                        index,
                    } => {
                        // read size bytes
                        // chunk never comes from outboard
                        ready!(self.poll_fill_buffer_from_input(size, cx))?;

                        // Hash it and push its hash into the VerifyState. This
                        // returns an error if the hash is bad. Otherwise, the
                        // chunk is verified.
                        let read_buf = &self.buf[0..size];
                        let chunk_hash = ChunkGroupState::new(index)
                            .update(read_buf)
                            .finalize(finalization.is_root());
                        self.state.feed_chunk(&chunk_hash)?;

                        // we go into the writing state now, starting from skip
                        self.buf_start = skip;
                        // we should have something to write,
                        // unless the entire chunk was empty
                        debug_assert!(self.buf_len() > 0 || size == 0);

                        break Poll::Ready(Ok(()));
                    }
                }
            }
        }

        // Returns Ok(true) to indicate the seek is finished. Note that both the
        // Decoder and the SliceDecoder will use this method (which doesn't depend on
        // io::Seek), but only the Decoder will call handle_seek_bookkeeping first.
        // This may read a chunk, but it never leaves output bytes in the buffer,
        // because the only time seeking reads a chunk it also skips the entire
        // thing.
        fn poll_handle_seek_read(
            &mut self,
            next: NextRead,
            cx: &mut Context,
        ) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(match next {
                NextRead::Header => {
                    // read 8 bytes
                    // header comes from outboard if we have one, otherwise from input
                    ready!(self.poll_fill_buffer_from_input_or_outboard(8, cx))?;
                    self.state.feed_header(self.buf[0..8].try_into().unwrap());
                    // we don't want to write the header, so we are done with the buffer contents
                    self.clear_buf();
                    // not done yet
                    false
                }
                NextRead::Parent => {
                    // read 64 bytes
                    // parent comes from outboard if we have one, otherwise from input
                    ready!(self.poll_fill_buffer_from_input_or_outboard(64, cx))?;
                    self.state
                        .feed_parent(&self.buf[0..64].try_into().unwrap())?;
                    // we don't want to write the parent, so we are done with the buffer contents
                    self.clear_buf();
                    // not done yet
                    false
                }
                NextRead::Chunk {
                    size,
                    finalization,
                    skip: _,
                    index,
                } => {
                    // read size bytes
                    // chunk never comes from outboard
                    ready!(self.poll_fill_buffer_from_input(size, cx))?;

                    // Hash it and push its hash into the VerifyState. This
                    // returns an error if the hash is bad. Otherwise, the
                    // chunk is verified.
                    let read_buf = &self.buf[0..size];
                    let chunk_hash = ChunkGroupState::new(index)
                        .update(read_buf)
                        .finalize(finalization.is_root());
                    self.state.feed_chunk(&chunk_hash)?;
                    // we don't want to write the chunk, so we are done with the buffer contents
                    self.clear_buf();
                    false
                }
                NextRead::Done => true, // The seek is done.
            }))
        }

        fn poll_fill_buffer_from_input(
            &mut self,
            size: usize,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let mut buf = ReadBuf::new(&mut self.buf[..size]);
            buf.advance(self.buf_end);
            let src = &mut self.input;
            while buf.remaining() > 0 {
                ready!(AsyncRead::poll_read(Pin::new(src), cx, &mut buf))?;
                self.buf_end = buf.filled().len();
            }
            Poll::Ready(Ok(()))
        }

        fn poll_fill_buffer_from_outboard(
            &mut self,
            size: usize,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let mut buf = ReadBuf::new(&mut self.buf[..size]);
            buf.advance(self.buf_end);
            let src = self.outboard.as_mut().unwrap();
            while buf.remaining() > 0 {
                ready!(AsyncRead::poll_read(Pin::new(src), cx, &mut buf))?;
                self.buf_end = buf.filled().len();
            }
            Poll::Ready(Ok(()))
        }

        fn poll_fill_buffer_from_input_or_outboard(
            &mut self,
            size: usize,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            if self.outboard.is_some() {
                self.poll_fill_buffer_from_outboard(size, cx)
            } else {
                self.poll_fill_buffer_from_input(size, cx)
            }
        }
    }

    /// type alias to make clippy happy
    type BoxedDecoderShared<T, O> = Pin<Box<DecoderShared<T, O>>>;

    /// state of the decoder
    ///
    /// This is the decoder, but it is a separate type so it can be private.
    /// The public AsyncDecoder just wraps this.
    #[derive(Debug)]
    enum DecoderState<T: AsyncRead + Unpin, O: AsyncRead + Unpin> {
        /// we are reading from the underlying reader
        Reading(BoxedDecoderShared<T, O>),
        /// we are being polled for output
        Output(BoxedDecoderShared<T, O>),
        /// invalid state
        Invalid,
    }

    impl<T: AsyncRead + Unpin, O: AsyncRead + Unpin> DecoderState<T, O> {
        fn take(&mut self) -> Self {
            std::mem::replace(self, DecoderState::Invalid)
        }

        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // on a zero length read, we do nothing whatsoever
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            loop {
                match self.take() {
                    Self::Reading(mut shared) => {
                        let res = shared.poll_input(cx);
                        if let Poll::Ready(Ok(())) = res {
                            // we have read a chunk from the underlying reader
                            // go to output state
                            *self = Self::Output(shared);
                            continue;
                        }
                        *self = Self::Reading(shared);
                        break res;
                    }
                    Self::Output(mut shared) => {
                        shared.write_output(buf);
                        *self = if shared.buf_len() == 0 {
                            // the caller has consumed all the data in the buffer
                            // go to reading state
                            shared.clear_buf();
                            Self::Reading(shared)
                        } else {
                            // we still have data in the buffer
                            // stay in output state
                            Self::Output(shared)
                        };
                        break Poll::Ready(Ok(()));
                    }
                    DecoderState::Invalid => {
                        break Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }

    /// Async compatible version of [Decoder](super::Decoder).
    #[derive(Debug)]
    pub struct AsyncDecoder<T: AsyncRead + Unpin, O: AsyncRead + Unpin>(DecoderState<T, O>);

    impl<T: AsyncRead + Unpin> AsyncDecoder<T, T> {
        /// Create a new async decoder from an underlying async reader.
        pub fn new(inner: T, hash: &Hash) -> Self {
            let state = DecoderShared::new(inner, None, hash);
            Self(DecoderState::Reading(Box::pin(state)))
        }
    }

    impl<T: AsyncRead + Unpin, O: AsyncRead + Unpin> AsyncDecoder<T, O> {
        /// Create a new async decoder from an underlying async reader and an async outboard reader.
        pub fn new_outboard(inner: T, outboard: O, hash: &Hash) -> Self {
            let state = DecoderShared::new(inner, Some(outboard), hash);
            Self(DecoderState::Reading(Box::pin(state)))
        }
    }

    impl<T: AsyncRead + Unpin, O: AsyncRead + Unpin> AsyncRead for AsyncDecoder<T, O> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    #[derive(Clone, Debug)]
    struct SliceDecoderInner<T: AsyncRead + Unpin> {
        shared: DecoderShared<T, T>,
        slice_start: u64,
        slice_remaining: u64,
        // If the caller requested no bytes, the extractor is still required to
        // include a chunk. We're not required to verify it, but we want to
        // aggressively check for extractor bugs.
        need_fake_read: bool,
    }

    impl<T: AsyncRead + Unpin> SliceDecoderInner<T> {
        fn content_len(&self) -> Option<u64> {
            self.shared.state.parser.content_len()
        }

        fn poll_input(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // If we haven't done the initial seek yet, do the full seek loop
            // first. Note that this will never leave any buffered output. The only
            // scenario where handle_seek_read reads a chunk is if it needs to
            // validate the final chunk, and then it skips the whole thing.
            if self.shared.state.content_position() < self.slice_start {
                loop {
                    // we don't keep internal state but just call seek_next again if the
                    // call to poll_handle_seek_read below returns pending.
                    let bookkeeping = self.shared.state.seek_next(self.slice_start);
                    // Note here, we skip to seek_bookkeeping_done without
                    // calling handle_seek_bookkeeping. That is, we never
                    // perform any underlying seeks. The slice extractor
                    // already took care of lining everything up for us.
                    let next = self.shared.state.seek_bookkeeping_done(bookkeeping);
                    let done = ready!(self.shared.poll_handle_seek_read(next, cx))?;
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
                // Read one byte and throw it away, just to verify a chunk.
                ready!(self.shared.poll_input(cx))?;
                self.shared.clear_buf();
                self.need_fake_read = false;
            } else if self.slice_remaining > 0 {
                ready!(self.shared.poll_input(cx))?;
                let len = self.shared.buf_len() as u64;
                if len <= self.slice_remaining {
                    self.slice_remaining -= len;
                } else {
                    // We read more than we needed. Truncate the buffer.
                    self.shared.buf_end -= (len - self.slice_remaining) as usize;
                    self.slice_remaining = 0;
                }
            };
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Debug)]
    enum SliceDecoderState<T: AsyncRead + Unpin> {
        /// we are reading from the underlying reader
        Reading(Box<SliceDecoderInner<T>>),
        /// we are being polled for output
        Output(Box<SliceDecoderInner<T>>),
        /// value so we can implement take. If you see this, you've found a bug.
        Taken,
    }

    impl<T: AsyncRead + Unpin> SliceDecoderState<T> {
        fn take(&mut self) -> Self {
            std::mem::replace(self, SliceDecoderState::Taken)
        }
    }

    /// Async compatible version of [SliceDecoder](super::SliceDecoder).
    #[derive(Clone, Debug)]
    pub struct AsyncSliceDecoder<T: AsyncRead + Unpin>(SliceDecoderState<T>);

    impl<T: AsyncRead + Unpin> AsyncSliceDecoder<T> {
        /// Create a new async slice decoder from an underlying async reader, hash,
        /// and slice start and length.
        pub fn new(inner: T, hash: &Hash, slice_start: u64, slice_len: u64) -> Self {
            let state = SliceDecoderInner {
                shared: DecoderShared::new(inner, None, hash),
                slice_start,
                slice_remaining: slice_len,
                need_fake_read: slice_len == 0,
            };
            Self(SliceDecoderState::Reading(Box::new(state)))
        }

        /// Read the size of the content from the underlying reader.
        ///
        /// This is the total size of the content from which the slice was extracted,
        /// not the size of the slice.
        ///
        /// This will advance the inner reader or outboard reader by 8 bytes if
        /// we are at the start.
        pub async fn read_size(&mut self) -> io::Result<u64> {
            if let SliceDecoderState::Reading(state) = &mut self.0 {
                future::poll_fn(|cx| state.shared.poll_read_header(cx)).await?;
            }
            Ok(match &self.0 {
                SliceDecoderState::Reading(state) => state.content_len().unwrap(),
                SliceDecoderState::Output(state) => state.content_len().unwrap(),
                SliceDecoderState::Taken => unreachable!(),
            })
        }

        /// Get back the inner reader.
        ///
        /// When calling this after decoding is finished, the inner reader will
        /// be at the end of the encoded data.
        ///
        /// When calling this before decoding is finished, there are no guarantees
        /// about the exact position of the inner reader, so use seek to restore
        /// the position if needed.
        pub fn into_inner(self) -> T {
            match self.0 {
                SliceDecoderState::Reading(state) => state.shared.input,
                SliceDecoderState::Output(state) => state.shared.input,
                SliceDecoderState::Taken => unreachable!(),
            }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for AsyncSliceDecoder<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                match self.0.take() {
                    SliceDecoderState::Reading(mut state) => match state.poll_input(cx) {
                        Poll::Ready(Ok(())) => {
                            self.0 = SliceDecoderState::Output(state);
                            continue;
                        }
                        Poll::Ready(Err(e)) => {
                            self.0 = SliceDecoderState::Reading(state);
                            break Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            self.0 = SliceDecoderState::Reading(state);
                            break Poll::Pending;
                        }
                    },
                    SliceDecoderState::Output(mut state) => {
                        state.shared.write_output(buf);
                        if state.shared.buf_len() == 0 {
                            // the caller has consumed all the data in the buffer
                            // go to reading state
                            state.shared.clear_buf();
                            self.0 = SliceDecoderState::Reading(state)
                        } else {
                            // we still have data in the buffer
                            // stay in output state
                            self.0 = SliceDecoderState::Output(state)
                        };
                        break Poll::Ready(Ok(()));
                    }
                    SliceDecoderState::Taken => {
                        unreachable!();
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Cursor, Read};
        use tokio::io::AsyncReadExt;

        use super::*;
        use crate::{
            decode::{make_test_input, SliceDecoder},
            encode, GROUP_SIZE, HEADER_SIZE,
        };

        #[tokio::test]
        async fn test_async_decode() {
            for &case in crate::test::TEST_CASES {
                use tokio::io::AsyncReadExt;
                println!("case {case}");
                let input = make_test_input(case);
                let (encoded, hash) = { encode::encode(&input) };
                let mut output = Vec::new();
                let mut reader = AsyncDecoder::new(&encoded[..], &hash);
                reader.read_to_end(&mut output).await.unwrap();
                assert_eq!(input, output);
            }
        }

        #[tokio::test]
        async fn test_async_decode_outboard() {
            for &case in crate::test::TEST_CASES {
                use tokio::io::AsyncReadExt;
                println!("case {case}");
                let input = make_test_input(case);
                let (outboard, hash) = { encode::outboard(&input) };
                let mut output = Vec::new();
                let mut reader = AsyncDecoder::new_outboard(&input[..], &outboard[..], &hash);
                reader.read_to_end(&mut output).await.unwrap();
                assert_eq!(input, output);
            }
        }

        #[tokio::test]
        async fn test_async_slices() {
            for &case in crate::test::TEST_CASES {
                let input = make_test_input(case);
                let (encoded, hash) = encode::encode(&input);
                // Also make an outboard encoding, to test that case.
                let (outboard, outboard_hash) = encode::outboard(&input);
                assert_eq!(hash, outboard_hash);
                for &slice_start in crate::test::TEST_CASES {
                    let expected_start = cmp::min(input.len(), slice_start);
                    let slice_lens = [0, 1, 2, GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE + 1];
                    // let slice_lens = [GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE + 1];
                    for &slice_len in slice_lens.iter() {
                        println!("\ncase {case} start {slice_start} len {slice_len}");
                        let expected_end = cmp::min(input.len(), slice_start + slice_len);
                        let expected_output = &input[expected_start..expected_end];
                        let mut slice = Vec::new();
                        let mut extractor = encode::SliceExtractor::new(
                            Cursor::new(&encoded),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice).unwrap();

                        // Make sure the outboard extractor produces the same output.
                        let mut slice_from_outboard = Vec::new();
                        let mut extractor = encode::SliceExtractor::new_outboard(
                            Cursor::new(&input),
                            Cursor::new(&outboard),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice_from_outboard).unwrap();
                        assert_eq!(slice, slice_from_outboard);

                        let mut output = Vec::new();
                        let mut reader = AsyncSliceDecoder::new(
                            &*slice,
                            &hash,
                            slice_start as u64,
                            slice_len as u64,
                        );
                        reader.read_to_end(&mut output).await.unwrap();
                        assert_eq!(expected_output, &*output);
                    }
                }
            }
        }

        #[tokio::test]
        async fn test_async_corrupted_slice() {
            let input = make_test_input(20_000);
            let slice_start = 5_000;
            let slice_len = 10_000;
            let (encoded, hash) = encode::encode(&input);

            // Slice out the middle 10_000 bytes;
            let mut slice = Vec::new();
            let mut extractor = encode::SliceExtractor::new(
                Cursor::new(&encoded),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice).unwrap();

            // First confirm that the regular decode works.
            let mut output = Vec::new();
            let mut reader =
                SliceDecoder::new(&*slice, &hash, slice_start as u64, slice_len as u64);
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(&input[slice_start..][..slice_len], &*output);

            // Also confirm that the outboard slice extractor gives the same slice.
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

            // Now confirm that flipping bits anywhere in the slice other than the
            // length header will corrupt it. Tweaking the length header doesn't
            // always break slice decoding, because the only thing its guaranteed
            // to break is the final chunk, and this slice doesn't include the
            // final chunk.
            let mut i = HEADER_SIZE;
            while i < slice.len() {
                let mut slice_clone = slice.clone();
                slice_clone[i] ^= 1;
                let mut reader = AsyncSliceDecoder::new(
                    &*slice_clone,
                    &hash,
                    slice_start as u64,
                    slice_len as u64,
                );
                output.clear();
                let err = reader.read_to_end(&mut output).await.unwrap_err();
                assert_eq!(io::ErrorKind::InvalidData, err.kind());
                i += 32;
            }
        }
    }
}

#[cfg(feature = "tokio_io")]
pub use tokio_io::{AsyncDecoder, AsyncSliceDecoder};

/// An incremental decoder, which reads and verifies the output of
/// [`Encoder`](../encode/struct.Encoder.html).
///
/// `Decoder` supports both the combined and outboard encoding format,
/// depending on which constructor you use.
///
/// `Decoder` supports
/// [`std::io::Seek`](https://doc.rust-lang.org/std/io/trait.Seek.html) if the
/// underlying reader does, but it's also compatible with non-seekable readers.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Create both combined and outboard encodings.
/// let input = b"some input";
/// let (encoded, hash) = abao::encode::encode(input);
/// let (outboard, _) = abao::encode::outboard(input);
///
/// // Decode the combined mode.
/// let mut combined_output = Vec::new();
/// let mut decoder = abao::decode::Decoder::new(&*encoded, &hash);
/// decoder.read_to_end(&mut combined_output)?;
///
/// // Decode the outboard mode.
/// let mut outboard_output = Vec::new();
/// let mut decoder = abao::decode::Decoder::new_outboard(&input[..], &*outboard, &hash);
/// decoder.read_to_end(&mut outboard_output)?;
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
    /// Create a new `Decoder` that reads encoded data from `inner` and verifies
    /// the hash incrementally while reading.
    pub fn new(inner: T, hash: &Hash) -> Self {
        Self {
            shared: DecoderShared::new(inner, None, hash),
        }
    }
}

impl<T: Read, O: Read> Decoder<T, O> {
    /// Create a new `Decoder` that reads data form `inner` and outboard data
    /// from `outboard` and verifies the hash incrementally while reading.
    pub fn new_outboard(inner: T, outboard: O, hash: &Hash) -> Self {
        Self {
            shared: DecoderShared::new(inner, Some(outboard), hash),
        }
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

/// An incremental slice decoder. This reads and verifies the output of the
/// [`SliceExtractor`](../encode/struct.SliceExtractor.html).
///
/// Note that there is no such thing as an "outboard slice". All slices include
/// the content bytes and tree nodes intermixed, as in the combined encoding
/// mode.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Start by encoding some input.
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = abao::encode::encode(&input);
///
/// // Slice the encoding. These parameters are multiples of the chunk size, which avoids
/// // unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 8192;
/// let encoded_cursor = std::io::Cursor::new(&encoded);
/// let mut extractor = abao::encode::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice)?;
///
/// // Decode the slice. The result should be the same as the part of the input that the slice
/// // represents. Note that we're using the same hash that encoding produced, which is
/// // independent of the slice parameters. That's the whole point; if we just wanted to re-encode
/// // a portion of the input and wind up with a different hash, we wouldn't need slicing.
/// let mut decoded = Vec::new();
/// let mut decoder = abao::decode::SliceDecoder::new(&*slice, &hash, slice_start, slice_len);
/// decoder.read_to_end(&mut decoded)?;
/// assert_eq!(&input[slice_start as usize..][..slice_len as usize], &*decoded);
///
/// // Like regular decoding, slice decoding will fail if the hash doesn't match.
/// let mut bad_slice = slice.clone();
/// let last_index = bad_slice.len() - 1;
/// bad_slice[last_index] ^= 1;
/// let mut decoder = abao::decode::SliceDecoder::new(&*bad_slice, &hash, slice_start, slice_len);
/// let err = decoder.read_to_end(&mut Vec::new()).unwrap_err();
/// assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SliceDecoder<T: Read> {
    shared: DecoderShared<T, T>,
    slice_start: u64,
    slice_remaining: u64,
    // If the caller requested no bytes, the extractor is still required to
    // include a chunk. We're not required to verify it, but we want to
    // aggressively check for extractor bugs.
    need_fake_read: bool,
}

impl<T: Read> SliceDecoder<T> {
    /// Create a new slice decoder that reads an encoded slice from `inner`.
    ///
    /// The `hash` parameter is the hash of the entire input, not just the slice.
    /// The `slice_start` and `slice_len` parameters are range of the slice within
    /// the input.
    ///
    /// If the range is larger than the available input, it will be truncated.
    /// So to read an entire encoded stream you can just set `slice_start` to 0
    /// and `slice_len` to `u64::max_value()`.
    pub fn new(inner: T, hash: &Hash, slice_start: u64, slice_len: u64) -> Self {
        Self {
            shared: DecoderShared::new(inner, None, hash),
            slice_start,
            slice_remaining: slice_len,
            need_fake_read: slice_len == 0,
        }
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
        if self.need_fake_read {
            // Read one byte and throw it away, just to verify a chunk.
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
            ret.extend_from_slice(&counter.to_be_bytes());
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

    #[test]
    fn test_decode() {
        for &case in crate::test::TEST_CASES {
            println!("case {case}");
            let input = make_test_input(case);
            let (encoded, hash) = { encode::encode(&input) };
            let output = decode(&encoded, &hash).unwrap();
            assert_eq!(input, output);
            assert_eq!(output.len(), output.capacity());
        }
    }

    #[test]
    fn test_decode_outboard() {
        for &case in crate::test::TEST_CASES {
            println!("case {case}");
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
        for &case in crate::test::TEST_CASES {
            println!("case {case}");
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
            if encoded.len() > GROUP_SIZE {
                tweaks.push(GROUP_SIZE);
            }
            for tweak in tweaks {
                println!("tweak {tweak}");
                let mut bad_encoded = encoded.clone();
                bad_encoded[tweak] ^= 1;

                let err = decode(&bad_encoded, &hash).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in crate::test::TEST_CASES {
            println!();
            println!("input_len {input_len}");
            let input = make_test_input(input_len);
            let (encoded, hash) = encode::encode(&input);
            for &seek in crate::test::TEST_CASES {
                println!("seek {seek}");
                // Test all three types of seeking.
                let mut seek_froms = Vec::new();
                seek_froms.push(SeekFrom::Start(seek as u64));
                seek_froms.push(SeekFrom::End(seek as i64 - input_len as i64));
                seek_froms.push(SeekFrom::Current(seek as i64));
                for seek_from in seek_froms {
                    println!("seek_from {seek_from:?}");
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
        let input_len = 0b100101 * GROUP_SIZE;
        println!("\n\ninput_len {input_len}");
        let mut prng = ChaChaRng::from_seed([0; 32]);
        let input = make_test_input(input_len);
        let (encoded, hash) = encode::encode(&input);
        let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
        // Do a thousand random seeks and chunk-sized reads.
        for _ in 0..1000 {
            let seek = prng.gen_range(0..input_len + 1);
            println!("\nseek {seek}");
            decoder
                .seek(SeekFrom::Start(seek as u64))
                .expect("seek error");
            // Clone the encoder before reading, to test repeated seeks on the same encoder.
            let mut output = Vec::new();
            decoder
                .clone()
                .take(GROUP_SIZE as u64)
                .read_to_end(&mut output)
                .expect("decoder error");
            let input_start = cmp::min(seek, input_len);
            let input_end = cmp::min(input_start + GROUP_SIZE, input_len);
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
        let one_hash = blake3::hash(b"x");

        // Decoding the empty tree with the right hash should succeed.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &zero_hash);
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(output.len(), 0);

        // Decoding the empty tree with any other hash should fail.
        let mut output = Vec::new();
        let mut decoder = Decoder::new(&*zero_encoded, &one_hash);
        let result = decoder.read_to_end(&mut output);
        assert!(result.is_err(), "a bad hash is supposed to fail!");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_seeking_around_invalid_data() {
        for &case in crate::test::TEST_CASES {
            // Skip the cases with only one or two chunks, so we have valid
            // reads before and after the tweak.
            if case <= 2 * GROUP_SIZE {
                continue;
            }

            println!("\ncase {case}");
            let input = make_test_input(case);
            let (mut encoded, hash) = encode::encode(&input);
            println!("encoded len {}", encoded.len());

            // Tweak a bit at the start of a chunk about halfway through. Loop
            // over prior parent nodes and chunks to figure out where the
            // target chunk actually starts.
            let tweak_chunk = encode::count_chunks(case as u64) / 2;
            let tweak_position = tweak_chunk as usize * GROUP_SIZE;
            println!("tweak position {tweak_position}");
            let mut tweak_encoded_offset = HEADER_SIZE;
            for chunk in 0..tweak_chunk {
                tweak_encoded_offset +=
                    encode::pre_order_parent_nodes(chunk, case as u64) as usize * PARENT_SIZE;
                tweak_encoded_offset += GROUP_SIZE;
            }
            tweak_encoded_offset +=
                encode::pre_order_parent_nodes(tweak_chunk, case as u64) as usize * PARENT_SIZE;
            println!("tweak encoded offset {tweak_encoded_offset}");
            encoded[tweak_encoded_offset] ^= 1;

            // Read all the bits up to that tweak. Because it's right after a chunk boundary, the
            // read should succeed.
            let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
            let mut output = vec![0; tweak_position];
            decoder.read_exact(&mut output).unwrap();
            assert_eq!(&input[..tweak_position], &*output);

            // Further reads at this point should fail.
            let mut buf = [0; GROUP_SIZE];
            let res = decoder.read(&mut buf);
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);

            // But now if we seek past the bad chunk, things should succeed again.
            let new_start = tweak_position + GROUP_SIZE;
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
        for &case in crate::test::TEST_CASES {
            let input = make_test_input(case);
            let (encoded, hash) = encode::encode(&input);

            // Seeking to EOF should succeed with the right hash.
            let mut output = Vec::new();
            let mut decoder = Decoder::new(Cursor::new(&encoded), &hash);
            decoder.seek(SeekFrom::Start(case as u64)).unwrap();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(output.len(), 0);

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
        for &case in crate::test::TEST_CASES {
            let input = make_test_input(case);
            let (encoded, hash) = encode::encode(&input);
            // Also make an outboard encoding, to test that case.
            let (outboard, outboard_hash) = encode::outboard(&input);
            assert_eq!(hash, outboard_hash);
            for &slice_start in crate::test::TEST_CASES {
                let expected_start = cmp::min(input.len(), slice_start);
                let slice_lens = [0, 1, 2, GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE + 1];
                for &slice_len in slice_lens.iter() {
                    println!("\ncase {case} start {slice_start} len {slice_len}");
                    let expected_end = cmp::min(input.len(), slice_start + slice_len);
                    let expected_output = &input[expected_start..expected_end];
                    let mut slice = Vec::new();
                    let mut extractor = encode::SliceExtractor::new(
                        Cursor::new(&encoded),
                        slice_start as u64,
                        slice_len as u64,
                    );
                    extractor.read_to_end(&mut slice).unwrap();

                    // Make sure the outboard extractor produces the same output.
                    let mut slice_from_outboard = Vec::new();
                    let mut extractor = encode::SliceExtractor::new_outboard(
                        Cursor::new(&input),
                        Cursor::new(&outboard),
                        slice_start as u64,
                        slice_len as u64,
                    );
                    extractor.read_to_end(&mut slice_from_outboard).unwrap();
                    assert_eq!(slice, slice_from_outboard);

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
        let mut extractor = encode::SliceExtractor::new(
            Cursor::new(&encoded),
            slice_start as u64,
            slice_len as u64,
        );
        extractor.read_to_end(&mut slice).unwrap();

        // First confirm that the regular decode works.
        let mut output = Vec::new();
        let mut reader = SliceDecoder::new(&*slice, &hash, slice_start as u64, slice_len as u64);
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(&input[slice_start..][..slice_len], &*output);

        // Also confirm that the outboard slice extractor gives the same slice.
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
        for &case in crate::test::TEST_CASES {
            println!("case {case}");
            let input = make_test_input(case);
            let (encoded, _) = encode::encode(&input);
            let (outboard, _) = encode::outboard(&input);
            let mut slice = Vec::new();
            let mut extractor = encode::SliceExtractor::new_outboard(
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
