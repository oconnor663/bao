use crate::encode::{
    cast_offset, encoded_size, outboard_size, FlipperNext, FlipperState, NextRead, ParseState,
    State, StateFinish,
};
use crate::{Hash, CHUNK_SIZE, HEADER_SIZE, PARENT_SIZE};
use arrayref::array_mut_ref;
use bytes::BytesMut;
use futures::io;
use futures::io::SeekFrom;
use futures::prelude::*;
use std::cmp;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Encode an entire slice into a bytes vector in the default combined mode.
/// This is a convenience wrapper around `Encoder::write_all`.
pub async fn encode(input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
    let bytes = input.as_ref();
    let mut vec = Vec::with_capacity(encoded_size(bytes.len() as u64) as usize);
    let mut encoder = Encoder::new(io::Cursor::new(&mut vec));
    encoder.write_all(bytes).await.unwrap();
    let hash = encoder.finalize().await.unwrap();
    (vec, hash)
}

/// Encode an entire slice into a bytes vector in the outboard mode. This is a
/// convenience wrapper around `Encoder::new_outboard` and `Encoder::write_all`.
pub async fn outboard(input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
    let bytes = input.as_ref();
    let mut vec = Vec::with_capacity(outboard_size(bytes.len() as u64) as usize);
    let mut encoder = Encoder::new_outboard(io::Cursor::new(&mut vec));
    encoder.write_all(bytes).await.unwrap();
    let hash = encoder.finalize().await.unwrap();
    (vec, hash)
}

/// An incremental encoder. Note that you must call `finalize` after you're
/// done writing.
///
/// `Encoder` supports both combined and outboard encoding, depending on which
/// constructor you use.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # futures::executor::block_on(async move {
/// use futures::prelude::*;
///
/// let mut encoded_incrementally = Vec::new();
/// let encoded_cursor = futures::io::Cursor::new(&mut encoded_incrementally);
/// let mut encoder = bao::encode_fut::Encoder::new(encoded_cursor);
/// encoder.write_all(b"some input").await?;
/// encoder.finalize().await?;
/// # Ok(())
/// # })
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Encoder<T: AsyncRead + AsyncWrite + AsyncSeek> {
    inner: T,
    chunk_state: blake3::guts::ChunkState,
    tree_state: State,
    outboard: bool,
    finalized: bool,
    write_buffer: BytesMut,
}

impl<T: AsyncRead + AsyncWrite + AsyncSeek + Unpin> Encoder<T> {
    /// Create a new `Encoder` that will produce a combined encoding.The encoding will contain all
    /// the input bytes, so that it can be decoded without the original input file. This is what
    /// you get from `bao encode`.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chunk_state: blake3::guts::ChunkState::new(0),
            tree_state: State::new(),
            outboard: false,
            finalized: false,
            write_buffer: BytesMut::with_capacity(64),
        }
    }

    /// Create a new `Encoder` for making an outboard encoding. That means that the encoding won't
    /// include any input bytes. Instead, the input will need to be supplied as a separate argument
    /// when the outboard encoding is later decoded. This is what you get from `bao encode
    /// --outboard`.
    pub fn new_outboard(inner: T) -> Self {
        let mut encoder = Self::new(inner);
        encoder.outboard = true;
        encoder
    }

    /// Finalize the encoding, after all the input has been written. You can't keep using this
    /// `Encoder` again after calling `finalize`, and writing or finalizing again will panic.
    ///
    /// The underlying strategy of the `Encoder` is to first store the tree in a post-order layout,
    /// and then to go back and flip the entire thing into pre-order. That makes it possible to
    /// stream input without knowing its length in advance, which is a core requirement of the
    /// `futures::io::AsyncWrite` interface. The downside is that `finalize` is a relatively expensive step.
    pub async fn finalize(&mut self) -> io::Result<Hash> {
        assert!(!self.finalized, "already finalized");
        self.finalized = true;

        // Compute the total len before we merge the final chunk into the
        // tree_state.
        let total_len = self
            .tree_state
            .count()
            .checked_add(self.chunk_state.len() as u64)
            .expect("addition overflowed");

        // Finalize the last chunk. Note that any partial chunk bytes retained in the chunk_state
        // have already been written to the underlying writer by .write().
        debug_assert!(self.chunk_state.len() > 0 || self.tree_state.count() == 0);
        let last_chunk_is_root = self.tree_state.count() == 0;
        let last_chunk_hash = self.chunk_state.finalize(last_chunk_is_root);
        self.tree_state
            .push_subtree(&last_chunk_hash, self.chunk_state.len());

        // Merge and write all the parents along the right edge.
        let root_hash;
        loop {
            match self.tree_state.merge_finalize() {
                StateFinish::Parent(parent) => self.inner.write_all(&parent).await?,
                StateFinish::Root(root) => {
                    root_hash = root;
                    break;
                }
            }
        }

        // Write the length header, at the end.
        self.inner.write_all(&crate::encode_len(total_len)).await?;

        // Finally, flip the tree to be pre-order. This means rewriting the
        // entire output, so it's expensive.
        self.flip_post_order_stream().await?;

        Ok(root_hash)
    }

    /// Return the underlying writer.
    pub fn into_inner(self) -> T {
        self.inner
    }

    async fn flip_post_order_stream(&mut self) -> io::Result<()> {
        let mut write_cursor = self.inner.seek(SeekFrom::End(0)).await?;
        let mut read_cursor = write_cursor - HEADER_SIZE as u64;
        let mut header = [0; HEADER_SIZE];
        self.inner.seek(SeekFrom::Start(read_cursor)).await?;
        self.inner.read_exact(&mut header).await?;
        let content_len = crate::decode_len(&header);
        let mut flipper = FlipperState::new(content_len);
        loop {
            match flipper.next() {
                FlipperNext::FeedParent => {
                    let mut parent = [0; PARENT_SIZE];
                    self.inner
                        .seek(SeekFrom::Start(read_cursor - PARENT_SIZE as u64))
                        .await?;
                    self.inner.read_exact(&mut parent).await?;
                    read_cursor -= PARENT_SIZE as u64;
                    flipper.feed_parent(parent);
                }
                FlipperNext::TakeParent => {
                    let parent = flipper.take_parent();
                    self.inner
                        .seek(SeekFrom::Start(write_cursor - PARENT_SIZE as u64))
                        .await?;
                    self.inner.write_all(&parent).await?;
                    write_cursor -= PARENT_SIZE as u64;
                }
                FlipperNext::Chunk(size) => {
                    // In outboard moded, we skip over chunks.
                    if !self.outboard {
                        let mut chunk = [0; CHUNK_SIZE];
                        self.inner
                            .seek(SeekFrom::Start(read_cursor - size as u64))
                            .await?;
                        self.inner.read_exact(&mut chunk[..size]).await?;
                        read_cursor -= size as u64;
                        self.inner
                            .seek(SeekFrom::Start(write_cursor - size as u64))
                            .await?;
                        self.inner.write_all(&chunk[..size]).await?;
                        write_cursor -= size as u64;
                    }
                    flipper.chunk_moved();
                }
                FlipperNext::Done => {
                    debug_assert_eq!(HEADER_SIZE as u64, write_cursor);
                    self.inner.seek(SeekFrom::Start(0)).await?;
                    self.inner.write_all(&header).await?;
                    return Ok(());
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + AsyncSeek + Unpin> AsyncWrite for Encoder<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(!self.finalized, "already finalized");

        let Self {
            write_buffer,
            ref mut inner,
            chunk_state,
            tree_state,
            outboard,
            ..
        } = &mut *self;

        // Write out anything we still have in the buffer.
        while !write_buffer.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, &write_buffer[..]) {
                Poll::Ready(Ok(written)) => {
                    let _ = write_buffer.split_to(written);
                }
                other => return other,
            }
        }

        // Short-circuit if the input is empty.
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If the current chunk is full, we need to finalize it, add it to
        // the tree state, and write out any completed parent nodes.
        if chunk_state.len() == CHUNK_SIZE {
            // This can't be the root, because we know more input is coming.
            let chunk_hash = chunk_state.finalize(false);
            tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            let chunk_counter = tree_state.count() / CHUNK_SIZE as u64;
            *chunk_state = blake3::guts::ChunkState::new(chunk_counter);
            while let Some(parent) = tree_state.merge_parent() {
                match Pin::new(&mut *inner).poll_write(cx, &parent) {
                    Poll::Ready(Ok(written)) => {
                        if written != parent.len() {
                            // need to buffer the rest of the data
                            write_buffer.extend_from_slice(&parent[written..]);
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // store into write buffer
                        write_buffer.extend_from_slice(&parent);
                    }
                }
            }
        }

        // Add as many bytes as possible to the current chunk.
        let want = CHUNK_SIZE - chunk_state.len();
        let take = cmp::min(want, input.len());
        if !*outboard {
            if write_buffer.is_empty() {
                // attempt to write
                match Pin::new(inner).poll_write(cx, &input[..take]) {
                    Poll::Ready(Ok(written)) => {
                        if written != take {
                            write_buffer.extend_from_slice(&input[written..take]);
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                // only extend, we have already tried to write above and couldn't finish
                write_buffer.extend_from_slice(&input[..take]);
            }
        }
        chunk_state.update(&input[..take]);

        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            write_buffer,
            ref mut inner,
            ..
        } = &mut *self;

        // Need to write out anything we still have in the buffer
        while !write_buffer.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, &write_buffer[..]) {
                Poll::Ready(Ok(written)) => {
                    let _ = write_buffer.split_to(written);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// An incremental slice extractor, which reads encoded bytes and produces a slice.
///
/// `SliceExtractor` supports reading both the combined and outboard encoding, depending on which
/// constructor you use. Though to be clear, there's no such thing as an "outboard slice" per se.
/// Slices always include subtree hashes inline with the content, as a combined encoding does.
///
/// Note that slices always split the encoding at chunk boundaries. The BLAKE3 chunk size is 1024
/// bytes, so using `slice_start` and `slice_len` values that are an even multiple of 1024 avoids
/// wasting space.
///
/// Extracting a slice doesn't re-hash any of the bytes. As a result, it's fast compared to
/// decoding. You can quickly convert an outboard encoding to a combined encoding by "extracting" a
/// slice with a `slice_start` of zero and a `slice_len` equal to the original input length.
///
/// See the `decode` module for decoding slices.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # futures::executor::block_on(async move {
/// use futures::prelude::*;
///
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = bao::encode_fut::encode(&input).await;
/// // These parameters are multiples of the chunk size, which avoids unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 8192;
/// let encoded_cursor = futures::io::Cursor::new(&encoded);
/// let mut extractor = bao::encode_fut::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice).await?;
///
/// // The slice includes some overhead to store the necessary subtree hashes.
/// assert_eq!(9096, slice.len());
/// # Ok(())
/// # })
/// # }
/// ```
pub struct SliceExtractor<T: AsyncRead + AsyncSeek + Unpin, O: AsyncRead + AsyncSeek> {
    input: T,
    outboard: Option<O>,
    slice_start: u64,
    slice_len: u64,
    slice_bytes_read: u64,
    parser: ParseState,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
    seek_done: bool,
}

impl<T: AsyncRead + AsyncSeek + Unpin> SliceExtractor<T, T> {
    /// Create a new `SliceExtractor` to read from a combined encoding. Note that `slice_start` and
    /// `slice_len` are with respect to the *content* of the encoding, that is, the *original*
    /// input bytes. This corresponds to `bao slice slice_start slice_len`.
    pub fn new(input: T, slice_start: u64, slice_len: u64) -> Self {
        Self::new_inner(input, None, slice_start, slice_len)
    }
}

impl<T: AsyncRead + AsyncSeek + Unpin, O: AsyncRead + AsyncSeek + Unpin> SliceExtractor<T, O> {
    /// Create a new `SliceExtractor` to read from an unmodified input file and an outboard
    /// encoding of that same file (see `Encoder::new_outboard`). As with `SliceExtractor::new`,
    /// `slice_start` and `slice_len` are with respect to the *content* of the encoding, that is,
    /// the *original* input bytes. This corresponds to `bao slice slice_start slice_len
    /// --outboard`.
    pub fn new_outboard(input: T, outboard: O, slice_start: u64, slice_len: u64) -> Self {
        Self::new_inner(input, Some(outboard), slice_start, slice_len)
    }

    /// Return the underlying readers. The second reader is `Some` if and only if this
    /// `SliceExtractor` was created with `new_outboard`.
    pub fn into_inner(self) -> (T, Option<O>) {
        (self.input, self.outboard)
    }

    fn new_inner(input: T, outboard: Option<O>, slice_start: u64, slice_len: u64) -> Self {
        Self {
            input,
            outboard,
            slice_start,
            // Always try to include at least one byte.
            slice_len: cmp::max(slice_len, 1),
            slice_bytes_read: 0,
            parser: ParseState::new(),
            buf: [0; CHUNK_SIZE],
            buf_start: 0,
            buf_end: 0,
            seek_done: false,
        }
    }

    fn buf_len(&self) -> usize {
        self.buf_end - self.buf_start
    }

    // Note that unlike the regular Reader, the header bytes go into the output buffer.
    fn read_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let header = array_mut_ref!(self.buf, 0, HEADER_SIZE);
        {
            let mut total_read = 0;
            while total_read < HEADER_SIZE {
                let res = if let Some(outboard) = &mut self.outboard {
                    Pin::new(&mut *outboard).poll_read(cx, &mut header[total_read..])
                } else {
                    Pin::new(&mut self.input).poll_read(cx, &mut header[total_read..])
                };

                match res {
                    Poll::Ready(Ok(read)) => {
                        total_read += read;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        self.buf_start = 0;
        self.buf_end = HEADER_SIZE;
        self.parser.feed_header(header);
        Poll::Ready(Ok(()))
    }

    // Note that unlike the regular Reader, the parent bytes go into the output buffer.
    fn read_parent(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let parent = array_mut_ref!(self.buf, 0, PARENT_SIZE);
        {
            let mut total_read = 0;
            while total_read < PARENT_SIZE {
                let res = if let Some(outboard) = &mut self.outboard {
                    Pin::new(&mut *outboard).poll_read(cx, &mut parent[total_read..])
                } else {
                    Pin::new(&mut self.input).poll_read(cx, &mut parent[total_read..])
                };

                match res {
                    Poll::Ready(Ok(read)) => {
                        total_read += read;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        self.buf_start = 0;
        self.buf_end = PARENT_SIZE;
        self.parser.advance_parent();
        Poll::Ready(Ok(()))
    }

    fn read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        size: usize,
        skip: usize,
    ) -> Poll<io::Result<()>> {
        debug_assert_eq!(0, self.buf_len(), "read_chunk with nonempty buffer");
        let chunk = &mut self.buf[..size];
        {
            let mut total_read = 0;
            while total_read < size {
                let res = if let Some(outboard) = &mut self.outboard {
                    Pin::new(&mut *outboard).poll_read(cx, &mut chunk[total_read..])
                } else {
                    Pin::new(&mut self.input).poll_read(cx, &mut chunk[total_read..])
                };

                match res {
                    Poll::Ready(Ok(read)) => {
                        total_read += read;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        self.buf_start = 0;
        self.buf_end = size;
        // After reading a chunk, increment slice_bytes_read. This will stop
        // the read loop once we've read everything the caller asked for. If
        // the read indicates we should skip partway into the chunk (because
        // the target of the previous seek was in the middle), we don't count
        // skipped bytes against the total.
        self.slice_bytes_read += (size - skip) as u64;
        self.parser.advance_chunk();
        Poll::Ready(Ok(()))
    }

    fn make_progress_and_buffer_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // If we haven't finished the seek yet, do a step of that. That will buffer some output,
        // unless we just finished seeking.
        if !self.seek_done {
            let bookkeeping = self.parser.seek_next(self.slice_start);
            // The SliceExtractor doesn't manage a subtree stack, so it only
            // looks at the underlying_seek instruction.
            if let Some(outboard) = &mut self.outboard {
                if let Some((content_pos, outboard_pos)) = bookkeeping.underlying_seek_outboard() {
                    // As with Reader in the outboard case, the outboard extractor has to seek both of
                    // its inner readers. The content position of the state goes into the content
                    // reader, and the rest of the reported seek offset goes into the outboard reader.
                    match Pin::new(&mut self.input).poll_seek(cx, SeekFrom::Start(content_pos)) {
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            // TODO: is this okay?
                            return Poll::Pending;
                        }
                    }
                    match Pin::new(outboard).poll_seek(cx, SeekFrom::Start(outboard_pos)) {
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            // TODO: is this okay?
                            return Poll::Pending;
                        }
                    }
                }
            } else {
                if let Some(encoding_position) = bookkeeping.underlying_seek() {
                    match Pin::new(&mut self.input)
                        .poll_seek(cx, SeekFrom::Start(cast_offset(encoding_position)?))
                    {
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            // TODO: is this okay?
                            return Poll::Pending;
                        }
                    }
                }
            }
            let next_read = self.parser.seek_bookkeeping_done(bookkeeping);
            match next_read {
                NextRead::Header => return self.read_header(cx),
                NextRead::Parent => return self.read_parent(cx),
                NextRead::Chunk {
                    size,
                    finalization: _,
                    skip,
                    index: _,
                } => return self.read_chunk(cx, size, skip),
                NextRead::Done => self.seek_done = true, // Fall through to read.
            }
        }

        // If we haven't finished the read yet, do a step of that. If we've already supplied all
        // the requested bytes, however, don't read any more.
        if self.slice_bytes_read < self.slice_len {
            match self.parser.read_next() {
                NextRead::Header => unreachable!(),
                NextRead::Parent => return self.read_parent(cx),
                NextRead::Chunk {
                    size,
                    finalization: _,
                    skip,
                    index: _,
                } => return self.read_chunk(cx, size, skip),
                NextRead::Done => {} // EOF
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncSeek + Unpin, O: AsyncRead + AsyncSeek + Unpin> AsyncRead
    for SliceExtractor<T, O>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // If we don't have any output ready to go, try to read more.
        if self.buf_len() == 0 {
            match self.make_progress_and_buffer_output(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Unless we're at EOF, the buffer either already had some bytes or just got refilled.
        // Return as much as we can from it.
        let n = cmp::min(buf.len(), self.buf_len());
        buf[..n].copy_from_slice(&self.buf[self.buf_start..][..n]);
        self.buf_start += n;
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::decode::make_test_input;

    use futures::executor::block_on;

    #[test]
    fn test_encode() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = blake3::hash(&input);
            let (encoded, hash) = block_on(encode(&input));
            assert_eq!(expected_hash, hash);
            assert_eq!(encoded.len() as u128, encoded_size(case as u64));
            assert_eq!(encoded.len(), encoded.capacity());
            assert_eq!(
                encoded.len() as u128,
                case as u128 + outboard_size(case as u64)
            );
        }
    }

    #[test]
    fn test_outboard_encode() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = blake3::hash(&input);
            let (outboard, hash) = block_on(outboard(&input));
            assert_eq!(expected_hash, hash);
            assert_eq!(outboard.len() as u128, outboard_size(case as u64));
            assert_eq!(outboard.len(), outboard.capacity());
        }
    }

    #[test]
    #[should_panic]
    fn test_finalize_twice_panics() {
        block_on(async move {
            let mut encoder = Encoder::new(io::Cursor::new(Vec::<u8>::new()));
            let _ = encoder.finalize().await;
            let _ = encoder.finalize().await;
        });
    }

    #[test]
    #[should_panic]
    fn test_write_after_finalize_panics() {
        block_on(async move {
            let mut encoder = Encoder::new(io::Cursor::new(Vec::<u8>::new()));
            let _ = encoder.finalize().await;
            let _ = encoder.write(&[]).await;
        });
    }

    #[test]
    fn test_into_inner() {
        let v = vec![1u8, 2, 3];
        let encoder = Encoder::new(io::Cursor::new(v.clone()));
        let extractor =
            SliceExtractor::new(io::Cursor::new(encoder.into_inner().into_inner()), 0, 0);
        let (r1, r2) = extractor.into_inner();
        assert_eq!(r1.into_inner(), v);
        assert!(r2.is_none());

        let outboard = SliceExtractor::new_outboard(
            io::Cursor::new(v.clone()),
            io::Cursor::new(v.clone()),
            0,
            0,
        );
        let (r3, r4) = outboard.into_inner();
        assert_eq!(r3.into_inner(), v);
        assert_eq!(r4.unwrap().into_inner(), v);
    }

    #[test]
    fn test_empty_write_after_one_chunk() {
        let input = &[0; CHUNK_SIZE];
        let mut output = Vec::new();
        block_on(async move {
            let mut encoder = Encoder::new(io::Cursor::new(&mut output));
            encoder.write_all(input).await.unwrap();
            encoder.write(&[]).await.unwrap();
            let hash = encoder.finalize().await.unwrap();
            assert_eq!((output, hash), encode(input).await);
            assert_eq!(hash, blake3::hash(input));
        });
    }
}
