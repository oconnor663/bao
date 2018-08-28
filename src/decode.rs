use arrayvec::ArrayVec;
use constant_time_eq::constant_time_eq;
use copy_in_place::copy_in_place;
use rayon;

use encode;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, MAX_DEPTH, PARENT_SIZE};

use std;
use std::cmp;
use std::fmt;
use std::io;
use std::io::prelude::*;

fn verify_hash(node_bytes: &[u8], hash: &Hash, finalization: Finalization) -> Result<()> {
    let computed = hash::hash_node(node_bytes, finalization);
    if constant_time_eq(hash, &computed) {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

struct Subtree {
    offset: usize,
    content_len: usize,
    hash: Hash,
    finalization: Finalization,
}

enum Verified {
    Parent { left: Subtree, right: Subtree },
    Chunk { offset: usize, len: usize },
}

// Check that the top level of a subtree (which could be a single chunk) has a valid hash. This is
// designed to be callable by single-threaded, multi-threaded, and in-place decode functions. Note
// that it's legal for the subtree buffer to contain extra bytes after the parent node or chunk.
// The slices and casts in this function assume the buffer is big enough for the content, which
// should be checked by the caller with parse_and_check_content_len or known some other way.
fn verify_one_level(buf: &[u8], subtree: &Subtree) -> Result<Verified> {
    let &Subtree {
        offset,
        content_len,
        ref hash,
        finalization,
    } = subtree;
    if content_len <= CHUNK_SIZE {
        let chunk = &buf[offset..][..content_len];
        verify_hash(chunk, hash, finalization)?;
        Ok(Verified::Chunk {
            offset,
            len: content_len,
        })
    } else {
        let parent = array_ref!(buf, offset, PARENT_SIZE);
        verify_hash(parent, hash, finalization)?;
        let (left_hash, right_hash) = array_refs!(parent, HASH_SIZE, HASH_SIZE);
        let left = Subtree {
            offset: subtree.offset + PARENT_SIZE,
            content_len: hash::left_len(content_len as u64) as usize,
            hash: *left_hash,
            finalization: NotRoot,
        };
        let right = Subtree {
            offset: left.offset + encode::encoded_subtree_size(left.content_len as u64) as usize,
            content_len: content_len - left.content_len,
            hash: *right_hash,
            finalization: NotRoot,
        };
        Ok(Verified::Parent { left, right })
    }
}

fn decode_recurse(encoded: &[u8], subtree: &Subtree, output: &mut [u8]) -> Result<usize> {
    match verify_one_level(encoded, subtree)? {
        Verified::Chunk { offset, len } => {
            output[..len].copy_from_slice(&encoded[offset..][..len]);
            Ok(len)
        }
        Verified::Parent { left, right } => {
            let (left_out, right_out) = output.split_at_mut(left.content_len);
            let left_n = decode_recurse(encoded, &left, left_out)?;
            let right_n = decode_recurse(encoded, &right, right_out)?;
            Ok(left_n + right_n)
        }
    }
}

fn decode_recurse_rayon(encoded: &[u8], subtree: &Subtree, output: &mut [u8]) -> Result<usize> {
    match verify_one_level(encoded, subtree)? {
        Verified::Chunk { offset, len } => {
            output[..len].copy_from_slice(&encoded[offset..][..len]);
            Ok(len)
        }
        Verified::Parent { left, right } => {
            let (left_out, right_out) = output.split_at_mut(left.content_len);
            let (left_res, right_res) = rayon::join(
                || decode_recurse_rayon(encoded, &left, left_out),
                || decode_recurse_rayon(encoded, &right, right_out),
            );
            Ok(left_res? + right_res?)
        }
    }
}

fn verify_recurse(encoded: &[u8], subtree: &Subtree) -> Result<()> {
    match verify_one_level(encoded, subtree)? {
        Verified::Chunk { .. } => Ok(()),
        Verified::Parent { left, right } => {
            verify_recurse(encoded, &left)?;
            verify_recurse(encoded, &right)
        }
    }
}

fn verify_recurse_rayon(encoded: &[u8], subtree: &Subtree) -> Result<()> {
    match verify_one_level(encoded, subtree)? {
        Verified::Chunk { .. } => Ok(()),
        Verified::Parent { left, right } => {
            let (left_res, right_res) = rayon::join(
                || verify_recurse_rayon(encoded, &left),
                || verify_recurse_rayon(encoded, &right),
            );
            left_res.and(right_res)
        }
    }
}

// This function doesn't perform any verification, and it should only be used after one of the
// verify functions above.
fn extract_in_place(
    buf: &mut [u8],
    mut read_offset: usize,
    mut write_offset: usize,
    content_len: usize,
) {
    if content_len <= CHUNK_SIZE {
        // This function might eventually make its way into libcore:
        // https://github.com/rust-lang/rust/pull/53652
        copy_in_place(buf, read_offset, write_offset, content_len);
    } else {
        read_offset += PARENT_SIZE;
        let left_len = hash::left_len(content_len as u64) as usize;
        extract_in_place(buf, read_offset, write_offset, left_len);
        read_offset += encode::encoded_subtree_size(left_len as u64) as usize;
        write_offset += left_len;
        let right_len = content_len - left_len;
        extract_in_place(buf, read_offset, write_offset, right_len);
    }
}

// Casting the content_len down to usize runs the risk that 1 and 2^32+1 might give the same result
// on 32 bit systems, which would lead to apparent collisions. Check for that case, as well as the
// more obvious cases where the buffer is too small for the content length, or too small to even
// contain a header. Note that this doesn't verify any hashes.
pub fn parse_and_check_content_len(encoded: &[u8]) -> Result<usize> {
    if encoded.len() < HEADER_SIZE {
        return Err(Error::Truncated);
    }
    let len = hash::decode_len(array_ref!(encoded, 0, HEADER_SIZE));
    if (encoded.len() as u128) < encode::encoded_size(len) {
        return Err(Error::Truncated);
    }
    Ok(len as usize)
}

fn root_subtree(content_len: usize, hash: &Hash) -> Subtree {
    Subtree {
        offset: HEADER_SIZE,
        content_len,
        hash: *hash,
        finalization: Root(content_len as u64),
    }
}

pub fn decode(encoded: &[u8], output: &mut [u8], hash: &Hash) -> Result<usize> {
    let content_len = parse_and_check_content_len(encoded)?;
    if content_len <= hash::MAX_SINGLE_THREADED {
        decode_recurse(encoded, &root_subtree(content_len, hash), output)
    } else {
        decode_recurse_rayon(encoded, &root_subtree(content_len, hash), output)
    }
}

/// This is slower than `decode`, because only the verification step can be done in parallel. All
/// the memmoves have to be done in series.
pub fn decode_in_place(encoded: &mut [u8], hash: &Hash) -> Result<usize> {
    // Note that if you change anything in this function, you should probably
    // also update benchmarks::decode_in_place_fake.
    let content_len = parse_and_check_content_len(encoded)?;
    if content_len <= hash::MAX_SINGLE_THREADED {
        verify_recurse(encoded, &root_subtree(content_len, hash))?;
    } else {
        verify_recurse_rayon(encoded, &root_subtree(content_len, hash))?;
    }
    extract_in_place(encoded, HEADER_SIZE, 0, content_len);
    Ok(content_len)
}

pub fn decode_to_vec(encoded: &[u8], hash: &Hash) -> Result<Vec<u8>> {
    let content_len = parse_and_check_content_len(encoded)?;
    // Unsafe code here could avoid the cost of initialization, but it's not much.
    let mut out = vec![0; content_len];
    decode(encoded, &mut out, hash)?;
    Ok(out)
}

pub fn hash_from_encoded_nostd<F, E>(mut read_exact_fn: F) -> std::result::Result<Hash, E>
where
    F: FnMut(&mut [u8]) -> std::result::Result<(), E>,
{
    let mut buf = [0; CHUNK_SIZE];
    read_exact_fn(&mut buf[..HEADER_SIZE])?;
    let content_len = hash::decode_len(array_ref!(buf, 0, HEADER_SIZE));
    let node;
    if content_len <= CHUNK_SIZE as u64 {
        node = &mut buf[..content_len as usize];
    } else {
        node = &mut buf[..PARENT_SIZE];
    }
    read_exact_fn(node)?;
    Ok(hash::hash_node(node, Root(content_len)))
}

pub fn hash_from_encoded<T: Read>(reader: &mut T) -> io::Result<Hash> {
    hash_from_encoded_nostd(|buf| reader.read_exact(buf))
}

#[derive(Clone, Debug)]
struct State {
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
    pub fn new(hash: &Hash) -> Self {
        Self {
            stack: ArrayVec::new(),
            root_hash: *hash,
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
            // that's a spurious EOF and a security issue.
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
        let content_len = hash::decode_len(&header);
        self.content_len = Some(content_len);
        self.reset_to_root();
    }

    pub fn feed_parent(&mut self, parent: hash::ParentNode) -> Result<()> {
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
            return Err(Error::HashMismatch);
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

    pub fn feed_chunk(&mut self, chunk_hash: Hash) -> Result<()> {
        let expected_hash = *self.stack.last().expect("unexpectedly empty stack");
        if !constant_time_eq(&chunk_hash, &expected_hash) {
            return Err(Error::HashMismatch);
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

type Result<T> = std::result::Result<T, Error>;

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

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::HashMismatch => io::Error::new(io::ErrorKind::InvalidData, "hash mismatch"),
            Error::Truncated => io::Error::new(io::ErrorKind::UnexpectedEof, "truncated encoding"),
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
    pub fn new(inner: T, hash: &Hash) -> Self {
        Self {
            inner,
            state: State::new(hash),
            buf: [0; CHUNK_SIZE],
            buf_start: 0,
            buf_end: 0,
        }
    }

    /// Return the total length of the stream, according the header. This doesn't require the
    /// underlying reader to implement `Seek`. Note that this is not the remaining length, which
    /// will be different if the reader has already advanced.
    pub fn len(&mut self) -> io::Result<u64> {
        loop {
            match self.state.len_next() {
                LenNext::Len(len) => return Ok(len),
                LenNext::Next(next) => match next {
                    StateNext::Header => self.read_header()?,
                    StateNext::Parent => self.read_parent()?,
                    StateNext::Chunk {
                        size,
                        skip,
                        finalization,
                    } => {
                        // Note that reading a chunk (which we need to do to verify the hash if
                        // there are no parent nodes at all) advances the reader. However, because
                        // this can only happen at the beginning, and we buffer the last chunk
                        // read, the caller won't skip any data.
                        self.read_chunk(size, skip, finalization)?;
                    }
                },
            }
        }
    }

    fn buf_len(&self) -> usize {
        self.buf_end - self.buf_start
    }

    fn clear_buf(&mut self) {
        // Note that because seeking can move buf_start backwards, it's important that we set them
        // both to exactly zero. It wouldn't be enough to just set buf_start = buf_end.
        self.buf_start = 0;
        self.buf_end = 0;
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
        self.state.feed_parent(parent)?;
        Ok(())
    }

    fn read_chunk(
        &mut self,
        size: usize,
        skip: usize,
        finalization: Finalization,
    ) -> io::Result<()> {
        debug_assert!(skip == 0 || skip < size, "impossible skip offset");
        debug_assert_eq!(0, self.buf_len(), "read_chunk with nonempty buffer");
        // Clear the buffer before doing any IO, so that if there's a failure subsequent reads and
        // seeks don't think there's valid data there. Note that even though we just asserted that
        // the buffer was empty above, we still need to clear it, because seek can move buf_start
        // backwards.
        self.clear_buf();
        self.inner.read_exact(&mut self.buf[..size])?;
        let hash = hash::hash_node(&self.buf[..size], finalization);
        self.state.feed_chunk(hash)?;
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
        // Read and verify the length if we haven't already. Note that this might read a chunk,
        // which would fill the buffer and change the State position.
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

        // Compute our current position, and use that to compute the absolute target_position of
        // the seek. Note an invariant here, which we'll also rely on below: If the buffer is
        // non-empty, the State position is exactly the end of the buffer.
        let starting_position = self.state.position() - self.buf_len() as u64;
        let target_position = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(off) => add_offset(content_len, off)?,
            io::SeekFrom::Current(off) => add_offset(starting_position, off)?,
        };

        // If the seek is entirely within the current buffer, just adjust buf_start. Note that
        // we're relying on the position invariant from above: If the buffer is non-empty, then
        // self.state.position() is exactly the end of the current buffer.
        let buf_origin = self.state.position() - self.buf_end as u64;
        if buf_origin <= target_position && target_position < self.state.position() {
            self.buf_start = (target_position - buf_origin) as usize;
            return Ok(target_position);
        }

        // Now, since we're entering the main seek loop, clear the buffer. Buffered input won't be
        // valid at the new position.
        self.clear_buf();

        // Finally, loop over the seek_next() method until it's done.
        loop {
            let (seek_offset, next) = self.state.seek_next(target_position);
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
                    debug_assert_eq!(target_position, self.state.position());
                    return Ok(target_position);
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

// This module is only exposed for writing benchmarks, and nothing here should
// actually be used outside this crate.
#[doc(hidden)]
pub mod benchmarks {
    use super::*;

    // A limitation of the benchmarks runner is that you can't do per-run reinitialization that
    // doesn't get measured. So we do an "in-place" decoding where the buffer we actually modify is
    // garbage bytes, so that we don't trash the input in each run.
    pub fn decode_in_place_fake(encoded: &[u8], hash: &Hash, fake_buf: &mut [u8]) -> Result<usize> {
        let content_len = parse_and_check_content_len(encoded)?;
        if content_len <= hash::MAX_SINGLE_THREADED {
            verify_recurse(encoded, &root_subtree(content_len, hash))?;
        } else {
            verify_recurse_rayon(encoded, &root_subtree(content_len, hash))?;
        }
        extract_in_place(fake_buf, HEADER_SIZE, 0, content_len);
        Ok(content_len)
    }
}

#[cfg(test)]
pub(crate) fn make_test_input(len: usize) -> Vec<u8> {
    extern crate byteorder;
    use byteorder::{BigEndian, WriteBytesExt};

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

#[cfg(test)]
mod test {
    extern crate rand;

    use self::rand::{prng::chacha::ChaChaRng, Rng, SeedableRng};
    use std::io;
    use std::io::prelude::*;
    use std::io::Cursor;

    use super::*;
    use encode;
    use hash;

    #[test]
    fn test_decoders() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (hash, encoded) = { encode::encode_to_vec(&input) };

            let mut output = vec![0; case];
            decode_recurse(&encoded, &root_subtree(input.len(), &hash), &mut output).unwrap();
            assert_eq!(input, output);

            let mut output = vec![0; case];
            decode_recurse_rayon(&encoded, &root_subtree(input.len(), &hash), &mut output).unwrap();
            assert_eq!(input, output);

            let mut output = vec![0; case];
            decode(&encoded, &mut output, &hash).unwrap();
            assert_eq!(input, output);

            let mut output = encoded.clone();
            let n = decode_in_place(&mut output, &hash).unwrap();
            output.truncate(n);
            assert_eq!(input, output);

            let output = decode_to_vec(&encoded, &hash).unwrap();
            assert_eq!(input, output);

            let mut output = Vec::new();
            let mut decoder = Reader::new(&encoded[..], &hash);
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(input, output);

            // Go ahead and test the fake benchmarking decoder because why not.
            let output = encoded.clone();
            let mut output_mut = encoded.clone();
            let n = benchmarks::decode_in_place_fake(&output, &hash, &mut output_mut).unwrap();
            output_mut.truncate(n);
            assert_eq!(input, output_mut);
        }
    }

    #[test]
    fn test_decoders_corrupted() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (hash, encoded) = encode::encode_to_vec(&input);
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
                let res =
                    decode_recurse(&bad_encoded, &root_subtree(input.len(), &hash), &mut output);
                assert_eq!(Error::HashMismatch, res.unwrap_err());

                let mut output = vec![0; case];
                let res = decode_recurse_rayon(
                    &bad_encoded,
                    &root_subtree(input.len(), &hash),
                    &mut output,
                );
                assert_eq!(Error::HashMismatch, res.unwrap_err());

                let mut output = vec![0; case];
                let res = decode(&bad_encoded, &mut output, &hash);
                assert_eq!(Error::HashMismatch, res.unwrap_err());

                let mut output = bad_encoded.clone();
                let res = decode_in_place(&mut output, &hash);
                assert_eq!(Error::HashMismatch, res.unwrap_err());

                let res = decode_to_vec(&bad_encoded, &hash);
                assert_eq!(Error::HashMismatch, res.unwrap_err());
            }
        }
    }

    #[test]
    fn test_seek() {
        for &input_len in hash::TEST_CASES {
            println!();
            println!("input_len {}", input_len);
            let input = make_test_input(input_len);
            let (hash, encoded) = encode::encode_to_vec(&input);
            for &seek in hash::TEST_CASES {
                println!("seek {}", seek);
                // Test all three types of seeking.
                let mut seek_froms = Vec::new();
                seek_froms.push(io::SeekFrom::Start(seek as u64));
                seek_froms.push(io::SeekFrom::End(seek as i64 - input_len as i64));
                seek_froms.push(io::SeekFrom::Current(seek as i64));
                for seek_from in seek_froms {
                    println!("seek_from {:?}", seek_from);
                    let mut decoder = Reader::new(Cursor::new(&encoded), &hash);
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
        let (hash, encoded) = encode::encode_to_vec(&input);
        let mut decoder = Reader::new(Cursor::new(&encoded), &hash);
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

        let (zero_hash, zero_encoded) = encode::encode_to_vec(b"");
        let one_hash = hash::hash(b"x");

        // Decoding the empty tree with the right hash should succeed.
        let mut output = Vec::new();
        let mut decoder = Reader::new(&*zero_encoded, &zero_hash);
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(&output, &[]);

        // Decoding the empty tree with any other hash should fail.
        let mut output = Vec::new();
        let mut decoder = Reader::new(&*zero_encoded, &one_hash);
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
            let (hash, mut encoded) = encode::encode_to_vec(&input);
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
            let mut decoder = Reader::new(Cursor::new(&encoded), &hash);
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
            let input = make_test_input(case);
            let (hash, encoded) = encode::encode_to_vec(&input);
            let mut bad_hash = hash;
            bad_hash[0] ^= 1;

            // Seeking past the end of a tree should succeed with the right hash.
            let mut output = Vec::new();
            let mut decoder = Reader::new(Cursor::new(&encoded), &hash);
            decoder.seek(io::SeekFrom::Start(case as u64)).unwrap();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(&output, &[]);

            // Seeking past the end of a tree should fail if the root hash is wrong.
            let mut decoder = Reader::new(Cursor::new(&encoded), &bad_hash);
            let result = decoder.seek(io::SeekFrom::Start(case as u64));
            assert!(result.is_err(), "a bad hash is supposed to fail!");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn test_hash_from_encoded() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (hash, encoded) = encode::encode_to_vec(&input);
            let inferred_hash = hash_from_encoded(&mut Cursor::new(&*encoded)).unwrap();
            assert_eq!(hash, inferred_hash, "hashes don't match");
        }
    }

    #[test]
    fn test_len_then_read() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let (hash, encoded) = encode::encode_to_vec(&input);
            let mut decoder = Reader::new(&*encoded, &hash);

            // Read the len and make sure it's correct.
            let len = decoder.len().unwrap();
            assert_eq!(case as u64, len, "len mismatch");

            // Read all the output and make sure we didn't miss any.
            let mut output = Vec::new();
            decoder.read_to_end(&mut output).unwrap();
            assert_eq!(input, output, "missed output");

            // Check the len again just to be safe.
            let len = decoder.len().unwrap();
            assert_eq!(case as u64, len, "len mismatch");
        }
    }
}
