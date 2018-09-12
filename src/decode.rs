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

// The state structs are each in their own modules to enforce privacy. For example, callers should
// only ever read content_len by calling len_next().
use self::parse_state::ParseState;
mod parse_state {
    use super::*;

    #[derive(Clone, Debug)]
    pub(crate) struct ParseState {
        content_len: Option<u64>,
        next_chunk: u64,
        upcoming_parents: u8,
        stack_depth: u8,
        encoded_offset: u128,
        length_verified: bool,
        at_root: bool,
    }

    impl ParseState {
        pub(crate) fn new() -> Self {
            Self {
                content_len: None,
                next_chunk: 0,
                upcoming_parents: 0,
                stack_depth: 1,
                encoded_offset: 0,
                length_verified: false,
                at_root: true,
            }
        }

        pub(crate) fn position(&self) -> u64 {
            if let Some(content_len) = self.content_len {
                cmp::min(
                    content_len,
                    self.next_chunk.saturating_mul(CHUNK_SIZE as u64),
                )
            } else {
                0
            }
        }

        // VerifyState needs this to know when to pop nodes during a seek.
        pub(crate) fn stack_depth(&self) -> usize {
            self.stack_depth as usize
        }

        // As with len_next, the ParseState doesn't strictly need to know about finalizations to do
        // its job. But its callers need to finalize, and we want to tightly gate access to
        // content_len (so that it doesn't get accidentally used without verifying it), so we
        // centralize the logic here.
        pub(crate) fn finalization(&self) -> Finalization {
            let content_len = self.content_len.expect("finalization with no len");
            if self.at_root {
                Root(content_len)
            } else {
                NotRoot
            }
        }

        fn reset_to_root(&mut self) {
            self.next_chunk = 0;
            self.upcoming_parents = encode::pre_order_parent_nodes(0, self.content_len.unwrap());
            self.encoded_offset = HEADER_SIZE as u128;
            self.at_root = true;
            self.stack_depth = 1;
        }

        // Strictly speaking, since ParseState doesn't verify anything, it could just return the
        // content_len from a parsed header without any extra fuss. However, all of the users of this
        // struct either need to do verifying themselves (VerifyState) or will produce output that
        // needs to have all the verifiable data in it (SliceExtractor). So it makes sense to
        // centralize the length reading logic here.
        //
        // Note that if reading the length returns StateNext::Chunk (leading the caller to call
        // feed_chunk), the content position will no longer be at the start, as with a standard read.
        // All of our callers buffer the last chunk, so this won't ultimately cause the user to skip
        // over any input. But a caller that didn't buffer anything would need to account for this
        // somehow.
        pub(crate) fn len_next(&self) -> LenNext {
            match (self.content_len, self.length_verified) {
                (None, false) => LenNext::Next(StateNext::Header),
                (None, true) => unreachable!(),
                (Some(len), false) => {
                    if self.upcoming_parents > 0 {
                        LenNext::Next(StateNext::Parent)
                    } else {
                        LenNext::Next(StateNext::Chunk {
                            size: len as usize,
                            finalization: Root(len),
                        })
                    }
                }
                (Some(len), true) => LenNext::Len(len),
            }
        }

        fn is_eof(&self) -> bool {
            match self.len_next() {
                LenNext::Len(len) => self.next_chunk >= encode::count_chunks(len),
                LenNext::Next(_) => false,
            }
        }

        pub(crate) fn read_next(&self) -> Option<StateNext> {
            let content_len = match self.len_next() {
                LenNext::Next(next) => return Some(next),
                LenNext::Len(len) => len,
            };
            if self.is_eof() {
                None
            } else if self.upcoming_parents > 0 {
                Some(StateNext::Parent)
            } else {
                Some(StateNext::Chunk {
                    size: encode::chunk_size(self.next_chunk, content_len),
                    finalization: NotRoot,
                })
            }
        }

        // The buffered_bytes argument tells the parser how many content bytes immediately prior to
        // the next_chunk the caller is storing. (This is generally exactly the previous chunk, but
        // in a multi-threaded reader it could be the size of a larger pipeline of buffers.) If the
        // seek is into that region, it will tell the caller to just adjust its buffer start,
        // rather than seeking backwards and repeating reads.
        //
        // Returns (maybe buffer start, maybe seek, maybe state next). A None buffer start means
        // that the buffer needs to be purged (such that subsequent calls to seek would pass
        // buffered_bytes=0), otherwise the buffer should be retained and its cursor set to the new
        // start value. A non-None seek value means that the caller should execute a seek on the
        // underlying reader, with the offset measured from the start. No state next means the seek
        // is done, though the first two arguments still need to be respected first.
        pub(crate) fn seek_next(
            &mut self,
            seek_to: u64,
            buffered_bytes: usize,
        ) -> (Option<usize>, Option<u128>, Option<StateNext>) {
            let content_len = match self.len_next() {
                LenNext::Next(next) => {
                    debug_assert_eq!(0, buffered_bytes);
                    return (None, None, Some(next));
                }
                LenNext::Len(len) => len,
            };

            // Cap the seek_to at the content_len. This simplifies buffer adjustment and EOF
            // checking, since content_len is the max position().
            let seek_to = cmp::min(seek_to, content_len);

            // If the seek can be handled with just a buffer adjustment, do that. This includes
            // seeks into the middle of a chunk we just read, possibly as a result of the a LenNext
            // above.
            let leftmost_buffered = self.position() - buffered_bytes as u64;
            if leftmost_buffered <= seek_to && seek_to <= self.position() {
                let new_buf_start = (seek_to - leftmost_buffered) as usize;
                return (Some(new_buf_start), None, None);
            }

            // If the seek is further to our left than just a buffer adjustment, reset the whole
            // parser and stack, so that we can re-seek from the beginning. Note that this is one
            // of the two case (along with popping subtrees from the stack below) where the call
            // will need to execute an actual seek in the underlying stream.
            let mut maybe_seek_offset = None;
            let leftmost_buffered = self.position() - buffered_bytes as u64;
            if seek_to < leftmost_buffered {
                self.reset_to_root();
                maybe_seek_offset = Some(self.encoded_offset);
            }

            loop {
                // If the target is the current position, the seek is finished. This includes EOF.
                if seek_to == self.position() {
                    return (None, maybe_seek_offset, None);
                }

                // If the target is within the current subtree, we either need to descend in the
                // tree or read the next chunk for a buffer adjustment.
                if seek_to < self.subtree_end() {
                    if self.upcoming_parents > 0 {
                        return (None, maybe_seek_offset, Some(StateNext::Parent));
                    } else {
                        debug_assert!(self.subtree_size() <= CHUNK_SIZE as u64);
                        return (
                            None,
                            maybe_seek_offset,
                            Some(StateNext::Chunk {
                                size: self.subtree_size() as usize,
                                finalization: self.finalization(),
                            }),
                        );
                    }
                }

                // Otherwise jump out of the current subtree and loop.
                self.stack_depth -= 1;
                self.encoded_offset += encode::encoded_subtree_size(self.subtree_size());
                maybe_seek_offset = Some(self.encoded_offset);
                self.next_chunk += encode::count_chunks(self.subtree_size());
                if !self.is_eof() {
                    // upcoming_parents is only meaningful if we're before EOF.
                    self.upcoming_parents =
                        encode::pre_order_parent_nodes(self.next_chunk, content_len);
                }
            }
        }

        pub(crate) fn feed_header(&mut self, header: &[u8; HEADER_SIZE]) {
            assert!(self.content_len.is_none(), "second call to feed_header");
            let content_len = hash::decode_len(header);
            self.content_len = Some(content_len);
            self.reset_to_root();
        }

        pub(crate) fn advance_parent(&mut self) {
            assert!(
                self.upcoming_parents > 0,
                "too many calls to advance_parent"
            );
            self.upcoming_parents -= 1;
            self.encoded_offset += PARENT_SIZE as u128;
            self.length_verified = true;
            self.at_root = false;
            self.stack_depth += 1;
        }

        pub(crate) fn advance_chunk(&mut self) {
            assert_eq!(
                0, self.upcoming_parents,
                "advance_chunk with non-zero upcoming parents"
            );
            self.encoded_offset += self.subtree_size() as u128;
            self.next_chunk += 1;
            self.length_verified = true;
            self.at_root = false;
            self.stack_depth -= 1;
            // Note that is_eof() depends on the flag changes we just made.
            if !self.is_eof() {
                // upcoming_parents is only meaningful if we're before EOF.
                self.upcoming_parents =
                    encode::pre_order_parent_nodes(self.next_chunk, self.content_len.unwrap());
            }
        }

        fn subtree_size(&self) -> u64 {
            debug_assert!(!self.is_eof());
            let content_len = self.content_len.unwrap();
            // The following should avoid overflow even if content_len is 2^64-1. upcoming_parents was
            // computed from the chunk count, and as long as chunks are larger than 1 byte, it will
            // always be less than 64.
            let max_subtree_size = (1 << self.upcoming_parents) * CHUNK_SIZE as u64;
            cmp::min(content_len - self.position(), max_subtree_size)
        }

        fn subtree_end(&self) -> u64 {
            debug_assert!(!self.is_eof());
            self.position() + self.subtree_size()
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StateNext {
    Header,
    Parent,
    Chunk {
        size: usize,
        finalization: Finalization,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LenNext {
    Len(u64),
    Next(StateNext),
}

// The state structs are each in their own modules to enforce privacy. For example, callers should
// only ever read content_len by calling len_next().
use self::verify_state::VerifyState;
mod verify_state {
    use super::*;

    #[derive(Clone)]
    pub(crate) struct VerifyState {
        stack: ArrayVec<[Hash; MAX_DEPTH]>,
        parser: ParseState,
        root_hash: Hash,
    }

    impl VerifyState {
        pub(crate) fn new(hash: &Hash) -> Self {
            let mut stack = ArrayVec::new();
            stack.push(*hash);
            Self {
                stack,
                parser: ParseState::new(),
                root_hash: *hash,
            }
        }

        pub(crate) fn position(&self) -> u64 {
            self.parser.position()
        }

        pub(crate) fn read_next(&self) -> Option<StateNext> {
            self.parser.read_next()
        }

        pub(crate) fn len_next(&self) -> LenNext {
            self.parser.len_next()
        }

        pub(crate) fn seek_next(
            &mut self,
            seek_to: u64,
            buffered_bytes: usize,
        ) -> (Option<usize>, Option<u128>, Option<StateNext>) {
            let position_before = self.position();
            let ret = self.parser.seek_next(seek_to, buffered_bytes);
            if self.position() < position_before {
                // Any leftward seek requires resetting the stack to the beginning.
                self.stack.clear();
                self.stack.push(self.root_hash);
            }
            debug_assert!(self.stack.len() >= self.parser.stack_depth());
            while self.stack.len() > self.parser.stack_depth() {
                self.stack.pop();
            }
            ret
        }

        pub(crate) fn feed_header(&mut self, header: &[u8; HEADER_SIZE]) {
            self.parser.feed_header(header);
        }

        pub(crate) fn feed_parent(&mut self, parent: &hash::ParentNode) -> Result<()> {
            let finalization = self.parser.finalization();
            let expected_hash = *self.stack.last().expect("unexpectedly empty stack");
            let computed_hash = hash::hash_node(parent, finalization);
            if !constant_time_eq(&expected_hash, &computed_hash) {
                return Err(Error::HashMismatch);
            }
            let left_child = *array_ref!(parent, 0, HASH_SIZE);
            let right_child = *array_ref!(parent, HASH_SIZE, HASH_SIZE);
            self.stack.pop();
            self.stack.push(right_child);
            self.stack.push(left_child);
            self.parser.advance_parent();
            Ok(())
        }

        pub(crate) fn feed_chunk(&mut self, chunk_hash: Hash) -> Result<()> {
            let expected_hash = *self.stack.last().expect("unexpectedly empty stack");
            if !constant_time_eq(&chunk_hash, &expected_hash) {
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

// Shared between Reader and SliceReader (but not SliceExtractor).
#[derive(Clone)]
struct ReaderShared<T: Read, O: Read> {
    input: T,
    outboard: Option<O>,
    state: VerifyState,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
}

impl<T: Read, O: Read> ReaderShared<T, O> {
    pub fn new(input: T, outboard: Option<O>, hash: &Hash) -> Self {
        Self {
            input,
            outboard,
            state: VerifyState::new(hash),
            buf: [0; CHUNK_SIZE],
            buf_start: 0,
            buf_end: 0,
        }
    }

    pub fn len(&mut self) -> io::Result<u64> {
        loop {
            match self.state.len_next() {
                LenNext::Len(len) => return Ok(len),
                LenNext::Next(next) => match next {
                    StateNext::Header => self.read_header()?,
                    StateNext::Parent => self.read_parent()?,
                    StateNext::Chunk { size, finalization } => {
                        // Note that reading a chunk (which we need to do to verify the hash if
                        // there are no parent nodes at all) advances the reader. However, because
                        // this can only happen at the beginning, and we buffer the last chunk
                        // read, the caller won't skip any data.
                        self.read_chunk(size, finalization)?;
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
        if let Some(ref mut outboard) = self.outboard {
            outboard.read_exact(&mut header)?;
        } else {
            self.input.read_exact(&mut header)?;
        }
        self.state.feed_header(&header);
        Ok(())
    }

    fn read_parent(&mut self) -> io::Result<()> {
        let mut parent = [0; PARENT_SIZE];
        if let Some(ref mut outboard) = self.outboard {
            outboard.read_exact(&mut parent)?;
        } else {
            self.input.read_exact(&mut parent)?;
        }
        self.state.feed_parent(&parent)?;
        Ok(())
    }

    fn read_chunk(&mut self, size: usize, finalization: Finalization) -> io::Result<()> {
        // Erase the buffer before doing any IO, so that if there's a failure subsequent reads and
        // seeks don't think there's valid data there.
        self.clear_buf();
        self.input.read_exact(&mut self.buf[..size])?;
        let hash = hash::hash_node(&self.buf[..size], finalization);
        self.state.feed_chunk(hash)?;
        self.buf_end = size;
        Ok(())
    }

    fn take_bytes(&mut self, buf: &mut [u8]) -> usize {
        let take = cmp::min(self.buf_len(), buf.len());
        buf[..take].copy_from_slice(&self.buf[self.buf_start..self.buf_start + take]);
        self.buf_start += take;
        take
    }
}

impl<T: Read, O: Read> fmt::Debug for ReaderShared<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ReaderShared {{ is_outboard: {}, state: {:?}, buf_start: {}, buf_end: {} }}",
            self.outboard.is_some(),
            self.state,
            self.buf_start,
            self.buf_end,
        )
    }
}

#[derive(Clone, Debug)]
pub struct Reader<T: Read, O: Read> {
    shared: ReaderShared<T, O>,
}

impl<T: Read> Reader<T, T> {
    pub fn new(inner: T, hash: &Hash) -> Self {
        Self {
            shared: ReaderShared::new(inner, None, hash),
        }
    }
}

impl<T: Read, O: Read> Reader<T, O> {
    pub fn new_outboard(inner: T, outboard: O, hash: &Hash) -> Self {
        Self {
            shared: ReaderShared::new(inner, Some(outboard), hash),
        }
    }

    /// Return the total length of the stream, according the header. This doesn't require the
    /// underlying reader to implement `Seek`. Note that this is the *total* length, regardless of
    /// the current read position.
    pub fn len(&mut self) -> io::Result<u64> {
        self.shared.len()
    }
}

impl<T: Read, O: Read> Read for Reader<T, O> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we need more data, loop on read_next() until we read a chunk.
        if self.shared.buf_len() == 0 {
            loop {
                match self.shared.state.read_next() {
                    Some(StateNext::Header) => self.shared.read_header()?,
                    Some(StateNext::Parent) => self.shared.read_parent()?,
                    Some(StateNext::Chunk { size, finalization }) => {
                        self.shared.read_chunk(size, finalization)?;
                        break;
                    }
                    None => return Ok(0), // EOF
                }
            }
        }
        Ok(self.shared.take_bytes(buf))
    }
}

impl<T: Read + Seek, O: Read + Seek> Seek for Reader<T, O> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        // Read and verify the length if we haven't already. The seek would take care of this
        // itself, but we need to get our hands on it directly to compute the asolute seek offset.
        let content_len = self.len()?;

        // Compute our current position, and use that to compute the absolute seek offset.
        let starting_position = self.shared.state.position() - self.shared.buf_len() as u64;
        let seek_to = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(off) => add_offset(content_len, off)?,
            io::SeekFrom::Current(off) => add_offset(starting_position, off)?,
        };

        loop {
            let (maybe_buf_start, maybe_seek_offset, maybe_next) =
                self.shared.state.seek_next(seek_to, self.shared.buf_end);
            if let Some(buf_start) = maybe_buf_start {
                self.shared.buf_start = buf_start;
            } else {
                // Seeks outside of the current buffer must erase it, because otherwise subsequent
                // short seeks could reuse buffer data from the wrong position.
                self.shared.clear_buf();
            }
            if let Some(offset) = maybe_seek_offset {
                // In the outboard case, the input reader will seek to the exact content position,
                // and the outboard reader will subtract that from the reported offset (which is
                // calculated for the combined case).
                if let Some(ref mut outboard) = self.shared.outboard {
                    let content_position = self.shared.state.position();
                    self.shared
                        .input
                        .seek(io::SeekFrom::Start(content_position))?;
                    let outboard_offset = offset - content_position as u128;
                    outboard.seek(io::SeekFrom::Start(cast_offset(outboard_offset)?))?;
                } else {
                    self.shared
                        .input
                        .seek(io::SeekFrom::Start(cast_offset(offset)?))?;
                }
            }
            match maybe_next {
                Some(StateNext::Header) => unreachable!(),
                Some(StateNext::Parent) => self.shared.read_parent()?,
                Some(StateNext::Chunk { size, finalization }) => {
                    self.shared.read_chunk(size, finalization)?
                }
                None => {
                    return Ok(seek_to);
                }
            }
        }
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

pub struct SliceReader<T: Read> {
    shared: ReaderShared<T, T>,
    slice_start: u64,
    slice_remaining: u64,
    did_seek: bool,
}

impl<T: Read> SliceReader<T> {
    pub fn new(inner: T, hash: &Hash, slice_start: u64, slice_len: u64) -> Self {
        Self {
            shared: ReaderShared::new(inner, None, hash),
            slice_start,
            slice_remaining: slice_len,
            did_seek: false,
        }
    }
}

impl<T: Read> Read for SliceReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any output ready to go, try to read more.
        if self.shared.buf_len() == 0 {
            // If we haven't done the seek yet, do the whole thing in a loop.
            if !self.did_seek {
                // Do the seek.
                self.did_seek = true;
                loop {
                    // Note that we ignore the returned seek offset. In a slice, the next thing we
                    // need to read is always next in the stream.
                    let (maybe_start, _, maybe_next) = self
                        .shared
                        .state
                        .seek_next(self.slice_start, self.shared.buf_end);
                    if let Some(start) = maybe_start {
                        self.shared.buf_start = start;
                    } else {
                        // Seek never needs to clear the buffer, because there's only one seek.
                        debug_assert_eq!(0, self.shared.buf_start);
                        debug_assert_eq!(0, self.shared.buf_end);
                    }
                    match maybe_next {
                        Some(StateNext::Header) => self.shared.read_header()?,
                        Some(StateNext::Parent) => self.shared.read_parent()?,
                        Some(StateNext::Chunk { size, finalization }) => {
                            self.shared.read_chunk(size, finalization)?;
                        }
                        None => break,
                    }
                }
            }

            // After seeking, if we didn't already fill the buffer above, work on reading. If we've
            // already supplied all the requested bytes, however, don't read any more.
            while self.slice_remaining > 0 && self.shared.buf_len() == 0 {
                match self.shared.state.read_next() {
                    Some(StateNext::Header) => unreachable!(),
                    Some(StateNext::Parent) => self.shared.read_parent()?,
                    Some(StateNext::Chunk { size, finalization }) => {
                        self.shared.read_chunk(size, finalization)?;
                    }
                    None => break, // EOF
                }
            }
        }

        // Unless we're at EOF, the buffer either already had some bytes or just got refilled.
        // Return as much as we can from it. Decrement the slice_remaining so that we know when to
        // stop.
        let want = cmp::min(buf.len(), self.slice_remaining as usize);
        let take = self.shared.take_bytes(&mut buf[..want]);
        self.slice_remaining -= take as u64;
        Ok(take)
    }
}

pub struct SliceExtractor<T: Read + Seek, O: Read + Seek> {
    input: T,
    outboard: Option<O>,
    slice_start: u64,
    slice_len: u64,
    slice_bytes_read: u64,
    previous_chunk_size: usize,
    parser: ParseState,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
    seek_done: bool,
}

impl<T: Read + Seek> SliceExtractor<T, T> {
    pub fn new(input: T, slice_start: u64, slice_len: u64) -> Self {
        Self::new_inner(input, None, slice_start, slice_len)
    }
}

impl<T: Read + Seek, O: Read + Seek> SliceExtractor<T, O> {
    pub fn new_outboard(input: T, outboard: O, slice_start: u64, slice_len: u64) -> Self {
        Self::new_inner(input, Some(outboard), slice_start, slice_len)
    }

    fn new_inner(input: T, outboard: Option<O>, slice_start: u64, slice_len: u64) -> Self {
        Self {
            input,
            outboard,
            slice_start,
            slice_len,
            slice_bytes_read: 0,
            previous_chunk_size: 0,
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
    fn read_header(&mut self) -> io::Result<()> {
        let header = array_mut_ref!(self.buf, 0, HEADER_SIZE);
        if let Some(ref mut outboard) = self.outboard {
            outboard.read_exact(header)?;
        } else {
            self.input.read_exact(header)?;
        }
        self.buf_start = 0;
        self.buf_end = HEADER_SIZE;
        self.parser.feed_header(header);
        Ok(())
    }

    // Note that unlike the regular Reader, the parent bytes go into the output buffer.
    fn read_parent(&mut self) -> io::Result<()> {
        let parent = array_mut_ref!(self.buf, 0, PARENT_SIZE);
        if let Some(ref mut outboard) = self.outboard {
            outboard.read_exact(parent)?;
        } else {
            self.input.read_exact(parent)?;
        }
        self.buf_start = 0;
        self.buf_end = PARENT_SIZE;
        self.parser.advance_parent();
        Ok(())
    }

    fn read_chunk(&mut self, size: usize) -> io::Result<()> {
        debug_assert_eq!(0, self.buf_len(), "read_chunk with nonempty buffer");
        let chunk = &mut self.buf[..size];
        self.input.read_exact(chunk)?;
        self.buf_start = 0;
        self.buf_end = size;
        // After reading a chunk, increment slice_bytes_read. This will stop the read loop once
        // we've read everything the caller asked for. Note that if the seek indicates we should
        // skip partway into a chunk, we'll decrement slice_bytes_read to account for the skip.
        self.slice_bytes_read += size as u64;
        self.parser.advance_chunk();
        // Record the size of the chunk we just read. Unlike the other readers, because this one
        // keeps header and parent bytes in the output buffer, we can't just rely on buf_end.
        self.previous_chunk_size = size;
        Ok(())
    }

    fn make_progress_and_buffer_output(&mut self) -> io::Result<()> {
        // If we haven't finished the seek yet, do a step of that. That will buffer some output,
        // unless we just finished seeking.
        if !self.seek_done {
            // Also note that this reader, unlike the others, has to account for
            // previous_chunk_size separately from buf_end.
            let (maybe_start, maybe_seek_offset, maybe_next) = self
                .parser
                .seek_next(self.slice_start, self.previous_chunk_size);
            if let Some(start) = maybe_start {
                // If the seek needs us to skip into the middle of the buffer, we don't actually
                // skip bytes, because the recipient will need everything for decoding. However, we
                // decrement slice_bytes_read, so that the skipped bytes don't count against what
                // the caller asked for.
                self.slice_bytes_read -= start as u64;
            } else {
                // Seek never needs to clear the buffer, because there's only one seek.
                debug_assert_eq!(0, self.buf_len());
                debug_assert_eq!(0, self.previous_chunk_size);
            }
            if let Some(offset) = maybe_seek_offset {
                if let Some(ref mut outboard) = self.outboard {
                    // As with Reader in the outboard case, the outboard extractor has to seek both of
                    // its inner readers. The content position of the state goes into the content
                    // reader, and the rest of the reported seek offset goes into the outboard reader.
                    let content_position = self.parser.position();
                    self.input.seek(io::SeekFrom::Start(content_position))?;
                    let outboard_offset = offset - content_position as u128;
                    outboard.seek(io::SeekFrom::Start(cast_offset(outboard_offset)?))?;
                } else {
                    self.input.seek(io::SeekFrom::Start(cast_offset(offset)?))?;
                }
            }
            match maybe_next {
                Some(StateNext::Header) => return self.read_header(),
                Some(StateNext::Parent) => return self.read_parent(),
                Some(StateNext::Chunk {
                    size,
                    finalization: _,
                }) => return self.read_chunk(size),
                None => self.seek_done = true, // Fall through to read.
            }
        }

        // If we haven't finished the read yet, do a step of that. If we've already supplied all
        // the requested bytes, however, don't read any more.
        if self.slice_bytes_read < self.slice_len {
            match self.parser.read_next() {
                Some(StateNext::Header) => unreachable!(),
                Some(StateNext::Parent) => return self.read_parent(),
                Some(StateNext::Chunk {
                    size,
                    finalization: _,
                }) => return self.read_chunk(size),
                None => {} // EOF
            }
        }

        Ok(())
    }
}

impl<T: Read + Seek, O: Read + Seek> Read for SliceExtractor<T, O> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any output ready to go, try to read more.
        if self.buf_len() == 0 {
            self.make_progress_and_buffer_output()?;
        }

        // Unless we're at EOF, the buffer either already had some bytes or just got refilled.
        // Return as much as we can from it.
        let n = cmp::min(buf.len(), self.buf_len());
        buf[..n].copy_from_slice(&self.buf[self.buf_start..][..n]);
        self.buf_start += n;
        Ok(n)
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

            let (outboard_hash, outboard) = { encode::encode_outboard_to_vec(&input) };
            assert_eq!(hash, outboard_hash);
            let mut output = Vec::new();
            let mut decoder = Reader::new_outboard(&input[..], &outboard[..], &hash);
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

                let mut output = Vec::new();
                let mut decoder = Reader::new(&bad_encoded[..], &hash);
                let res = decoder.read_to_end(&mut output);
                assert_eq!(io::ErrorKind::InvalidData, res.unwrap_err().kind());
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
        println!("\n\ninput_len {}", input_len);
        let mut prng = ChaChaRng::from_seed([0; 32]);
        let input = make_test_input(input_len);
        let (hash, encoded) = encode::encode_to_vec(&input);
        let mut decoder = Reader::new(Cursor::new(&encoded), &hash);
        // Do a thousand random seeks and chunk-sized reads.
        for _ in 0..1000 {
            let seek = prng.gen_range(0, input_len + 1);
            println!("\nseek {}", seek);
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

    #[test]
    fn test_slices() {
        for &case in hash::TEST_CASES {
            let input = make_test_input(case);
            let (hash, encoded) = encode::encode_to_vec(&input);
            // Also make an outboard encoding, to test that case.
            let (outboard_hash, outboard) = encode::encode_outboard_to_vec(&input);
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
                        let mut extractor = SliceExtractor::new(
                            Cursor::new(&encoded),
                            slice_start as u64,
                            slice_len as u64,
                        );
                        extractor.read_to_end(&mut slice).unwrap();
                    }
                    // Make sure the outboard extractor produces the same output.
                    {
                        let mut slice_from_outboard = Vec::new();
                        let mut extractor = SliceExtractor::new_outboard(
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
                        SliceReader::new(&*slice, &hash, slice_start as u64, slice_len as u64);
                    reader.read_to_end(&mut output).unwrap();
                    assert_eq!(expected_output, &*output);
                }
            }
        }
    }

    #[test]
    fn test_corrupted_slice() {
        let input = make_test_input(20000);
        let slice_start = 5000;
        let slice_len = 15000;
        let (hash, encoded) = encode::encode_to_vec(&input);

        // Slice out the middle 5000 bytes;
        let mut slice = Vec::new();
        {
            let mut extractor =
                SliceExtractor::new(Cursor::new(&encoded), slice_start as u64, slice_len as u64);
            extractor.read_to_end(&mut slice).unwrap();
        }

        // First confirm that the regular decode works.
        let mut output = Vec::new();
        let mut reader = SliceReader::new(&*slice, &hash, slice_start as u64, slice_len as u64);
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(&input[slice_start..][..slice_len], &*output);

        // Also confirm that the outboard slice extractor gives the same slice.
        {
            let (outboard_hash, outboard) = encode::encode_outboard_to_vec(&input);
            assert_eq!(hash, outboard_hash);
            let mut slice_from_outboard = Vec::new();
            let mut extractor = SliceExtractor::new_outboard(
                Cursor::new(&input),
                Cursor::new(&outboard),
                slice_start as u64,
                slice_len as u64,
            );
            extractor.read_to_end(&mut slice_from_outboard).unwrap();
            assert_eq!(slice, slice_from_outboard);
        }

        // Now confirm that flipping bits anywhere in the slice will corrupt it.
        let mut i = 0;
        while i < slice.len() {
            let mut slice_clone = slice.clone();
            slice_clone[i] ^= 1;
            let mut reader =
                SliceReader::new(&*slice_clone, &hash, slice_start as u64, slice_len as u64);
            let err = reader.read_to_end(&mut output).unwrap_err();
            assert_eq!(io::ErrorKind::InvalidData, err.kind());
            i += 32;
        }
    }
}
