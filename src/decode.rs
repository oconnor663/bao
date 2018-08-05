extern crate constant_time_eq;
extern crate either;

use self::constant_time_eq::constant_time_eq;
use self::either::Either::{self, Left, Right};
use arrayvec::ArrayVec;
use unverified::Unverified;

use encode;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, MAX_DEPTH, PARENT_SIZE};

use std;

#[derive(Clone)]
pub struct State2 {
    stack: ArrayVec<[Subtree; MAX_DEPTH]>,
    root_hash: Hash,
    content_length: Option<u64>,
    length_verified: bool,
    content_position: u64,
    encoded_offset: u128,
}

impl State2 {
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
        self.content_position = 0;
        self.encoded_offset = HEADER_SIZE as u128;
        self.stack.clear();
        self.stack.push(Subtree {
            hash: self.root_hash,
            start: 0,
            end: self.content_length.expect("no header"),
        });
    }

    pub fn read_next(&self) -> StateNext {
        let content_length;
        match self.len_next() {
            Left(len) => content_length = len,
            Right(next) => return next,
        }
        if let Some(subtree) = self.stack.last() {
            subtree.state_next(content_length, self.content_position)
        } else {
            assert!(self.length_verified, "unverified EOF");
            StateNext::Done
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

    pub fn seek_next(&mut self, content_position: u64) -> (u128, StateNext) {
        // Get the current content length. This will lead us to read the header and verify the root
        // node, if we haven't already.
        let content_length;
        match self.len_next() {
            Left(len) => content_length = len,
            Right(next) => return (self.encoded_offset, next),
        }

        // Record the target position, which we use in read_next() to compute the skip.
        self.content_position = content_position;

        // If we're already past EOF, either reset or short circuit.
        if self.stack.is_empty() {
            if content_position >= content_length {
                return (self.encoded_offset, StateNext::Done);
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
            if content_position < current_subtree.start + CHUNK_SIZE as u64 {
                return (self.encoded_offset, StateNext::Done);
            }

            // If the target is outside the next chunk, but within the current subtree, then we
            // need to descend.
            if content_position < current_subtree.end {
                return (
                    self.encoded_offset,
                    current_subtree.state_next(content_length, self.content_position),
                );
            }

            // Otherwise pop the current tree and repeat.
            self.encoded_offset += encode::encoded_subtree_size(current_subtree.len());
            self.stack.pop();
        }

        // If we made it out the main loop, we're at EOF.
        (self.encoded_offset, StateNext::Done)
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
    Done,
}

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

pub fn decode(mut input: &[u8], hash: &Hash) -> std::result::Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    let mut dec = Decoder2::new(hash);
    loop {
        let used = {
            let (used, output_bytes) = dec.feed(input)?;
            input = &input[used..];
            output.extend_from_slice(output_bytes);
            used
        };
        // TODO: This is ugly. I don't like that the loop has to be so
        // complicated. Can header parsing just fall through to chunk parsing?
        if dec.is_eof() {
            break;
        } else if used == 0 {
            // Incomplete input.
            return Err(());
        }
    }
    Ok(output)
}

// A tree with N chunks in it has a height equal to the ceiling log_2 of N.
fn tree_height(num_chunks: u64) -> u8 {
    64 - (num_chunks - 1).leading_zeros() as u8
}

// Given a chunk index, how many chunks are in the subtree for which that index
// is the rightmost leaf? We can figure that out by looking at which bits will
// change between that index and the next one. When a lot of bits change
// (because the carry bit is propagating through a big power of 2), we're at
// the end of a big subtree. Together with tree_height(), we'll use this to
// figure out how many parent nodes we need to traverse, after we pop a new
// subtree off the stack.
fn subtree_size_from_rightmost_chunk(chunk_index: u64) -> u64 {
    let changing_bits = chunk_index ^ (chunk_index + 1);
    let new_one_bit_only = changing_bits & (chunk_index + 1);
    new_one_bit_only
}

// Accumulate bytes up to a target length. When receiving small writes, store
// them in an internal buffer. When receiving big writes, if the internal
// buffer is empty, return slices directly from the input, to cut down on
// unnecessary copies.
struct Accumulator {
    buf: [u8; CHUNK_SIZE],
    buf_len: usize,
    used: bool,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            buf: [0; CHUNK_SIZE],
            buf_len: 0,
            used: false,
        }
    }

    fn accumulate<'a>(&'a mut self, input: &'a [u8], len: usize) -> (usize, Option<&'a [u8]>) {
        // Used means the bytes in our buffer were returned by the last call to
        // accumulate. Clear them.
        if self.used {
            self.used = false;
            self.buf_len = 0;
        }
        // If we can just return bytes straight from the input, do that.
        if self.buf_len == 0 && input.len() >= len {
            return (len, Some(&input[..len]));
        }
        // Otherwise fill our buffer with as many bytes as we can, up to the
        // total that we need.
        let needed = len.saturating_sub(self.buf_len);
        let take = std::cmp::min(needed, input.len());
        self.buf[self.buf_len..][..take].copy_from_slice(&input[..take]);
        self.buf_len += take;
        // If we managed to fill it all the way, return the bytes.
        if self.buf_len == len {
            self.used = true;
            (take, Some(&self.buf[..len]))
        } else {
            (take, None)
        }
    }
}

/// (bytes used, output)
type Result2<'a> = std::result::Result<(usize, &'a [u8]), ()>;

/// This decoder saves a stack of right children and pops that stack to
/// traverse, as in a standard depth-first search. For seeking, we always clear
/// the stack and start from the top. This has a performance penalty compared
/// to maintaining a complete stack of parent nodes, but 1) it's a lot simpler,
/// and 2) the complete stack still sometimes has to do full-cost short seeks,
/// when crossing between large sub-tree boundaries.
pub struct Decoder2 {
    stack: ArrayVec<[Hash; 64]>,
    acc: Accumulator,
    position: u64,
    parents_before_next_node: u8,
    len: Option<u64>,
    hash: Hash,
    // TODO: too many bools
    is_eof: bool,
    is_root: bool,
}

impl Decoder2 {
    pub fn new(root_hash: &Hash) -> Self {
        Self {
            stack: ArrayVec::new(),
            acc: Accumulator::new(),
            position: 0,
            parents_before_next_node: 0,
            len: None,
            hash: *root_hash,
            is_eof: false,
            is_root: true,
        }
    }

    pub fn is_eof(&self) -> bool {
        self.is_eof
    }

    pub fn feed<'a>(&'a mut self, input: &'a [u8]) -> Result2 {
        // If we haven't parsed the header, do that.
        let len = if let Some(len) = self.len {
            len
        } else {
            return self.feed_header(input);
        };
        // Short-circuit if we've finished decoding.
        // XXX: We *must not* short-circuit in the zero length case, because
        // feed_header doesn't check the header hash. This is an easy mistake
        // to make. (Source: I made it several times, even after I knew about
        // it.) If we short-circuit zero, then the decoder will accept zero for
        // *any* hash, which is effectively a collision.
        if len > 0 && self.position > len {
            return Ok((0, &[]));
        }
        let finalization = if self.is_root {
            // TODO: doesn't handle failure well.
            self.is_root = false;
            Root(len)
        } else {
            NotRoot
        };
        // If we need to process more parent nodes, do one of those.
        if self.parents_before_next_node > 0 {
            return self.feed_parent(input, finalization);
        }
        // Otherwise do a chunk.
        self.feed_chunk(input, finalization)
    }

    fn feed_header(&mut self, input: &[u8]) -> Result2 {
        let (used, maybe_bytes) = self.acc.accumulate(input, HEADER_SIZE);
        if let Some(header_bytes) = maybe_bytes {
            let len = hash::decode_len(*array_ref!(header_bytes, 0, HEADER_SIZE));
            self.len = Some(len);
            let total_chunks = 1 + len.saturating_sub(1) / CHUNK_SIZE as u64;
            self.parents_before_next_node = tree_height(total_chunks);
        }
        Ok((used, &[]))
    }

    fn feed_parent(&mut self, input: &[u8], finalization: Finalization) -> Result2 {
        let (used, maybe_bytes) = self.acc.accumulate(input, PARENT_SIZE);
        if let Some(parent_bytes) = maybe_bytes {
            let left = array_ref!(parent_bytes, 0, HASH_SIZE);
            let right = array_ref!(parent_bytes, HASH_SIZE, HASH_SIZE);
            let found_hash = hash::parent_hash(left, right, finalization);
            if !constant_time_eq(&found_hash, &self.hash) {
                return Err(());
            }
            // If the hash was right, we've successfully parsed a node. The
            // left child becomes the new hash, and the right child goes on the
            // stack to traverse later.
            self.hash = *left;
            self.stack.push(*right);
            self.parents_before_next_node -= 1;
        }
        Ok((used, &[]))
    }

    fn feed_chunk<'a>(&'a mut self, input: &'a [u8], finalization: Finalization) -> Result2 {
        // The remaining_len can be zero, in the zero length case. Otherwise,
        // we shouldn't get here.
        let remaining_len = self.len.unwrap() - self.position;
        let remaining_chunks = 1 + remaining_len.saturating_sub(1) / CHUNK_SIZE as u64;
        let chunk_len = std::cmp::min(CHUNK_SIZE as u64, remaining_len) as usize;
        let (used, maybe_bytes) = self.acc.accumulate(input, chunk_len);
        if let Some(bytes) = maybe_bytes {
            let found_hash = hash::hash_node(bytes, finalization);
            if !constant_time_eq(&found_hash, &self.hash) {
                return Err(());
            }
            // If the hash was right, we've successfully parsed a chunk. Pop a
            // new hash off the stack if we can (if not EOF).
            if let Some(hash) = self.stack.pop() {
                self.hash = hash;
                // We know that by popping the stack, we're going to end up at
                // the top of another tree that's the same height as the one we
                // just finished. Set parents_before_next_node to reflect that.
                // TODO: This section is too complicated.
                let current_chunk_index = self.position / CHUNK_SIZE as u64;
                let next_subtree_size = std::cmp::min(
                    remaining_chunks - 1,
                    subtree_size_from_rightmost_chunk(current_chunk_index),
                );
                self.parents_before_next_node = tree_height(next_subtree_size);
                self.position += chunk_len as u64;
            } else {
                self.is_eof = true;
            }
            Ok((used, bytes))
        } else {
            Ok((used, &[]))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    HashMismatch,
    ShortInput,
    Overflow,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
enum State {
    NoHeader,
    Eof,
    Chunk(Region),
    Node(Region),
}

#[derive(Debug, Clone)]
pub struct Decoder {
    header_hash: Hash,
    header: Option<Region>,
    position: u64,
    stack: Vec<Node>,
}

impl Decoder {
    pub fn new(header_hash: &Hash) -> Self {
        Self {
            header_hash: *header_hash,
            header: None,
            position: 0,
            stack: Vec::new(),
        }
    }

    pub fn len(&self) -> Option<u64> {
        self.header.map(|h| h.len())
    }

    fn state(&self) -> State {
        let header = if let Some(region) = self.header {
            region
        } else {
            return State::NoHeader;
        };
        if self.position >= header.end {
            return State::Eof;
        }
        let current_region = if let Some(node) = self.stack.last() {
            // invariant here: the current position is inside the last node
            if node.left.contains(self.position) {
                node.left
            } else {
                node.right
            }
        } else {
            header
        };
        if current_region.len() <= CHUNK_SIZE as u64 {
            State::Chunk(current_region)
        } else {
            State::Node(current_region)
        }
    }

    pub fn seek(&mut self, position: u64) {
        // Setting the position breaks state()'s invariant, since now we might
        // be outside the bounds of the last node in the stack. We have to fix
        // it before we return.
        self.position = position;

        // If we don't have the header yet, or if we're EOF, short circuit.
        let header_end = self.header.map(|r| r.end).unwrap_or(0);
        if self.position >= header_end {
            return;
        }

        // Otherwise, pop off all nodes that don't contain the current
        // position. Note that the first node (if any) will never be popped.
        while let Some(&node) = self.stack.last() {
            if node.contains(position) {
                break;
            }
            self.stack.pop();
        }
    }

    // Give the (encoded_offset, size) needed in the next call to feed(). A
    // size of zero means EOF.
    pub fn needed(&self) -> (u64, usize) {
        match self.state() {
            State::NoHeader => (0, HEADER_SIZE),
            State::Eof => (0, 0),
            State::Chunk(r) => (r.encoded_offset, r.len() as usize),
            State::Node(r) => (r.encoded_offset, PARENT_SIZE),
        }
    }

    // Returns (consumed, output), where output is Some() when a chunk was
    // consumed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<(usize, &'a [u8])> {
        // Immediately shadow input with a wrapper type that only gives us
        // bytes when the hash is correct.
        let mut input = Unverified::wrap(input);

        match self.state() {
            State::NoHeader => self.feed_header(&mut input),
            State::Eof => Ok((0, &[])),
            State::Chunk(r) => self.feed_chunk(&mut input, r),
            State::Node(r) => self.feed_node(&mut input, r),
        }
    }

    fn feed_header<'a>(&mut self, input: &mut Unverified<'a>) -> Result<(usize, &'a [u8])> {
        // TODO: THIS IS INCORRECT (ALSO TODO IN make_root ABOVE)
        let header_bytes = input.read_verify(HEADER_SIZE, &self.header_hash)?;
        self.header = Some(Region::make_root(
            &self.header_hash,
            hash::decode_len(*array_ref!(header_bytes, 0, HEADER_SIZE)),
        ));
        Ok((HEADER_SIZE, &[]))
    }

    fn feed_chunk<'a>(
        &mut self,
        input: &mut Unverified<'a>,
        region: Region,
    ) -> Result<(usize, &'a [u8])> {
        let chunk_bytes = input.read_verify(region.len() as usize, &region.hash)?;
        // We pay attention to the `chunk_offset` for cases where a previous
        // seek() put us in the middle of the chunk. In that case, we still
        // have to verify the whole thing, but we only return the bytes after
        // the seek position. In regular reading without seeks, the chunk
        // offset will always end up being zero.
        let chunk_offset = (self.position - region.start) as usize;
        let ret = &chunk_bytes[chunk_offset..];
        // Successfully feeding a chunk moves the position foward, and pops any
        // finished nodes off the node stack. Subsequent feeds will be for the
        // following chunk.
        self.seek(region.end);
        // Note that the length of the entire chunk is returned as "consumed",
        // even in offset cases where only part of it is returned, because the
        // caller still fed the whole chunk in and still needs to advance the
        // entire chunk length forward in the encoded input.
        Ok((chunk_bytes.len() as usize, ret))
    }

    fn feed_node<'a>(
        &mut self,
        input: &mut Unverified<'a>,
        region: Region,
    ) -> Result<(usize, &'a [u8])> {
        let node_bytes = input.read_verify(PARENT_SIZE, &region.hash)?;
        let node = region.parse_node(node_bytes)?;
        self.stack.push(node);
        Ok((PARENT_SIZE, &[]))
    }
}

/// A `Region` represents some part of the content (or all of it, if it's the
/// "root region") with a given hash. If the length of the region is less than
/// or equal to the chunk size, the region's hash is simply the hash of that
/// chunk. If it's longer than a chunk, then the region is encoded as a tree,
/// and it's hash is the hash of the node at the top of that tree.
///
/// Regions also track their "encoded offset", the position in the encoding
/// where the region's chunk or node begins. Note how this is different from
/// "start" and "end", which are offsets in the *content*, not the encoding.
#[derive(Debug, Copy, Clone)]
struct Region {
    start: u64,
    end: u64,
    encoded_offset: u64,
    hash: Hash,
}

impl Region {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    fn contains(&self, position: u64) -> bool {
        self.start <= position && position < self.end
    }

    // TODO: HANDLE THE ROOT NODE'S HASH DIFFERENCES
    fn make_root(hash: &Hash, len: u64) -> Region {
        Region {
            start: 0,
            end: len,
            encoded_offset: HEADER_SIZE as u64,
            hash: *hash,
        }
    }

    /// Splits the current region into two subregions, with the key logic
    /// happening in `hash::left_len`. If calculating the new `encoded_offset`
    /// overflows, return `None`.
    fn parse_node(&self, bytes: &[u8]) -> Result<Node> {
        let left = Region {
            start: self.start,
            end: self.start + hash::left_len(self.len()),
            encoded_offset: checked_add(self.encoded_offset, PARENT_SIZE as u64)?,
            hash: *array_ref!(bytes, 0, HASH_SIZE),
        };
        let right = Region {
            start: left.end,
            end: self.end,
            encoded_offset: checked_add(left.encoded_offset, encoded_len(left.len())?)?,
            hash: *array_ref!(bytes, HASH_SIZE, HASH_SIZE),
        };
        Ok(Node { left, right })
    }
}

#[derive(Debug, Copy, Clone)]
struct Node {
    left: Region,
    right: Region,
}

impl Node {
    fn contains(&self, position: u64) -> bool {
        self.left.start <= position && position < self.right.end
    }
}

/// Computing the encoded length of a region is surprisingly cheap. All binary
/// trees have a useful property: as long as all interior nodes have exactly two
/// children (ours do), the number of nodes is always equal to the
/// number of leaves minus one. Because we require all the leaves in our tree
/// to be full chunks (except the last one), we only need to divide by the
/// chunk size, which in practice is just a bitshift.
///
/// Note that a complete encoded file is both the encoded "root region", and
/// the bytes of the header itself, which aren't accounted for here.
///
/// Because the encoded len is longer than the input length, it can overflow
/// for very large inputs. In that case, we return `Err(Overflow)`.
fn encoded_len(region_len: u64) -> Result<u64> {
    // Divide rounding up to get the number of chunks.
    let num_chunks = (region_len / CHUNK_SIZE as u64) + (region_len % CHUNK_SIZE as u64 > 0) as u64;
    // The number of nodes is one less, but not less than zero.
    let num_nodes = num_chunks.saturating_sub(1);
    // `all_nodes` can't overflow by itself unless the node size is larger
    // than the chunk size, which would be pathological, but whatever :p
    checked_add(checked_mul(num_nodes, PARENT_SIZE as u64)?, region_len)
}

fn checked_add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(Error::Overflow)
}

fn checked_mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or(Error::Overflow)
}

#[cfg(test)]
mod test {
    use super::*;
    use encode::encode;

    #[test]
    fn test_tree_height() {
        let cases = [
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 3),
            (7, 3),
            (8, 3),
            (9, 4),
            (16, 4),
            (17, 5),
        ];
        for &(num_chunks, height) in cases.iter() {
            assert_eq!(
                height,
                tree_height(num_chunks),
                "bad height for {} chunks",
                num_chunks,
            );
        }
    }

    #[test]
    fn test_subtree_size_from_rightmost_chunk() {
        let cases = [
            (0, 1),
            (1, 2),
            (2, 1),
            (3, 4),
            (4, 1),
            (5, 2),
            (6, 1),
            (7, 8),
            (8, 1),
            (9, 2),
            (15, 16),
            (31, 32),
        ];
        for &(chunk_index, size) in cases.iter() {
            assert_eq!(
                size,
                subtree_size_from_rightmost_chunk(chunk_index),
                "bad size for index {}",
                chunk_index,
            );
        }
    }

    #[test]
    fn test_accumulator() {
        let mut acc = Accumulator::new();
        {
            // Writes smaller than the target length return no output.
            let (used, output) = acc.accumulate(&[0; 50], 100);
            assert_eq!(50, used);
            assert_eq!(None, output);
        }
        {
            // A big write takes just enough bytes to fill the buffer, and then
            // returns the result.
            let (used, maybe_output) = acc.accumulate(&[0; 999], 100);
            assert_eq!(50, used);
            let output = maybe_output.unwrap();
            assert_eq!(&[0; 100][..], output);
        }
        {
            // A big write when the buffer is empty will return a pointer
            // directly from the input.
            let input = &[0; 999];
            let (used, maybe_output) = acc.accumulate(input, 100);
            assert_eq!(100, used);
            let output = maybe_output.unwrap();
            assert_eq!(&[0; 100][..], output);
            assert_eq!(
                input.as_ptr(),
                output.as_ptr(),
                "pointer doesn't come from input"
            );
        }
    }

    #[test]
    fn test_decode() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = vec![0; case];
            let (hash, encoded) = encode(&input);
            let decoded = decode(&encoded, &hash).expect("decode error");
            assert_eq!(input, decoded, "decoded doesn't match input");
        }
    }

    //     extern crate rand;
    //     use self::rand::Rng;

    //     use super::*;
    //     use simple::encode;
    //     use hash::TEST_CASES;

    //     #[test]
    //     fn test_encoded_len() {
    //         for &case in TEST_CASES {
    //             let found_len = encode(&vec![0; case]).0.len() as u64;
    //             let computed_len = encoded_len(case as u64).unwrap() + HEADER_SIZE as u64;
    //             assert_eq!(found_len, computed_len, "wrong length in case {}", case);
    //         }
    //     }

    //     #[test]
    //     fn test_decoder() {
    //         // This simulates a writer who supplies exactly what's asked for by
    //         // needed(), until EOF.
    //         for &case in TEST_CASES {
    //             println!("\n>>>>> starting case {}", case);
    //             let input = vec![0x72; case];
    //             let (encoded, hash) = encode(&input);
    //             println!("encoded.len() {}", encoded.len());
    //             let mut decoder = Decoder::new(&hash);
    //             let mut output = Vec::new();
    //             loop {
    //                 let (offset, len) = decoder.needed();
    //                 println!("needed: {}, {}", offset, len);
    //                 if len == 0 {
    //                     break;
    //                 }
    //                 let encoded_input = &encoded[offset as usize..offset as usize + len];
    //                 let (consumed, out_slice) = decoder.feed(encoded_input).unwrap();
    //                 println!("consumed: {} (gave output: {})", consumed, output.len());
    //                 assert_eq!(consumed, len);
    //                 output.extend_from_slice(out_slice);
    //             }
    //             assert_eq!(input, output);
    //         }
    //     }

    //     fn decode_all(mut encoded: &[u8], hash: &Hash) -> Result<Vec<u8>> {
    //         let mut decoder = Decoder::new(&hash);
    //         let mut output = Vec::new();
    //         loop {
    //             let (_, len) = decoder.needed();
    //             if len == 0 {
    //                 return Ok(output);
    //             }
    //             let (consumed, out_slice) = decoder.feed(encoded)?;
    //             output.extend_from_slice(out_slice);
    //             encoded = &encoded[consumed..];
    //         }
    //     }

    //     #[test]
    //     fn test_decoder_corrupted() {
    //         // Similar to test_simple_corrupted. We flip bits and make things stop
    //         // working.
    //         for &case in TEST_CASES {
    //             println!("\n>>>>> starting case {}", case);
    //             let input = vec![0x72; case];
    //             let (encoded, hash) = encode(&input);
    //             println!("encoded lenth {}", encoded.len());
    //             for &tweak_case in TEST_CASES {
    //                 if tweak_case >= encoded.len() {
    //                     continue;
    //                 }
    //                 println!("tweak case {}", tweak_case);
    //                 let mut corrupted = encoded.clone();
    //                 corrupted[tweak_case] ^= 1;
    //                 assert_eq!(
    //                     decode_all(&corrupted, &hash).unwrap_err(),
    //                     Error::HashMismatch
    //                 );
    //                 // But make sure it does work without the tweak.
    //                 decode_all(&encoded, &hash).unwrap();
    //             }
    //         }
    //     }

    //     #[test]
    //     fn test_decoder_overfeed() {
    //         // This simulates a writer who doesn't even call needed(), and instead
    //         // just feeds everything into every call to seek(), bumping the start
    //         // forward as bytes are consumed.
    //         for &case in TEST_CASES {
    //             let input = vec![0x72; case];
    //             let (encoded, hash) = encode(&input);
    //             let mut decoder = Decoder::new(&hash);
    //             let mut output = Vec::new();
    //             let mut encoded_input = &encoded[..];
    //             loop {
    //                 let (consumed, out_slice) = decoder.feed(encoded_input).unwrap();
    //                 if consumed == 0 {
    //                     break;
    //                 }
    //                 output.extend_from_slice(out_slice);
    //                 encoded_input = &encoded_input[consumed..]
    //             }
    //             assert_eq!(input, output);
    //         }
    //     }

    //     #[test]
    //     fn test_decoder_feed_by_ones() {
    //         // This simulates a writer who tries to feed small amounts, making the
    //         // amount larger with each failure until things succeed.
    //         let input = vec![0; 4 * CHUNK_SIZE + 1];
    //         let (encoded, hash) = encode(&input);
    //         let mut decoder = Decoder::new(&hash);
    //         let mut encoded_slice = &encoded[..];
    //         let mut output = Vec::new();
    //         let mut feed_len = 0;
    //         loop {
    //             match decoder.feed(&encoded_slice[..feed_len]) {
    //                 Ok((consumed, out_slice)) => {
    //                     if consumed == 0 {
    //                         // Note that this EOF will happen after the last
    //                         // successful feed, when we attempt to feed 0 bytes
    //                         // again. If we reset feed_len to anything other than
    //                         // zero, we'd end up slicing out of bounds.
    //                         break;
    //                     }
    //                     output.extend_from_slice(out_slice);
    //                     encoded_slice = &encoded_slice[consumed..];
    //                     feed_len = 0;
    //                 }
    //                 Err(Error::ShortInput) => {
    //                     // Keep bumping the feed length until we succeed.
    //                     feed_len += 1;
    //                 }
    //                 e => panic!("unexpected error: {:?}", e),
    //             }
    //         }
    //     }

    //     #[test]
    //     fn test_decoder_seek() {
    //         for &case in TEST_CASES {
    //             println!("\n>>>>> case {}", case);
    //             // Use pseudorandom input, so that slices from different places are
    //             // very likely not to match.
    //             let input: Vec<u8> = rand::ChaChaRng::new_unseeded()
    //                 .gen_iter()
    //                 .take(case)
    //                 .collect();
    //             let (encoded, hash) = encode(&input);
    //             for &seek_case in TEST_CASES {
    //                 if seek_case > case {
    //                     continue;
    //                 }
    //                 println!(">>> seek case {}", seek_case);
    //                 let mut decoder = Decoder::new(&hash);
    //                 decoder.seek(seek_case as u64);
    //                 // Read the rest of the output and confirm it matches the input
    //                 // slice at the same offset.
    //                 let mut output = Vec::new();
    //                 loop {
    //                     let (offset, len) = decoder.needed();
    //                     if len == 0 {
    //                         break;
    //                     }
    //                     let encoded_input = &encoded[offset as usize..offset as usize + len];
    //                     let (_, out_slice) = decoder.feed(encoded_input).unwrap();
    //                     output.extend_from_slice(out_slice);
    //                 }
    //                 let expected = &input[seek_case..];
    //                 assert_eq!(expected, &output[..]);
    //             }
    //         }
    //     }

    //     // Tested in both simple.rs and decode.rs.
    //     #[test]
    //     fn test_short_header_fails() {
    //         // A permissive decoder might allow 7 null bytes to be zero just like 8
    //         // null bytes would be. That would be a bug, and a security bug at
    //         // that. The hash of 7 nulls isn't the same as the hash of 8, and it's
    //         // crucial that a given input has a unique hash.
    //         let encoded = vec![0; 7];
    //         let hash = ::hash(&encoded);
    //         assert_eq!(decode_all(&encoded, &hash).unwrap_err(), Error::ShortInput);
    //     }
}
