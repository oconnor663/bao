use arrayvec::ArrayVec;
use blake2b_simd;
use copy_in_place::copy_in_place;
use core::cmp;
use core::fmt;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, PARENT_SIZE};
#[cfg(feature = "std")]
use rayon;
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::prelude::*;
#[cfg(feature = "std")]
use std::io::SeekFrom::{End, Start};

pub fn encode(input: &[u8], output: &mut [u8]) -> Hash {
    let content_len = input.len() as u64;
    assert_eq!(
        output.len() as u128,
        encoded_size(content_len),
        "output is the wrong length"
    );
    output[..HEADER_SIZE].copy_from_slice(&hash::encode_len(content_len));
    #[cfg(feature = "std")]
    {
        if input.len() <= hash::MAX_SINGLE_THREADED {
            encode_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
        } else {
            encode_recurse_rayon(input, &mut output[HEADER_SIZE..], Root(content_len))
        }
    }
    #[cfg(not(feature = "std"))]
    {
        encode_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
    }
}

/// `buf` must be exactly `encoded_size(content_len)`. This is slower than `encode`, because only
/// the hashing can be done in parallel. All the memmoves have to be done in series.
pub fn encode_in_place(buf: &mut [u8], content_len: usize) -> Hash {
    // Note that if you change anything in this function, you should probably
    // also update benchmarks::encode_in_place_fake.
    assert_eq!(
        buf.len() as u128,
        encoded_size(content_len as u64),
        "buf is the wrong length"
    );
    layout_chunks_in_place(buf, 0, HEADER_SIZE, content_len);
    let (header, rest) = buf.split_at_mut(HEADER_SIZE);
    header.copy_from_slice(&hash::encode_len(content_len as u64));
    #[cfg(feature = "std")]
    {
        if content_len <= hash::MAX_SINGLE_THREADED {
            write_parents_in_place(rest, content_len, Root(content_len as u64))
        } else {
            write_parents_in_place_rayon(rest, content_len, Root(content_len as u64))
        }
    }
    #[cfg(not(feature = "std"))]
    {
        write_parents_in_place(rest, content_len, Root(content_len as u64))
    }
}

pub fn encode_outboard(input: &[u8], output: &mut [u8]) -> Hash {
    let content_len = input.len() as u64;
    assert_eq!(
        output.len() as u128,
        outboard_size(content_len),
        "output is the wrong length"
    );
    output[..HEADER_SIZE].copy_from_slice(&hash::encode_len(content_len));
    #[cfg(feature = "std")]
    {
        if input.len() <= hash::MAX_SINGLE_THREADED {
            encode_outboard_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
        } else {
            encode_outboard_recurse_rayon(input, &mut output[HEADER_SIZE..], Root(content_len))
        }
    }
    #[cfg(not(feature = "std"))]
    {
        encode_outboard_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
    }
}

#[cfg(feature = "std")]
pub fn encode_to_vec(input: &[u8]) -> (Hash, Vec<u8>) {
    let size = encoded_size(input.len() as u64) as usize;
    // Unsafe code here could avoid the cost of initialization, but it's not much.
    let mut output = vec![0; size];
    let hash = encode(input, &mut output);
    (hash, output)
}

#[cfg(feature = "std")]
pub fn encode_outboard_to_vec(input: &[u8]) -> (Hash, Vec<u8>) {
    let size = outboard_size(input.len() as u64) as usize;
    let mut output = vec![0; size];
    let hash = encode_outboard(input, &mut output);
    (hash, output)
}

fn encode_recurse(input: &[u8], output: &mut [u8], finalization: Finalization) -> Hash {
    debug_assert_eq!(
        output.len() as u128,
        encoded_subtree_size(input.len() as u64)
    );
    if input.len() <= CHUNK_SIZE {
        output.copy_from_slice(input);
        return hash::hash_node(input, finalization);
    }
    let left_len = hash::left_len(input.len() as u64);
    let (left_in, right_in) = input.split_at(left_len as usize);
    let (parent_out, rest) = output.split_at_mut(PARENT_SIZE);
    let (left_out, right_out) = rest.split_at_mut(encoded_subtree_size(left_len) as usize);
    let left_hash = encode_recurse(left_in, left_out, NotRoot);
    let right_hash = encode_recurse(right_in, right_out, NotRoot);
    parent_out[..HASH_SIZE].copy_from_slice(&left_hash);
    parent_out[HASH_SIZE..].copy_from_slice(&right_hash);
    hash::parent_hash(&left_hash, &right_hash, finalization)
}

#[cfg(feature = "std")]
fn encode_recurse_rayon(input: &[u8], output: &mut [u8], finalization: Finalization) -> Hash {
    debug_assert_eq!(
        output.len() as u128,
        encoded_subtree_size(input.len() as u64)
    );
    if input.len() <= CHUNK_SIZE {
        output.copy_from_slice(input);
        return hash::hash_node(input, finalization);
    }
    let left_len = hash::left_len(input.len() as u64);
    let (left_in, right_in) = input.split_at(left_len as usize);
    let (parent_out, rest) = output.split_at_mut(PARENT_SIZE);
    let (left_out, right_out) = rest.split_at_mut(encoded_subtree_size(left_len) as usize);
    let (left_hash, right_hash) = rayon::join(
        || encode_recurse_rayon(left_in, left_out, NotRoot),
        || encode_recurse_rayon(right_in, right_out, NotRoot),
    );
    parent_out[..HASH_SIZE].copy_from_slice(&left_hash);
    parent_out[HASH_SIZE..].copy_from_slice(&right_hash);
    hash::parent_hash(&left_hash, &right_hash, finalization)
}

fn encode_outboard_recurse(input: &[u8], output: &mut [u8], finalization: Finalization) -> Hash {
    debug_assert_eq!(
        output.len() as u128,
        outboard_subtree_size(input.len() as u64)
    );
    if input.len() <= CHUNK_SIZE {
        return hash::hash_node(input, finalization);
    }
    let left_len = hash::left_len(input.len() as u64);
    let (left_in, right_in) = input.split_at(left_len as usize);
    let (parent_out, rest) = output.split_at_mut(PARENT_SIZE);
    let (left_out, right_out) = rest.split_at_mut(outboard_subtree_size(left_len) as usize);
    let left_hash = encode_outboard_recurse(left_in, left_out, NotRoot);
    let right_hash = encode_outboard_recurse(right_in, right_out, NotRoot);
    parent_out[..HASH_SIZE].copy_from_slice(&left_hash);
    parent_out[HASH_SIZE..].copy_from_slice(&right_hash);
    hash::parent_hash(&left_hash, &right_hash, finalization)
}

#[cfg(feature = "std")]
fn encode_outboard_recurse_rayon(
    input: &[u8],
    output: &mut [u8],
    finalization: Finalization,
) -> Hash {
    debug_assert_eq!(
        output.len() as u128,
        outboard_subtree_size(input.len() as u64)
    );
    if input.len() <= CHUNK_SIZE {
        return hash::hash_node(input, finalization);
    }
    let left_len = hash::left_len(input.len() as u64);
    let (left_in, right_in) = input.split_at(left_len as usize);
    let (parent_out, rest) = output.split_at_mut(PARENT_SIZE);
    let (left_out, right_out) = rest.split_at_mut(outboard_subtree_size(left_len) as usize);
    let (left_hash, right_hash) = rayon::join(
        || encode_outboard_recurse_rayon(left_in, left_out, NotRoot),
        || encode_outboard_recurse_rayon(right_in, right_out, NotRoot),
    );
    parent_out[..HASH_SIZE].copy_from_slice(&left_hash);
    parent_out[HASH_SIZE..].copy_from_slice(&right_hash);
    hash::parent_hash(&left_hash, &right_hash, finalization)
}

// This function doesn't check for adequate space. Its caller should check.
fn layout_chunks_in_place(
    buf: &mut [u8],
    read_offset: usize,
    write_offset: usize,
    content_len: usize,
) {
    if content_len <= CHUNK_SIZE {
        copy_in_place(buf, read_offset..read_offset + content_len, write_offset);
    } else {
        let left_len = hash::left_len(content_len as u64) as usize;
        let left_write_offset = write_offset + PARENT_SIZE;
        let right_len = content_len - left_len;
        let right_read_offset = read_offset + left_len;
        let right_write_offset = left_write_offset + encoded_subtree_size(left_len as u64) as usize;
        // Encoding the left side will overwrite some of the space occupied by the right, so do the
        // right side first.
        layout_chunks_in_place(buf, right_read_offset, right_write_offset, right_len);
        layout_chunks_in_place(buf, read_offset, left_write_offset, left_len);
    }
}

// This function doesn't check for adequate space. Its caller should check.
fn write_parents_in_place(buf: &mut [u8], content_len: usize, finalization: Finalization) -> Hash {
    if content_len <= CHUNK_SIZE {
        debug_assert_eq!(content_len, buf.len());
        hash::hash_node(buf, finalization)
    } else {
        let left_len = hash::left_len(content_len as u64) as usize;
        let right_len = content_len - left_len;
        let split = encoded_subtree_size(left_len as u64) as usize;
        let (parent, rest) = buf.split_at_mut(PARENT_SIZE);
        let (left_slice, right_slice) = rest.split_at_mut(split);
        let left_hash = write_parents_in_place(left_slice, left_len, NotRoot);
        let right_hash = write_parents_in_place(right_slice, right_len, NotRoot);
        *array_mut_ref!(parent, 0, HASH_SIZE) = left_hash;
        *array_mut_ref!(parent, HASH_SIZE, HASH_SIZE) = right_hash;
        hash::parent_hash(&left_hash, &right_hash, finalization)
    }
}

// This function doesn't check for adequate space. Its caller should check.
#[cfg(feature = "std")]
fn write_parents_in_place_rayon(
    buf: &mut [u8],
    content_len: usize,
    finalization: Finalization,
) -> Hash {
    if content_len <= CHUNK_SIZE {
        debug_assert_eq!(content_len, buf.len());
        hash::hash_node(buf, finalization)
    } else {
        let left_len = hash::left_len(content_len as u64) as usize;
        let right_len = content_len - left_len;
        let split = encoded_subtree_size(left_len as u64) as usize;
        let (parent, rest) = buf.split_at_mut(PARENT_SIZE);
        let (left_slice, right_slice) = rest.split_at_mut(split);
        let (left_hash, right_hash) = rayon::join(
            || write_parents_in_place_rayon(left_slice, left_len, NotRoot),
            || write_parents_in_place_rayon(right_slice, right_len, NotRoot),
        );
        *array_mut_ref!(parent, 0, HASH_SIZE) = left_hash;
        *array_mut_ref!(parent, HASH_SIZE, HASH_SIZE) = right_hash;
        hash::parent_hash(&left_hash, &right_hash, finalization)
    }
}

pub fn encoded_size(content_len: u64) -> u128 {
    content_len as u128 + outboard_size(content_len)
}

// Should the return type here really by u128? Two reasons: 1) It's convenient to use the same type
// as encoded_size(), and 2) if we're ever experimenting with very small chunk sizes, we could
// indeed overflow u64.
pub fn outboard_size(content_len: u64) -> u128 {
    outboard_subtree_size(content_len) + HEADER_SIZE as u128
}

pub(crate) fn encoded_subtree_size(content_len: u64) -> u128 {
    content_len as u128 + outboard_subtree_size(content_len)
}

pub(crate) fn outboard_subtree_size(content_len: u64) -> u128 {
    // The number of parent nodes is always the number of chunks minus one. To see why this is true,
    // start with a single chunk and incrementally add chunks to the tree. Each new chunk always
    // brings one parent node along with it.
    let num_parents = count_chunks(content_len) - 1;
    num_parents as u128 * PARENT_SIZE as u128
}

pub(crate) fn count_chunks(content_len: u64) -> u64 {
    // Two things to watch out for here: the 0-length input still counts as 1 chunk, and we don't
    // want to overflow when content_len is u64::MAX_VALUE.
    let full_chunks: u64 = content_len / CHUNK_SIZE as u64;
    let has_partial_chunk: bool = (content_len % CHUNK_SIZE as u64) != 0;
    cmp::max(1, full_chunks + has_partial_chunk as u64)
}

pub(crate) fn chunk_size(chunk: u64, content_len: u64) -> usize {
    let chunk_start = chunk * CHUNK_SIZE as u64;
    cmp::min(CHUNK_SIZE, (content_len - chunk_start) as usize)
}

/// Prior to the final chunk, to calculate the number of post-order parent nodes for a chunk, we
/// need to know the height of the subtree for which the chunk is the rightmost. This is the same as
/// the number of trailing ones in the chunk index (counting from 0). For example, chunk number 11
/// (0b1011) has two trailing parent nodes.
///
/// Note that this is closely related to the trick we're using in hash::State::needs_merge. The
/// number of trailing zeroes at a given index is the same as the number of ones that switched off
/// when we moved rightward from the previous index.
fn post_order_parent_nodes_nonfinal(chunk: u64) -> u8 {
    (!chunk).trailing_zeros() as u8
}

/// The final chunk of a post order tree has to have a parent node for each of the not yet merged
/// subtrees behind it. This is the same as the total number of ones in the chunk index (counting
/// from 0).
fn post_order_parent_nodes_final(chunk: u64) -> u8 {
    chunk.count_ones() as u8
}

/// In pre-order there are a couple considerations for counting the number of parent nodes:
///
/// - The number of parents for the first chunk in a tree, is equal to the bit length of the index
///   of the final chunk (counting from 0). For example, a tree of 16 chunks (final chunk index 15
///   or 0b1111) has 4 leading parent nodes, while a tree of 17 chunks has 5.
/// - In the interior of the tree -- ignoring the chunks near the end for a moment -- the number of
///   parent nodes is the height of the tree for which the given chunk is the leftmost. This is
///   equal to the number of trailing zeros in the chunk index. This ends up being similar to the
///   post_order_parent_nodes_nonfinal calculation above, except offset by one.
///
/// Unlike the post-order logic above, where all the subtrees we're looking at before the final
/// chunk are complete, the pre-order case has to account for partial subtrees. For example, chunk 4
/// would normally (in any tree of 8 or more chunks) be the start of a subtree of size 4 and height
/// 2. However, if the tree has a total of 7 chunks, then the subtree starting at chunk 4 is only of
/// size 3. And if the tree has a total of 5 chunks, then chunk 4 is the final chunk and the only
/// chunk in its subtree.
///
/// To account for this, for every chunk after the first, we take the minimum of both rules, with
/// respect to the number of chunks *remaining*. For example, in the 7 chunk tree, chunk 4 starts a
/// subtree of the 3 remaining chunks. That means it still has 2 parent nodes, because a 3 chunk
/// tree is still of height 2. But in the 5 chunk tree, chunk 4 has no parent nodes at all, because
/// a 1 chunk tree is of height 0.
pub(crate) fn pre_order_parent_nodes(chunk: u64, content_len: u64) -> u8 {
    let total_chunks = count_chunks(content_len);
    debug_assert!(
        chunk < total_chunks,
        "attempted to count parent nodes after EOF"
    );
    let remaining = total_chunks - chunk;
    let starting_bound = 64 - (remaining - 1).leading_zeros();
    let interior_bound = chunk.trailing_zeros();
    cmp::min(starting_bound, interior_bound) as u8
}

#[derive(Clone)]
struct FlipperState {
    parents: ArrayVec<[hash::ParentNode; hash::MAX_DEPTH]>,
    content_len: u64,
    chunk_moved: u64,
    parents_needed: u8,
    parents_available: u8,
}

impl FlipperState {
    pub fn new(content_len: u64) -> Self {
        let total_chunks = count_chunks(content_len);
        Self {
            parents: ArrayVec::new(),
            content_len,
            chunk_moved: total_chunks,
            parents_needed: post_order_parent_nodes_final(total_chunks - 1),
            parents_available: 0,
        }
    }

    pub fn next(&self) -> FlipperNext {
        // chunk_moved() adds both the parents_available for the chunk just moved and the
        // parents_needed for the chunk to its left, so we have to do TakeParent first.
        if self.parents_available > 0 {
            FlipperNext::TakeParent
        } else if self.parents_needed > 0 {
            FlipperNext::FeedParent
        } else if self.chunk_moved > 0 {
            FlipperNext::Chunk(chunk_size(self.chunk_moved - 1, self.content_len))
        } else {
            FlipperNext::Done
        }
    }

    pub fn chunk_moved(&mut self) {
        // Add the pre-order parents available for the chunk that just moved and the post-order
        // parents needed for the chunk to its left.
        debug_assert!(self.chunk_moved > 0);
        debug_assert_eq!(self.parents_available, 0);
        debug_assert_eq!(self.parents_needed, 0);
        self.chunk_moved -= 1;
        self.parents_available = pre_order_parent_nodes(self.chunk_moved, self.content_len);
        if self.chunk_moved > 0 {
            self.parents_needed = post_order_parent_nodes_nonfinal(self.chunk_moved - 1);
        }
    }

    pub fn feed_parent(&mut self, parent: hash::ParentNode) {
        debug_assert!(self.chunk_moved > 0);
        debug_assert_eq!(self.parents_available, 0);
        debug_assert!(self.parents_needed > 0);
        self.parents_needed -= 1;
        self.parents.push(parent);
    }

    pub fn take_parent(&mut self) -> hash::ParentNode {
        debug_assert!(self.parents_available > 0);
        self.parents_available -= 1;
        self.parents.pop().expect("took too many parents")
    }
}

impl fmt::Debug for FlipperState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FlipperState {{ parents: {}, content_len: {}, chunk_moved: {}, parents_needed: {}, parents_available: {} }}",
               self.parents.len(), self.content_len, self.chunk_moved, self.parents_needed, self.parents_available)
    }
}

#[derive(Clone, Copy, Debug)]
enum FlipperNext {
    FeedParent,
    TakeParent,
    Chunk(usize),
    Done,
}

/// Most callers should use this writer for incremental encoding. The writer makes no attempt to
/// recover from IO errors, so callers that want to retry should start from the beginning with a new
/// writer.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct Writer<T: Read + Write + Seek> {
    inner: T,
    total_len: u64,
    chunk_state: blake2b_simd::State,
    tree_state: hash::State,
    outboard: bool,
}

#[cfg(feature = "std")]
impl<T: Read + Write + Seek> Writer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            total_len: 0,
            chunk_state: hash::new_blake2b_state(),
            tree_state: hash::State::new(),
            outboard: false,
        }
    }

    pub fn new_outboard(inner: T) -> Self {
        let mut writer = Self::new(inner);
        writer.outboard = true;
        writer
    }

    pub fn finish(&mut self) -> io::Result<Hash> {
        // First finish the post-order encoding.
        let root_hash;
        if self.total_len <= CHUNK_SIZE as u64 {
            root_hash = hash::finalize_hash(&mut self.chunk_state, Root(self.total_len));
        } else {
            let chunk_hash = hash::finalize_hash(&mut self.chunk_state, NotRoot);
            self.tree_state
                .push_subtree(&chunk_hash, self.chunk_state.count() as usize);
            loop {
                match self.tree_state.merge_finish() {
                    hash::StateFinish::Parent(parent) => self.inner.write_all(&parent)?,
                    hash::StateFinish::Root(root) => {
                        root_hash = root;
                        break;
                    }
                }
            }
        }
        self.inner.write_all(&hash::encode_len(self.total_len))?;

        // Then flip the tree to be pre-order.
        self.flip_post_order_stream()?;

        Ok(root_hash)
    }

    fn flip_post_order_stream(&mut self) -> io::Result<()> {
        let mut write_cursor = self.inner.seek(End(0))?;
        let mut read_cursor = write_cursor - HEADER_SIZE as u64;
        let mut header = [0; HEADER_SIZE];
        self.inner.seek(Start(read_cursor))?;
        self.inner.read_exact(&mut header)?;
        let content_len = hash::decode_len(&header);
        let mut flipper = FlipperState::new(content_len);
        loop {
            match flipper.next() {
                FlipperNext::FeedParent => {
                    let mut parent = [0; PARENT_SIZE];
                    self.inner.seek(Start(read_cursor - PARENT_SIZE as u64))?;
                    self.inner.read_exact(&mut parent)?;
                    read_cursor -= PARENT_SIZE as u64;
                    flipper.feed_parent(parent);
                }
                FlipperNext::TakeParent => {
                    let parent = flipper.take_parent();
                    self.inner.seek(Start(write_cursor - PARENT_SIZE as u64))?;
                    self.inner.write_all(&parent)?;
                    write_cursor -= PARENT_SIZE as u64;
                }
                FlipperNext::Chunk(size) => {
                    // In outboard moded, we skip over chunks.
                    if !self.outboard {
                        let mut chunk = [0; CHUNK_SIZE];
                        self.inner.seek(Start(read_cursor - size as u64))?;
                        self.inner.read_exact(&mut chunk[..size])?;
                        read_cursor -= size as u64;
                        self.inner.seek(Start(write_cursor - size as u64))?;
                        self.inner.write_all(&chunk[..size])?;
                        write_cursor -= size as u64;
                    }
                    flipper.chunk_moved();
                }
                FlipperNext::Done => {
                    debug_assert_eq!(HEADER_SIZE as u64, write_cursor);
                    self.inner.seek(Start(0))?;
                    self.inner.write_all(&header)?;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<T: Read + Write + Seek> Write for Writer<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            // Without more bytes coming, we're not sure how to finalize.
            return Ok(0);
        }
        if self.chunk_state.count() as usize == CHUNK_SIZE {
            let chunk_hash = hash::finalize_hash(&mut self.chunk_state, NotRoot);
            self.chunk_state = hash::new_blake2b_state();
            self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            while let Some(parent) = self.tree_state.merge_parent() {
                self.inner.write_all(&parent)?;
            }
        }
        let want = CHUNK_SIZE - self.chunk_state.count() as usize;
        let take = cmp::min(want, buf.len());
        // The outboard mode skips writing content to the stream.
        let written = if self.outboard {
            take
        } else {
            self.inner.write(&buf[..take])?
        };
        self.chunk_state.update(&buf[..written]);
        self.total_len += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// This is in its own module to enforce privacy. For example, callers should only ever read
// content_len by calling len_next().
use self::parse_state::StateNext;
pub(crate) mod parse_state {
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
            self.upcoming_parents = pre_order_parent_nodes(0, self.content_len.unwrap());
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
                LenNext::Len(len) => self.next_chunk >= count_chunks(len),
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
                    size: chunk_size(self.next_chunk, content_len),
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
                self.encoded_offset += encoded_subtree_size(self.subtree_size());
                maybe_seek_offset = Some(self.encoded_offset);
                self.next_chunk += count_chunks(self.subtree_size());
                if !self.is_eof() {
                    // upcoming_parents is only meaningful if we're before EOF.
                    self.upcoming_parents = pre_order_parent_nodes(self.next_chunk, content_len);
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
                    pre_order_parent_nodes(self.next_chunk, self.content_len.unwrap());
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
}

#[cfg(feature = "std")]
pub struct SliceExtractor<T: Read + Seek, O: Read + Seek> {
    input: T,
    outboard: Option<O>,
    slice_start: u64,
    slice_len: u64,
    slice_bytes_read: u64,
    previous_chunk_size: usize,
    parser: parse_state::ParseState,
    buf: [u8; CHUNK_SIZE],
    buf_start: usize,
    buf_end: usize,
    seek_done: bool,
}

#[cfg(feature = "std")]
impl<T: Read + Seek> SliceExtractor<T, T> {
    pub fn new(input: T, slice_start: u64, slice_len: u64) -> Self {
        // TODO: normalize zero-length slices?
        Self::new_inner(input, None, slice_start, slice_len)
    }
}

#[cfg(feature = "std")]
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
            parser: parse_state::ParseState::new(),
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

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
pub(crate) fn cast_offset(offset: u128) -> io::Result<u64> {
    if offset > u64::max_value() as u128 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "seek offset overflowed u64",
        ))
    } else {
        Ok(offset as u64)
    }
}

#[cfg(test)]
mod test {
    extern crate tempfile;

    use super::*;
    use decode::make_test_input;
    use std::io::Cursor;

    #[test]
    fn test_encoded_size() {
        for &case in hash::TEST_CASES {
            let input = make_test_input(case);
            let (_, encoded) = encode_to_vec(&input);
            assert_eq!(encoded.len() as u128, encoded_size(case as u64));
            assert_eq!(encoded.len(), encoded.capacity());
            assert_eq!(
                encoded.len() as u128,
                case as u128 + outboard_size(case as u64)
            );
        }
    }

    #[cfg(feature = "python")]
    #[test]
    fn compare_encoded_to_python() {
        for &case in hash::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![9; case];
            let (_, encoded) = encode_to_vec(&input);
            let output = cmd!("python3", "./test/bao.py", "encode", "-", "-")
                .input(input)
                .stdout_capture()
                .run()
                .unwrap();
            assert_eq!(output.stdout, encoded, "encoded mismatch");
        }
    }

    #[test]
    fn test_encode() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = hash::hash(&input);
            let (to_vec_hash, output) = encode_to_vec(&input);
            assert_eq!(expected_hash, to_vec_hash);

            let mut serial_output = vec![0; encoded_subtree_size(case as u64) as usize];
            let serial_hash = encode_recurse(&input, &mut serial_output, Root(case as u64));
            assert_eq!(expected_hash, serial_hash);
            assert_eq!(&output[HEADER_SIZE..], &*serial_output);

            let mut parallel_output = vec![0; encoded_subtree_size(case as u64) as usize];
            let parallel_hash =
                encode_recurse_rayon(&input, &mut parallel_output, Root(case as u64));
            assert_eq!(expected_hash, parallel_hash);
            assert_eq!(&output[HEADER_SIZE..], &*parallel_output);

            let mut highlevel_output = vec![0; encoded_size(case as u64) as usize];
            let highlevel_hash = encode(&input, &mut highlevel_output);
            assert_eq!(expected_hash, highlevel_hash);
            assert_eq!(output, highlevel_output);

            let mut highlevel_in_place_output = input.clone();
            highlevel_in_place_output.resize(encoded_size(case as u64) as usize, 0);
            let highlevel_in_place_hash = encode_in_place(&mut highlevel_in_place_output, case);
            assert_eq!(expected_hash, highlevel_in_place_hash);
            assert_eq!(output, highlevel_in_place_output);

            let mut writer_output = Vec::new();
            {
                let mut writer = Writer::new(Cursor::new(&mut writer_output));
                writer.write_all(&input).unwrap();
                let writer_hash = writer.finish().unwrap();
                assert_eq!(expected_hash, writer_hash);
            }
            assert_eq!(output, writer_output);
        }
    }

    #[test]
    fn test_outboard_encode() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = hash::hash(&input);
            let (to_vec_hash, outboard) = encode_outboard_to_vec(&input);
            assert_eq!(expected_hash, to_vec_hash);

            let mut serial_output = vec![0; outboard_subtree_size(case as u64) as usize];
            let serial_hash =
                encode_outboard_recurse(&input, &mut serial_output, Root(case as u64));
            assert_eq!(expected_hash, serial_hash);
            assert_eq!(&outboard[HEADER_SIZE..], &*serial_output);

            let mut parallel_outboard = vec![0; outboard_subtree_size(case as u64) as usize];
            let parallel_hash =
                encode_outboard_recurse_rayon(&input, &mut parallel_outboard, Root(case as u64));
            assert_eq!(expected_hash, parallel_hash);
            assert_eq!(&outboard[HEADER_SIZE..], &*parallel_outboard);

            let mut highlevel_outboard = vec![0; outboard_size(case as u64) as usize];
            let highlevel_hash = encode_outboard(&input, &mut highlevel_outboard);
            assert_eq!(expected_hash, highlevel_hash);
            assert_eq!(outboard, highlevel_outboard);

            let mut writer_outboard = Vec::new();
            {
                let mut writer = Writer::new_outboard(Cursor::new(&mut writer_outboard));
                writer.write_all(&input).unwrap();
                let writer_hash = writer.finish().unwrap();
                assert_eq!(expected_hash, writer_hash);
            }
            assert_eq!(outboard, writer_outboard);
        }
    }

    // This is another way to calculate the number of parent nodes, which takes longer but is less
    // magical. We use it for testing below.
    fn make_pre_post_list(total_chunks: u64) -> Vec<(u8, u8)> {
        fn recurse(start: u64, size: u64, answers: &mut Vec<(u8, u8)>) {
            assert!(size > 0);
            if size == 1 {
                return;
            }
            answers[start as usize].0 += 1;
            answers[(start + size - 1) as usize].1 += 1;
            let split = hash::largest_power_of_two_leq(size - 1);
            recurse(start, split, answers);
            recurse(start + split, size - split, answers);
        }
        let mut answers = vec![(0, 0); total_chunks as usize];
        recurse(0, total_chunks, &mut answers);
        answers
    }

    // Sanity check the helper above.
    #[test]
    fn test_make_pre_post_list() {
        assert_eq!(make_pre_post_list(1), vec![(0, 0)]);
        assert_eq!(make_pre_post_list(2), vec![(1, 0), (0, 1)]);
        assert_eq!(make_pre_post_list(3), vec![(2, 0), (0, 1), (0, 1)]);
        assert_eq!(make_pre_post_list(4), vec![(2, 0), (0, 1), (1, 0), (0, 2)]);
        assert_eq!(
            make_pre_post_list(5),
            vec![(3, 0), (0, 1), (1, 0), (0, 2), (0, 1)]
        );
    }

    #[test]
    fn test_parent_nodes() {
        for total_chunks in 1..100 {
            let content_len = total_chunks * CHUNK_SIZE as u64;
            let pre_post_list = make_pre_post_list(total_chunks);
            for chunk in 0..total_chunks {
                let (expected_pre, expected_post) = pre_post_list[chunk as usize];
                let pre = pre_order_parent_nodes(chunk, content_len);
                let post = if chunk < total_chunks - 1 {
                    post_order_parent_nodes_nonfinal(chunk)
                } else {
                    post_order_parent_nodes_final(chunk)
                };
                assert_eq!(
                    expected_pre, pre,
                    "incorrect pre-order parent nodes for chunk {} of total {}",
                    chunk, total_chunks
                );
                assert_eq!(
                    expected_post, post,
                    "incorrect post-order parent nodes for chunk {} of total {}",
                    chunk, total_chunks
                );
            }
        }
    }

    #[test]
    fn compare_slice_to_python() {
        for &case in hash::TEST_CASES {
            let input = make_test_input(case);
            let (_, encoded) = encode_to_vec(&input);
            let mut encoded_file = tempfile::NamedTempFile::new().unwrap();
            encoded_file.write_all(&encoded).unwrap();
            encoded_file.flush().unwrap();
            let slice_start = input.len() / 4;
            let slice_len = input.len() / 2;
            println!("\ncase {} start {} len {}", case, slice_start, slice_len);
            let mut slice = Vec::new();
            let mut extractor =
                SliceExtractor::new(Cursor::new(&encoded), slice_start as u64, slice_len as u64);
            extractor.read_to_end(&mut slice).unwrap();
            let python_output = cmd!(
                "python3",
                "./test/bao.py",
                "slice",
                slice_start.to_string(),
                slice_len.to_string()
            ).stdin(encoded_file.path())
            .stdout_capture()
            .run()
            .unwrap();
            assert_eq!(python_output.stdout, slice, "slice mismatch");
        }
    }
}
