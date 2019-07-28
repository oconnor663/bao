//! Encode some input bytes into the Bao format, or slice an existing encoding.
//!
//! The Bao encoding format makes it possible to stream content bytes while
//! verifying that they match the root hash. It also supports extracting
//! encoded slices that can be validated apart from the rest of the encoding.
//! This module handles the sending side of these operations. For the receiving
//! side, see the `decode` module.
//!
//! There are two modes of encoding, combined (the default) and outboard. The
//! combined mode mixes subtree hashes together with the input bytes, producing
//! a single file that can be decoded by itself. The outboard mode avoids
//! copying any input bytes. The outboard encoding is much smaller, but it can
//! only be used together with the original input file.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<std::error::Error>> {
//! use std::io::prelude::*;
//! use std::io::Cursor;
//!
//! let input = b"some input";
//! let expected_hash = bao::hash::hash(input);
//!
//! let (encoded_at_once, hash) = bao::encode::encode(b"some input");
//! assert_eq!(expected_hash, hash);
//!
//! let mut encoded_incrementally = Vec::new();
//! let mut encoder = bao::encode::Writer::new(Cursor::new(&mut encoded_incrementally));
//! encoder.write_all(b"some input")?;
//! let hash = encoder.finish()?;
//! assert_eq!(expected_hash, hash);
//!
//! assert_eq!(encoded_at_once, encoded_incrementally);
//! # Ok(())
//! # }
//! ```

use crate::hash::Finalization::{self, NotRoot, Root};
use crate::hash::{self, Hash, CHUNK_SIZE, HEADER_SIZE, PARENT_SIZE};
use arrayref::{array_mut_ref, array_ref};
use arrayvec::ArrayVec;
use blake2s_simd::many::{HashManyJob, MAX_DEGREE as MAX_SIMD_DEGREE};
use core::cmp;
use core::fmt;
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::prelude::*;
#[cfg(feature = "std")]
use std::io::SeekFrom;

/// Encode an entire slice into a bytes vector in the default combined mode.
/// This is a convenience wrapper around `Writer::write_all`.
#[cfg(feature = "std")]
pub fn encode(input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
    let bytes = input.as_ref();
    let mut vec = Vec::with_capacity(encoded_size(bytes.len() as u64) as usize);
    let mut writer = Writer::new(io::Cursor::new(&mut vec));
    writer.write_all(bytes).unwrap();
    let hash = writer.finish().unwrap();
    (vec, hash)
}

/// Encode an entire slice into a bytes vector in the outboard mode. This is a
/// convenience wrapper around `Writer::new_outboard` and `Writer::write_all`.
#[cfg(feature = "std")]
pub fn outboard(input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
    let bytes = input.as_ref();
    let mut vec = Vec::with_capacity(outboard_size(bytes.len() as u64) as usize);
    let mut writer = Writer::new_outboard(io::Cursor::new(&mut vec));
    writer.write_all(bytes).unwrap();
    let hash = writer.finish().unwrap();
    (vec, hash)
}

/// Compute the size of a combined encoding, given the size of the input. Note that for input sizes
/// close to `u64::MAX`, the result can overflow a `u64`.
pub fn encoded_size(content_len: u64) -> u128 {
    content_len as u128 + outboard_size(content_len)
}

/// Compute the size of an outboard encoding, given the size of the input.
pub fn outboard_size(content_len: u64) -> u128 {
    // Should the return type here really by u128? Two reasons: 1) It's convenient to use the same
    // type as encoded_size(), and 2) if we're ever experimenting with very small chunk sizes, we
    // could indeed overflow u64.
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

pub(crate) fn chunk_size(chunk_index: u64, content_len: u64) -> usize {
    let chunk_start = chunk_index * CHUNK_SIZE as u64;
    cmp::min(CHUNK_SIZE, (content_len - chunk_start) as usize)
}

// ----------------------------------------------------------------------------
// When flipping the post-order tree to pre-order during encoding, and when
// traversing the pre-order tree during decoding, we need to know how many
// parent nodes go before (in pre-order) or after (in post-order) each chunk.
// The following three functions use cute arithmetic tricks to figure that out
// without doing much work.
//
// Note that each of these tricks is very similar to the one we're using in
// hash::State::needs_merge. In general the zeros and ones that flip over
// between two chunk indexes are closely related to the subtrees that start or
// end at that boundary, because binary numbers and binary trees have a lot in
// common.
// ----------------------------------------------------------------------------

// Prior to the final chunk, to calculate the number of post-order parent nodes
// for a chunk, we need to know the height of the subtree for which the chunk
// is the rightmost. This is the same as the number of trailing ones in the
// chunk index (counting from 0). For example, chunk number 11 (0b1011) has two
// trailing parent nodes.
fn post_order_parent_nodes_nonfinal(chunk_index: u64) -> u8 {
    (!chunk_index).trailing_zeros() as u8
}

// The final chunk of a post order tree has to have a parent node for each of
// the not yet merged subtrees behind it. This is the same as the total number
// of ones in the chunk index (counting from 0).
fn post_order_parent_nodes_final(chunk_index: u64) -> u8 {
    chunk_index.count_ones() as u8
}

// In pre-order, there are a few different regimes we need to consider:
//
// - The number of parent nodes before the first chunk is the height of the
//   entire tree. For example, a tree of 4 chunks is of height 2, while a tree
//   of 5 chunks is of height 3. We can compute that as the bit length of [the
//   total number of chunks minus 1]. For example, 3 (0b11) has bit length 2,
//   and 4 (0b100) has bit length 3.
// - The number of parent nodes before an interior chunk is the height of the
//   largest subtree for which that chunk is the leftmost. For example, chunk
//   index 6 (the seventh chunk) is usually the leftmost chunk in the two-chunk
//   subtree that contains indexes 6 and 7. A two-chunk subtree is of height 1,
//   so index 6 is preceded by one parent node. We can usually compute that by
//   seeing that index 6 (0b110) has 1 trailing zero.
// - Along the right edge of the tree, not all subtrees are complete, and the
//   second rule doesn't always apply. For example, if chunk index 6 happens to
//   be the final chunk in the tree, and there is no chunk index 7, then index
//   6 doesn't begin a subtree of height 1, and there won't be a parent node in
//   front of it.
//
// We can call the first rule the "bit length rule" and the second rule the
// "trailing zeros rule". It turns out that we can understand the third rule as
// the *minimum* of the other two, and in fact doing that gives us the unified
// rule for all cases. That is, for a given chunk index we compute two things:
//
// - If this chunk and all the chunks after it were in a tree by themselves,
//   what would be the height of that tree? That is, the bit length of [that
//   number of chunks minus one].
// - If the subtree started by this chunk index was complete (as in the
//   interior of a large tree, not near the right edge), what would be the
//   height of that subtree? That is, the number of trailing zeros in the chunk
//   index. Note that this is undefined / maximally large for chunk index 0.
//
// We then take the minimum of those two values, and that's the number of
// parent nodes before each chunk.
pub(crate) fn pre_order_parent_nodes(chunk_index: u64, content_len: u64) -> u8 {
    fn bit_length(x: u64) -> u32 {
        // As mentioned above, note that this reports a bit length of 64 for
        // x=0. That works for us, because cmp::min below will always choose
        // the other rule, but think about it before you copy/paste this.
        64 - x.leading_zeros()
    }
    let total_chunks = count_chunks(content_len);
    debug_assert!(chunk_index < total_chunks);
    let total_chunks_after_this = total_chunks - chunk_index;
    let bit_length_rule = bit_length(total_chunks_after_this - 1);
    let trailing_zeros_rule = chunk_index.trailing_zeros();
    cmp::min(bit_length_rule, trailing_zeros_rule) as u8
}

// This type implements post-order-to-pre-order flipping for the encoder, in a way that could
// support an incremental or asynchronous flip. (Though currently its only caller does the whole
// flip all-at-once.)
//
// As discussed below and in bao.py, encoding first in post-order and then flipping to pre-order
// makes it possible encode without knowing the input length in advance, and without requiring
// buffer space for the entire input.
#[derive(Clone)]
struct FlipperState {
    parents: ArrayVec<[hash::ParentNode; hash::MAX_DEPTH]>,
    content_len: u64,
    last_chunk_moved: u64,
    parents_needed: u8,
    parents_available: u8,
}

impl FlipperState {
    pub fn new(content_len: u64) -> Self {
        let total_chunks = count_chunks(content_len);
        Self {
            parents: ArrayVec::new(),
            content_len,
            last_chunk_moved: count_chunks(content_len), // one greater than the final chunk index
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
        } else if self.last_chunk_moved > 0 {
            FlipperNext::Chunk(chunk_size(self.last_chunk_moved - 1, self.content_len))
        } else {
            FlipperNext::Done
        }
    }

    pub fn chunk_moved(&mut self) {
        // Add the pre-order parents available for the chunk that just moved and the post-order
        // parents needed for the chunk to its left.
        debug_assert!(self.last_chunk_moved > 0);
        debug_assert_eq!(self.parents_available, 0);
        debug_assert_eq!(self.parents_needed, 0);
        self.last_chunk_moved -= 1;
        self.parents_available = pre_order_parent_nodes(self.last_chunk_moved, self.content_len);
        if self.last_chunk_moved > 0 {
            self.parents_needed = post_order_parent_nodes_nonfinal(self.last_chunk_moved - 1);
        }
    }

    pub fn feed_parent(&mut self, parent: hash::ParentNode) {
        debug_assert!(self.last_chunk_moved > 0);
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
        write!(f, "FlipperState {{ parents: {}, content_len: {}, last_chunk_moved: {}, parents_needed: {}, parents_available: {} }}",
               self.parents.len(), self.content_len, self.last_chunk_moved, self.parents_needed, self.parents_available)
    }
}

#[derive(Clone, Copy, Debug)]
enum FlipperNext {
    FeedParent,
    TakeParent,
    Chunk(usize),
    Done,
}

/// An incremental encoder. Note that you must call `finish` after you're done writing.
///
/// `Writer` supports both combined and outboard encoding, depending on which constructor you use.
///
/// `Writer` is currently only available when `std` is enabled, because `std::io::Write` is a
/// required part of its interface. However, it could be extended to support `no_std`-compatible
/// traits outside of the standard library too. Please reach out to me if you need that.
///
/// The implementation is single-threaded but uses SIMD parallelism. As with
/// `hash::Writer`, performance is best if you use an input buffer of size
/// `hash::BUF_SIZE`, or some integer multiple of that.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<std::error::Error>> {
/// use std::io::prelude::*;
///
/// let mut encoded_incrementally = Vec::new();
/// let encoded_cursor = std::io::Cursor::new(&mut encoded_incrementally);
/// let mut encoder = bao::encode::Writer::new(encoded_cursor);
/// encoder.write_all(b"some input")?;
/// encoder.finish()?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct Writer<T: Read + Write + Seek> {
    inner: T,
    chunk_state: blake2s_simd::State,
    tree_state: hash::State,
    outboard: bool,
}

#[cfg(feature = "std")]
impl<T: Read + Write + Seek> Writer<T> {
    /// Create a new `Writer` that will produce a combined encoding.The encoding will contain all
    /// the input bytes, so that it can be decoded without the original input file. This is what
    /// you get from `bao encode`.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chunk_state: hash::new_chunk_state(),
            tree_state: hash::State::new(),
            outboard: false,
        }
    }

    /// Create a new `Writer` for making an outboard encoding. That means that the encoding won't
    /// include any input bytes. Instead, the input will need to be supplied as a separate argument
    /// when the outboard encoding is later decoded. This is what you get from `bao encode
    /// --outboard`.
    pub fn new_outboard(inner: T) -> Self {
        let mut writer = Self::new(inner);
        writer.outboard = true;
        writer
    }

    /// Finalize the encoding, after all the input has been written. You can't
    /// use this Writer again after calling `finish`.
    ///
    /// The underlying strategy of the `Writer` is to first store the tree in a post-order layout,
    /// and then to go back and flip the entire thing into pre-order. That makes it possible to
    /// stream input without knowing its length in advance, which is a core requirement of the
    /// `std::io::Write` interface. The downside is that `finish` is a relatively expensive step.
    pub fn finish(&mut self) -> io::Result<Hash> {
        // Compute the total len before we merge the final chunk into the
        // tree_state.
        let total_len = self
            .tree_state
            .count()
            .checked_add(self.chunk_state.count())
            .expect("addition overflowed");

        // If the chunk_state contains any chunk data, we have to finalize it
        // and incorporate it into the tree. Also, if there was never any data
        // at all, we have to hash the empty chunk. Note that any partial chunk
        // bytes retained in the chunk_state have already been written to the
        // underlying writer by .write().
        if self.chunk_state.count() > 0 || self.tree_state.count() == 0 {
            let finalization = if self.tree_state.count() == 0 {
                Root
            } else {
                NotRoot
            };
            let hash = hash::finalize_hash(&mut self.chunk_state, finalization);
            self.tree_state
                .push_subtree(&hash, self.chunk_state.count() as usize);
        }

        // Merge and write all the parents along the right edge.
        let root_hash;
        loop {
            match self.tree_state.merge_finish() {
                hash::StateFinish::Parent(parent) => self.inner.write_all(&parent)?,
                hash::StateFinish::Root(root) => {
                    root_hash = root;
                    break;
                }
            }
        }

        // Write the length header, at the end.
        self.inner.write_all(&hash::encode_len(total_len))?;

        // Finally, flip the tree to be pre-order. This means rewriting the
        // entire output, so it's expensive.
        self.flip_post_order_stream()?;

        Ok(root_hash)
    }

    fn flip_post_order_stream(&mut self) -> io::Result<()> {
        let mut write_cursor = self.inner.seek(SeekFrom::End(0))?;
        let mut read_cursor = write_cursor - HEADER_SIZE as u64;
        let mut header = [0; HEADER_SIZE];
        self.inner.seek(SeekFrom::Start(read_cursor))?;
        self.inner.read_exact(&mut header)?;
        let content_len = hash::decode_len(&header);
        let mut flipper = FlipperState::new(content_len);
        loop {
            match flipper.next() {
                FlipperNext::FeedParent => {
                    let mut parent = [0; PARENT_SIZE];
                    self.inner
                        .seek(SeekFrom::Start(read_cursor - PARENT_SIZE as u64))?;
                    self.inner.read_exact(&mut parent)?;
                    read_cursor -= PARENT_SIZE as u64;
                    flipper.feed_parent(parent);
                }
                FlipperNext::TakeParent => {
                    let parent = flipper.take_parent();
                    self.inner
                        .seek(SeekFrom::Start(write_cursor - PARENT_SIZE as u64))?;
                    self.inner.write_all(&parent)?;
                    write_cursor -= PARENT_SIZE as u64;
                }
                FlipperNext::Chunk(size) => {
                    // In outboard moded, we skip over chunks.
                    if !self.outboard {
                        let mut chunk = [0; CHUNK_SIZE];
                        self.inner
                            .seek(SeekFrom::Start(read_cursor - size as u64))?;
                        self.inner.read_exact(&mut chunk[..size])?;
                        read_cursor -= size as u64;
                        self.inner
                            .seek(SeekFrom::Start(write_cursor - size as u64))?;
                        self.inner.write_all(&chunk[..size])?;
                        write_cursor -= size as u64;
                    }
                    flipper.chunk_moved();
                }
                FlipperNext::Done => {
                    debug_assert_eq!(HEADER_SIZE as u64, write_cursor);
                    self.inner.seek(SeekFrom::Start(0))?;
                    self.inner.write_all(&header)?;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<T: Read + Write + Seek> Write for Writer<T> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        // Similar to hash::Writer, in normal operation we hash chunks in their
        // entirety using SIMD as they come in, only retaining a partial chunk
        // in the chunk_state if there's uneven input left over. However again,
        // the first chunk is a special case: If we receive exactly one chunk
        // on the first call, we have to retain it in the chunk_state, because
        // we won't know how to finalize it until we get more input. (Receiving
        // less than one chunk would retain it in any case, as uneven input
        // left over.)
        let orig_input_len = input.len();
        let maybe_root = self.tree_state.count() == 0 && input.len() <= CHUNK_SIZE;
        let have_partial_chunk = self.chunk_state.count() > 0;
        if maybe_root || have_partial_chunk {
            let want = CHUNK_SIZE - self.chunk_state.count() as usize;
            let take = cmp::min(want, input.len());
            if !self.outboard {
                self.inner.write_all(&input[..take])?;
            }
            self.chunk_state.update(&input[..take]);
            input = &input[take..];

            // If there's more input coming, finish the chunk before we
            // continue. Otherwise short circuit.
            if !input.is_empty() {
                // In this case there cannot be any pending parent nodes to be
                // written, because either we're partway through a chunk
                // already or we're the first chunk.
                debug_assert!(self.tree_state.merge_parent().is_none());
                let chunk_hash = hash::finalize_hash(&mut self.chunk_state, NotRoot);
                self.chunk_state = hash::new_chunk_state();
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            } else {
                return Ok(orig_input_len);
            }
        }

        // Hash groups of full chunks in parallel using SIMD. After hashing a
        // group of chunks, write each chunk to the output (if non-outboard),
        // incorporate its hash into the tree_state, and write out any
        // completed parent nodes.
        let params = hash::chunk_params(NotRoot);
        let mut chunks = input.chunks_exact(CHUNK_SIZE);
        let mut fused_chunks = chunks.by_ref().fuse();
        loop {
            let chunk_group: ArrayVec<[&[u8; CHUNK_SIZE]; MAX_SIMD_DEGREE]> = fused_chunks
                .by_ref()
                .take(MAX_SIMD_DEGREE)
                .map(|chunk| array_ref!(chunk, 0, CHUNK_SIZE))
                .collect();
            if chunk_group.is_empty() {
                break;
            }
            let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = chunk_group
                .iter()
                .map(|&chunk| HashManyJob::new(&params, chunk))
                .collect();
            blake2s_simd::many::hash_many(&mut jobs);
            for (&chunk, job) in chunk_group.iter().zip(&jobs) {
                // Note that we always merge and write the previous chunk's
                // parents just before writing the next chunk, rather than
                // after we finished writing the previous chunk. That's because
                // we don't know whether the last set of merges is root or not,
                // until we get more input.
                while let Some(parent) = self.tree_state.merge_parent() {
                    self.inner.write_all(&parent)?;
                }
                if !self.outboard {
                    self.inner.write_all(chunk)?;
                }
                let chunk_hash = Hash::new(job.to_hash().as_array());
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            }
        }

        // Emit any remaining partial chunk bytes and retain them in the
        // chunk_state.
        debug_assert!(chunks.remainder().len() < CHUNK_SIZE);
        debug_assert_eq!(self.chunk_state.count(), 0);
        if !chunks.remainder().is_empty() {
            // Again we merge and write the previous chunk's parents now that
            // we're sure there's more input.
            while let Some(parent) = self.tree_state.merge_parent() {
                self.inner.write_all(&parent)?;
            }
            if !self.outboard {
                self.inner.write_all(chunks.remainder())?;
            }
            self.chunk_state.update(chunks.remainder());
        }
        Ok(orig_input_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// This incremental parser underlies the VerifyState (which does the actual
// hash checking part of `bao decode`) and the SliceExtractor (which implements
// `bao slice` and doesn't actually check any hashes). It encapsulates the tree
// traversal logic, but it doesn't actually perform any IO or handle any of the
// bytes that get read; all of that is left to the caller.
#[derive(Clone, Debug)]
pub(crate) struct ParseState {
    content_len: Option<u64>,
    content_position: u64, // can be in the middle of a chunk, after a seek
    encoding_position: u128,
    stack_depth: u8,
    upcoming_parents: u8,
    // Tracking this state is crucial for security, see the "final chunk
    // requirement" in the spec. This parser doesn't actually check hashes, but
    // it drives callers that do check.
    final_chunk_validated: bool,
}

impl ParseState {
    pub fn new() -> Self {
        Self {
            content_len: None,
            content_position: 0,
            encoding_position: 0,
            stack_depth: 1,
            upcoming_parents: 0, // set later in feed_header
            final_chunk_validated: false,
        }
    }

    pub fn content_position(&self) -> u64 {
        self.content_position
    }

    fn at_root(&self) -> bool {
        self.content_position < CHUNK_SIZE as u64 && self.stack_depth == 1
    }

    fn at_eof(&self) -> bool {
        if let Some(content_len) = self.content_len {
            if self.content_position >= content_len {
                if self.final_chunk_validated {
                    // It's security critical that we never get to EOF without
                    // having validated the final chunk. This is part of the
                    // "final chunk requirement" in the spec.
                    return true;
                }
                // For content_len == 0, reads won't move the offset, and the
                // final_chunk_validated flag is usually the only way to tell
                // that we've gotten to EOF. But for any non-empty encoding, we
                // shouldn't be able to pass the EOF offset without also
                // validating the final_chunk.
                if content_len > 0 {
                    debug_assert!(self.content_position < content_len);
                }
            }
        }
        false
    }

    fn next_chunk_start(&self) -> u64 {
        debug_assert!(!self.at_eof(), "not valid at EOF");
        self.content_position - (self.content_position % CHUNK_SIZE as u64)
    }

    fn next_chunk_index(&self) -> u64 {
        debug_assert!(!self.at_eof(), "not valid at EOF");
        self.content_position / CHUNK_SIZE as u64
    }

    pub fn finalization(&self) -> Finalization {
        if self.at_root() {
            Root
        } else {
            NotRoot
        }
    }

    fn reset_to_root(&mut self) {
        let content_len = self.content_len.expect("reset before header");
        self.content_position = 0;
        self.encoding_position = HEADER_SIZE as u128;
        self.stack_depth = 1;
        self.upcoming_parents = pre_order_parent_nodes(0, content_len);
        // The final_chunk_validated flag is left alone. If the caller has
        // already validated the final chunk, then they can do EOF-relative
        // seeks or read the length without paying that cost again.
    }

    // Reading is done in a loop. The caller may need to read and process
    // several parent nodes before encountering the next chunk. Done indicates
    // EOF.
    pub fn read_next(&self) -> NextRead {
        // If we haven't yet parsed the length header, that has to happen
        // first. Note that this isn't necessarily a validated length, which in
        // general we can't get without seeking. The validated length isn't
        // required unless we're returning EOF.
        let content_len = if let Some(len) = self.content_len {
            len
        } else {
            return NextRead::Header;
        };
        if self.at_eof() {
            // It's security critical that we never get here without having
            // validated the final chunk first. This is part of the "final
            // chunk requirement" in the spec. at_eof() asserts it.
            NextRead::Done
        } else if self.upcoming_parents > 0 {
            NextRead::Parent {
                upcoming_parents: self.upcoming_parents,
            }
        } else {
            NextRead::Chunk {
                size: chunk_size(self.next_chunk_index(), content_len),
                finalization: self.finalization(),
                skip: (self.content_position % CHUNK_SIZE as u64) as usize,
            }
        }
    }

    // Like reading, seeking is done in a loop. The caller calls seek_next()
    // and receives a SeekBookkeeping object. The caller handles all the
    // indicated bookkeeping, adjusting its subtree stack if any and seeking
    // its underlying reader if any. The caller then passes the object back to
    // seek_bookkeeping_done(), which returns an optional NextRead action. If
    // the action is other than Done, the caller carries it out and then
    // repeats the seek loop. If the action is Done, the seek is finished.
    //
    // Usually seeking won't instruct the caller to read any chunks, but will
    // instead stop when it gets to the position where the next read loop will
    // finish by reading the target chunk. This gives the caller more
    // flexibility to read chunk data directly into the destination buffer,
    // rather than copying it twice.
    //
    // The one exception is seeking to or past the end. In that case seek will
    // instruct the caller to read (and validate, if applicable) the final
    // chunk. This is part of the "final chunk requirement" described in the
    // spec, which prevents corrupt length headers from being exposed to the
    // caller. If the caller retains that final chunk in its buffer, it'll need
    // to mark the buffer as "already read" or whatever.
    pub fn seek_next(&self, seek_to: u64) -> SeekBookkeeping {
        let mut new_state = self.clone();
        let next_read = new_state.new_state_seek_next(seek_to);
        SeekBookkeeping {
            old_state: self.clone(),
            new_state,
            next_read,
        }
    }

    // This is called on a clone of the ParseState (`new_state` above), and the
    // changes here are applied in seek_bookkeeping_done(). This allows
    // seek_next() to take &self and keeps everything idempotent.
    fn new_state_seek_next(&mut self, mut seek_to: u64) -> NextRead {
        // If we haven't yet parsed the len, that has to happen first.
        let content_len = if let Some(len) = self.content_len {
            len
        } else {
            return NextRead::Header;
        };

        // If the seek is to or past EOF, we need to check whether the final
        // chunk has already been validated. If not, we need to validate it as
        // part of seeking.
        let mut read_final_chunk = false;
        if seek_to >= content_len {
            if self.final_chunk_validated {
                // The final chunk has already been validated, and we don't
                // need to do any more work. Setting content_position at or
                // past the content_len indicates EOF to subsequent reads.
                // Other state parameters don't matter; they'll get reset if
                // the caller seeks back into the encoding.
                self.content_position = seek_to;
                return NextRead::Done;
            }
            // The final chunk hasn't been validated. We repoint the seek to
            // the last byte of the encoding, and read it when we get there.
            seek_to = content_len.saturating_sub(1);
            read_final_chunk = true;
        }

        // If seek_to is to the left of the next chunk, reset the whole state,
        // so that we can re-traverse from the beginning. The caller will have
        // to execute an underlying seek in this case. However, if seek_to is
        // just to a different skip offset within the next chunk, resetting is
        // unnecessary, which is why we use next_chunk_start() instead of
        // content_position.
        if self.at_eof() || seek_to < self.next_chunk_start() {
            self.reset_to_root();
        }

        // Now the meat of the seek computation. We know the seek is into or to
        // the right of the next chunk, and not EOF. Ascend out of as many
        // subtrees as necessary, until we're in the subtree containing the
        // target, and then either finish the seek or descend.
        loop {
            // If the target is within the next chunk, the seek is usually
            // finished. In that case we set the content_position to the exact
            // seek target, so that if it's in the middle of the chunk, then
            // the next read will compute the correct skip. The exception is a
            // repointed EOF seek, where we instruct the caller to read the
            // final chunk and call seek_next again.
            let distance = seek_to - self.next_chunk_start();
            if distance < CHUNK_SIZE as u64 {
                if read_final_chunk {
                    let size = (content_len - self.next_chunk_start()) as usize;
                    return NextRead::Chunk {
                        size,
                        finalization: self.finalization(),
                        skip: size, // Skip the whole thing.
                    };
                } else {
                    self.content_position = seek_to;
                    return NextRead::Done;
                }
            }

            // If the target is within the current subtree but not the next
            // chunk, we need to descend. Down-shift the distance rather than
            // computing the maximum subtree size, to prevent overflow.
            let downshifted_distance = distance
                .checked_shr(self.upcoming_parents as u32)
                .unwrap_or(0);
            if downshifted_distance < CHUNK_SIZE as u64 {
                debug_assert!(self.upcoming_parents > 0);
                return NextRead::Parent {
                    upcoming_parents: self.upcoming_parents,
                };
            }

            // Otherwise jump out of the current subtree and loop. In this case
            // we know the subtree size is maximal, and computing it won't
            // overflow. The caller will have to execute an underlying seek in
            // this case.
            let subtree_size = (CHUNK_SIZE as u64) << self.upcoming_parents;
            self.content_position = self.next_chunk_start() + subtree_size;
            self.encoding_position += encoded_subtree_size(subtree_size);
            self.stack_depth -= 1;
            // This depends on the update to content_position immediately above.
            self.upcoming_parents = pre_order_parent_nodes(self.next_chunk_index(), content_len);
        }
    }

    // This consumes the SeekBookkeeping object, to try to force the caller to
    // handle the bookkeeping instructions before the NextRead.
    pub fn seek_bookkeeping_done(&mut self, bookkeeping: SeekBookkeeping) -> NextRead {
        *self = bookkeeping.new_state;
        bookkeeping.next_read
    }

    pub fn len_next(&self) -> LenNext {
        if let Some(content_len) = self.content_len {
            // We can only return the length once the final chunk has been
            // validated. This is the "final chunk requirement".
            if self.final_chunk_validated {
                LenNext::Len(content_len)
            } else {
                // Otherwise we need to validate it, by seeking to EOF.
                LenNext::Seek(self.seek_next(content_len))
            }
        } else {
            // If we haven't even parsed the content header, that's the first
            // instruction for any seek, so zero is fine.
            LenNext::Seek(self.seek_next(0))
        }
    }

    // Returns the parsed length.
    pub fn feed_header(&mut self, header: &[u8; HEADER_SIZE]) {
        debug_assert!(self.content_len.is_none(), "second call to feed_header");
        let content_len = hash::decode_len(header);
        self.content_len = Some(content_len);
        self.reset_to_root();
    }

    pub fn advance_parent(&mut self) {
        debug_assert!(
            self.upcoming_parents > 0,
            "too many calls to advance_parent"
        );
        self.encoding_position += PARENT_SIZE as u128;
        self.stack_depth += 1;
        self.upcoming_parents -= 1;
    }

    pub fn advance_chunk(&mut self) {
        debug_assert_eq!(
            0, self.upcoming_parents,
            "advance_chunk with non-zero upcoming parents"
        );
        let content_len = self.content_len.expect("advance_chunk before header");
        let size = chunk_size(self.next_chunk_index(), content_len);
        let skip = self.content_position % CHUNK_SIZE as u64;
        self.content_position += size as u64 - skip;
        self.encoding_position += size as u128;
        self.stack_depth -= 1;
        if self.content_position >= content_len {
            debug_assert_eq!(self.content_position, content_len, "position past EOF");
            // We just validated the final chunk. This is the *only line* where
            // we satisfy the "final chunk requirement". Any transition into an
            // EOF state must go through this line of code.
            self.final_chunk_validated = true;
        } else {
            // upcoming_parents is only meaningful if we're before EOF.
            self.upcoming_parents = pre_order_parent_nodes(self.next_chunk_index(), content_len);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NextRead {
    Header,
    Parent {
        upcoming_parents: u8,
    },
    Chunk {
        size: usize,
        finalization: Finalization,
        skip: usize,
    },
    Done,
}

// This struct provides several methods that give bookkeeping instructions. The
// caller must handle all of these:
//
// reset_to_root: When seeking to the left, parsing resets all the way to the
// root. If the caller manages a stack of subtree hashes (as VerifyState does),
// its stack needs to be reset, so that it's ready to receive the root node
// again. This is indicated by returning true.
//
// stack_depth: Seeking to the right sometimes means skipping over upcoming
// subtrees. If the caller manages a stack of subtree hashes (again as
// VerifyState does), it might need to pop some hashes off the end of its
// stack. It should pop until the depth of its stack is equal to the returned
// depth. Note that giving a target depth rather than a number of pops keeps
// this instruction idempotent; if the caller executes it twice for some reason
// (maybe interruption or recoverable errors), they'll still get the correct
// answer.
//
// underlying_seek[_outboard]: Both of the cases above require a corresponding
// seek in the underlying reader. This is indicated by returning non-None. Note
// that the seek target is a u128, and it's the caller's responsibility to
// decide how to handle truncation to a u64, either by performing multiple
// seeks or by reporting an error. This comes up for pathologically long inputs
// close to u64::MAX bytes, where in theory encoding overhead pushes the
// encoded length past u64::MAX. It's reasonable to fail in that case, but the
// ParseState API itself is infallible.
//
// After handling all of the above, the caller passes the SeekBookkeeping back
// to seek_done(), which might returns a NextRead for the caller to carry
// out, or None to indicate
#[derive(Debug)]
pub(crate) struct SeekBookkeeping {
    old_state: ParseState,
    new_state: ParseState,
    next_read: NextRead,
}

impl SeekBookkeeping {
    pub fn reset_to_root(&self) -> bool {
        self.new_state.at_root() && !self.old_state.at_root()
    }

    pub fn stack_depth(&self) -> usize {
        self.new_state.stack_depth as usize
    }

    pub fn underlying_seek(&self) -> Option<u128> {
        if self.old_state.encoding_position != self.new_state.encoding_position {
            Some(self.new_state.encoding_position)
        } else {
            None
        }
    }

    // A variant on the above for callers who keep the encoded tree separate
    // from the content.
    pub fn underlying_seek_outboard(&self) -> Option<(u64, u64)> {
        if self.old_state.encoding_position != self.new_state.encoding_position {
            let content = self.new_state.next_chunk_start();
            let outboard = (self.new_state.encoding_position - content as u128) as u64;
            Some((content, outboard))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) enum LenNext {
    Seek(SeekBookkeeping),
    Len(u64),
}

/// An incremental slice extractor, which reads encoded bytes and produces a slice.
///
/// `SliceExtractor` supports reading both the combined and outboard encoding, depending on which
/// constructor you use. Though to be clear, there's no such thing as an "outboard slice" per se.
/// Slices always include subtree hashes inline with the content, as a combined encoding does.
///
/// Note that slices always split the encoding at chunk boundaries. Bao's chunk size is currently
/// 4096 bytes, so using `slice_start` and `slice_len` arguments that are a multiple that avoids
/// wasting space. Also, slicing when there's less than a full chunk of input is pointless.
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
/// # fn main() -> Result<(), Box<std::error::Error>> {
/// use std::io::prelude::*;
///
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = bao::encode::encode(&input);
/// // These parameters are multiples of the chunk size, which avoids unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 8192;
/// let encoded_cursor = std::io::Cursor::new(&encoded);
/// let mut extractor = bao::encode::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice)?;
///
/// // The slice includes some overhead to store the necessary subtree hashes, but it's not much.
/// assert_eq!(8712, slice.len());
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
pub struct SliceExtractor<T: Read + Seek, O: Read + Seek> {
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

#[cfg(feature = "std")]
impl<T: Read + Seek> SliceExtractor<T, T> {
    /// Create a new `SliceExtractor` to read from a combined encoding. Note that `slice_start` and
    /// `slice_len` are with respect to the *content* of the encoding, that is, the *original*
    /// input bytes. This corresponds to `bao slice slice_start slice_len`.
    pub fn new(input: T, slice_start: u64, slice_len: u64) -> Self {
        // TODO: normalize zero-length slices?
        Self::new_inner(input, None, slice_start, slice_len)
    }
}

#[cfg(feature = "std")]
impl<T: Read + Seek, O: Read + Seek> SliceExtractor<T, O> {
    /// Create a new `SliceExtractor` to read from an unmodified input file and an outboard
    /// encoding of that same file (see `Writer::new_outboard`). As with `SliceExtractor::new`,
    /// `slice_start` and `slice_len` are with respect to the *content* of the encoding, that is,
    /// the *original* input bytes. This corresponds to `bao slice slice_start slice_len
    /// --outboard`.
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
        if let Some(outboard) = &mut self.outboard {
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
        if let Some(outboard) = &mut self.outboard {
            outboard.read_exact(parent)?;
        } else {
            self.input.read_exact(parent)?;
        }
        self.buf_start = 0;
        self.buf_end = PARENT_SIZE;
        self.parser.advance_parent();
        Ok(())
    }

    fn read_chunk(&mut self, size: usize, skip: usize) -> io::Result<()> {
        debug_assert_eq!(0, self.buf_len(), "read_chunk with nonempty buffer");
        let chunk = &mut self.buf[..size];
        self.input.read_exact(chunk)?;
        self.buf_start = 0;
        self.buf_end = size;
        // After reading a chunk, increment slice_bytes_read. This will stop
        // the read loop once we've read everything the caller asked for. If
        // the read indicates we should skip partway into the chunk (because
        // the target of the previous seek was in the middle), we don't count
        // skipped bytes against the total.
        self.slice_bytes_read += (size - skip) as u64;
        self.parser.advance_chunk();
        Ok(())
    }

    fn make_progress_and_buffer_output(&mut self) -> io::Result<()> {
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
                    self.input.seek(SeekFrom::Start(content_pos))?;
                    outboard.seek(SeekFrom::Start(outboard_pos))?;
                }
            } else {
                if let Some(encoding_position) = bookkeeping.underlying_seek() {
                    self.input
                        .seek(SeekFrom::Start(cast_offset(encoding_position)?))?;
                }
            }
            let next_read = self.parser.seek_bookkeeping_done(bookkeeping);
            match next_read {
                NextRead::Header => return self.read_header(),
                NextRead::Parent {
                    upcoming_parents: _,
                } => return self.read_parent(),
                NextRead::Chunk {
                    size,
                    finalization: _,
                    skip,
                } => return self.read_chunk(size, skip),
                NextRead::Done => self.seek_done = true, // Fall through to read.
            }
        }

        // If we haven't finished the read yet, do a step of that. If we've already supplied all
        // the requested bytes, however, don't read any more.
        if self.slice_bytes_read < self.slice_len {
            match self.parser.read_next() {
                NextRead::Header => unreachable!(),
                NextRead::Parent {
                    upcoming_parents: _,
                } => return self.read_parent(),
                NextRead::Chunk {
                    size,
                    finalization: _,
                    skip,
                } => return self.read_chunk(size, skip),
                NextRead::Done => {} // EOF
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
    use super::*;
    use crate::decode::make_test_input;

    #[test]
    fn test_encode() {
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = hash::hash(&input);
            let (encoded, hash) = encode(&input);
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
        for &case in hash::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = hash::hash(&input);
            let (outboard, hash) = outboard(&input);
            assert_eq!(expected_hash, hash);
            assert_eq!(outboard.len() as u128, outboard_size(case as u64));
            assert_eq!(outboard.len(), outboard.capacity());
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
}
