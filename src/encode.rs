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
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::prelude::*;
//! use std::io::Cursor;
//!
//! let input = b"some input";
//! let expected_hash = blake3::hash(input);
//!
//! let (encoded_at_once, hash) = bao::encode(b"some input");
//! assert_eq!(expected_hash, hash);
//!
//! let mut encoded_incrementally = Vec::new();
//! let mut encoder = bao::Encoder::new(Cursor::new(&mut encoded_incrementally));
//! encoder.write_all(b"some input")?;
//! let hash = encoder.finalize()?;
//! assert_eq!(expected_hash, hash);
//!
//! assert_eq!(encoded_at_once, encoded_incrementally);
//! # Ok(())
//! # }
//! ```

use crate::{Config, Encoder, Hash, ParentNode, HASH_SIZE, HEADER_SIZE, PARENT_SIZE};
use blake3::hazmat::{ChainingValue, HasherExt};
use blake3::Hasher;
use std::cmp;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

// ----------------------------------------------------------------------------
// When flipping the post-order tree to pre-order during encoding, and when
// traversing the pre-order tree during decoding, we need to know how many
// parent nodes go before (in pre-order) or after (in post-order) each group.
// The following three functions use cute arithmetic tricks to figure that out
// without doing much work.
//
// Note that each of these tricks is very similar to the one we're using in
// State::needs_merge. In general the zeros and ones that flip over between two
// group indexes are closely related to the subtrees that start or end at that
// boundary, because binary numbers and binary trees have a lot in common.
// ----------------------------------------------------------------------------

// Prior to the final group, to calculate the number of post-order parent nodes
// for a group, we need to know the height of the subtree for which the group
// is the rightmost. This is the same as the number of trailing ones in the
// group index (counting from 0). For example, group number 11 (0b1011) has two
// trailing parent nodes.
fn post_order_parent_nodes_nonfinal(group_index: u64) -> u8 {
    (!group_index).trailing_zeros() as u8
}

// The final group of a post order tree has to have a parent node for each of
// the not yet merged subtrees behind it. This is the same as the total number
// of ones in the group index (counting from 0).
fn post_order_parent_nodes_final(group_index: u64) -> u8 {
    group_index.count_ones() as u8
}

// In pre-order, there are a few different regimes we need to consider:
//
// - The number of parent nodes before the first group is the height of the
//   entire tree. For example, a tree of 4 groups is of height 2, while a tree
//   of 5 groups is of height 3. We can compute that as the bit length of [the
//   total number of groups minus 1]. For example, 3 (0b11) has bit length 2,
//   and 4 (0b100) has bit length 3.
// - The number of parent nodes before an interior group is the height of the
//   largest subtree for which that group is the leftmost. For example, group
//   index 6 (the seventh group) is usually the leftmost group in the two-group
//   subtree that contains indexes 6 and 7. A two-group subtree is of height 1,
//   so index 6 is preceded by one parent node. We can usually compute that by
//   seeing that index 6 (0b110) has 1 trailing zero.
// - Along the right edge of the tree, not all subtrees are complete, and the
//   second rule doesn't always apply. For example, if group index 6 happens to
//   be the final group in the tree, and there is no group index 7, then index
//   6 doesn't begin a subtree of height 1, and there won't be a parent node in
//   front of it.
//
// We can call the first rule the "bit length rule" and the second rule the
// "trailing zeros rule". It turns out that we can understand the third rule as
// the *minimum* of the other two, and in fact doing that gives us the unified
// rule for all cases. That is, for a given group index we compute two things:
//
// - If this group and all the groups after it were in a tree by themselves,
//   what would be the height of that tree? That is, the bit length of [that
//   number of groups minus one].
// - If the subtree started by this group index was complete (as in the
//   interior of a large tree, not near the right edge), what would be the
//   height of that subtree? That is, the number of trailing zeros in the group
//   index. Note that this is undefined / maximally large for group index 0.
//
// We then take the minimum of those two values, and that's the number of
// parent nodes before each group.
pub(crate) fn pre_order_parent_nodes(config: Config, group_index: u64, content_len: u64) -> u8 {
    fn bit_length(x: u64) -> u32 {
        // As mentioned above, note that this reports a bit length of 64 for
        // x=0. That works for us, because cmp::min below will always choose
        // the other rule, but think about it before you copy/paste this.
        64 - x.leading_zeros()
    }
    let total_groups = config.count_groups(content_len);
    debug_assert!(group_index < total_groups);
    let total_groups_after_this = total_groups - group_index;
    let bit_length_rule = bit_length(total_groups_after_this - 1);
    let trailing_zeros_rule = group_index.trailing_zeros();
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
    config: Config,
    parents: Vec<ParentNode>,
    content_len: u64,
    last_group_moved: u64,
    parents_needed: u8,
    parents_available: u8,
}

impl FlipperState {
    pub fn new(config: Config, content_len: u64) -> Self {
        let total_groups = config.count_groups(content_len);
        Self {
            config,
            parents: Vec::new(),
            content_len,
            last_group_moved: total_groups, // one greater than the final group index
            parents_needed: post_order_parent_nodes_final(total_groups - 1),
            parents_available: 0,
        }
    }

    pub fn next(&self) -> FlipperNext {
        // group_moved() adds both the parents_available for the group just moved and the
        // parents_needed for the group to its left, so we have to do TakeParent first.
        if self.parents_available > 0 {
            FlipperNext::TakeParent
        } else if self.parents_needed > 0 {
            FlipperNext::FeedParent
        } else if self.last_group_moved > 0 {
            FlipperNext::ChunkGroup(
                self.config
                    .group_size_by_index(self.last_group_moved - 1, self.content_len),
            )
        } else {
            FlipperNext::Done
        }
    }

    pub fn group_moved(&mut self) {
        // Add the pre-order parents available for the group that just moved and the post-order
        // parents needed for the group to its left.
        debug_assert!(self.last_group_moved > 0);
        debug_assert_eq!(self.parents_available, 0);
        debug_assert_eq!(self.parents_needed, 0);
        self.last_group_moved -= 1;
        self.parents_available =
            pre_order_parent_nodes(self.config, self.last_group_moved, self.content_len);
        if self.last_group_moved > 0 {
            self.parents_needed = post_order_parent_nodes_nonfinal(self.last_group_moved - 1);
        }
    }

    pub fn feed_parent(&mut self, parent: ParentNode) {
        debug_assert!(self.last_group_moved > 0);
        debug_assert_eq!(self.parents_available, 0);
        debug_assert!(self.parents_needed > 0);
        self.parents_needed -= 1;
        self.parents.push(parent);
    }

    pub fn take_parent(&mut self) -> ParentNode {
        debug_assert!(self.parents_available > 0);
        self.parents_available -= 1;
        self.parents.pop().expect("took too many parents")
    }
}

impl fmt::Debug for FlipperState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FlipperState {{ parents: {}, content_len: {}, last_group_moved: {}, parents_needed: {}, parents_available: {} }}",
               self.parents.len(), self.content_len, self.last_group_moved, self.parents_needed, self.parents_available)
    }
}

#[derive(Clone, Copy, Debug)]
enum FlipperNext {
    FeedParent,
    TakeParent,
    ChunkGroup(usize),
    Done,
}

#[derive(Clone)]
pub(crate) struct State {
    subtree_cvs: Vec<ChainingValue>,
    total_groups: u64,
}

impl State {
    pub fn new() -> Self {
        Self {
            subtree_cvs: Vec::new(),
            total_groups: 0,
        }
    }

    // We keep the subtree hashes in an array without storing their size, and we use this cute
    // trick to figure out when we should merge them. Because every subtree (prior to the
    // finalization step) is a power of two times the group size, adding a new subtree to the
    // right/small end is a lot like adding a 1 to a binary number, and merging subtrees is like
    // propagating the carry bit. Each carry represents a place where two subtrees need to be
    // merged, and the final number of 1 bits is the same as the final number of subtrees.
    fn needs_merge(&self) -> bool {
        self.subtree_cvs.len() > self.total_groups.count_ones() as usize
    }

    /// Add a subtree CV to the state and return a Vec containing all the new parent nodes in
    /// post-order. This does aggressive merging, so you can only call this when you know there's
    /// more input coming.
    #[must_use]
    pub fn push_subtree(&mut self, subtree_cv: &ChainingValue) -> Vec<ParentNode> {
        // Lazy merging, to avoid finalizing the root too early.
        self.subtree_cvs.push(*subtree_cv);
        self.total_groups += 1;
        let mut new_parents = Vec::new();
        while self.needs_merge() {
            let right_child = self.subtree_cvs.pop().unwrap();
            let left_child = self.subtree_cvs.pop().unwrap();
            let parent_cv = blake3::hazmat::merge_subtrees_non_root(
                &left_child,
                &right_child,
                blake3::hazmat::Mode::Hash,
            );
            self.subtree_cvs.push(parent_cv);
            let mut parent_node = [0; PARENT_SIZE];
            parent_node[..HASH_SIZE].copy_from_slice(&left_child);
            parent_node[HASH_SIZE..].copy_from_slice(&right_child);
            new_parents.push(parent_node);
        }
        new_parents
    }

    /// Return the root hash and a Vec containing new parent nodes in post-order. Note that there
    /// is always at least one new parent node: the root node itself. If the final group is also
    /// the only group, and therefore the root group, you need to handle that case separately.
    #[must_use]
    pub fn merge_finalize(&self, final_group_cv: &ChainingValue) -> (Hash, Vec<ParentNode>) {
        assert!(!self.subtree_cvs.is_empty());
        // Merge all the subtree CVs from the right/bottom going to the left/top. The last one is
        // the root node.
        let mut new_parents = Vec::new();
        let mut current_cv = *final_group_cv;
        let mut i = self.subtree_cvs.len() - 1;
        loop {
            let mut parent_node = [0; PARENT_SIZE];
            parent_node[..HASH_SIZE].copy_from_slice(&self.subtree_cvs[i]);
            parent_node[HASH_SIZE..].copy_from_slice(&current_cv);
            new_parents.push(parent_node);
            if i > 0 {
                current_cv = blake3::hazmat::merge_subtrees_non_root(
                    &self.subtree_cvs[i],
                    &current_cv,
                    blake3::hazmat::Mode::Hash,
                );
                i -= 1;
            } else {
                let root_hash = blake3::hazmat::merge_subtrees_root(
                    &self.subtree_cvs[0],
                    &current_cv,
                    blake3::hazmat::Mode::Hash,
                );
                return (root_hash, new_parents);
            }
        }
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Avoid printing hashes, they might be secret.
        write!(
            f,
            "State {{ subtree_cvs: {}, total_groups: {} }}",
            self.subtree_cvs.len(),
            self.total_groups,
        )
    }
}

impl<T: Read + Write + Seek> Encoder<T> {
    /// Create a new `Encoder` that will produce a combined encoding with the default group size,
    /// 16 KiB. The encoding will contain all the input bytes, so that it can be decoded without
    ///    the original input file. This is what you get from `bao encode`.
    pub fn new(inner: T) -> Self {
        Config::default().new_encoder(inner)
    }

    /// Create a new `Encoder` for making an outboard encoding with the default group size (16
    /// KiB). The encoding won't include any input bytes. Instead, the input will need to be
    /// supplied as a separate argument when the outboard encoding is later decoded. This is what
    /// you get from `bao encode --outboard`.
    pub fn new_outboard(inner: T) -> Self {
        Config::default().new_outboard_encoder(inner)
    }

    /// Finalize the encoding, after all the input has been written. You can't keep using this
    /// `Encoder` again after calling `finalize`, and writing or finalizing again will panic.
    ///
    /// The underlying strategy of the `Encoder` is to first store the tree in a post-order layout,
    /// and then to go back and flip the entire thing into pre-order. That makes it possible to
    /// stream input without knowing its length in advance, which is a core requirement of the
    /// `std::io::Write` interface. The downside is that `finalize` is a relatively expensive step.
    pub fn finalize(&mut self) -> io::Result<Hash> {
        if self.group_state.count() == 0 {
            // The final group can't be empty unless the whole tree is empty.
            debug_assert_eq!(self.tree_state.total_groups, 0);
        }
        assert!(!self.finalized, "already finalized");
        self.finalized = true;

        // Compute the total len before we merge the final group into the tree_state, since it
        // might be short.
        let total_len =
            self.tree_state.total_groups * self.config.group_size as u64 + self.group_state.count();

        // Finalize the last group. If the tree_state is empty, the last group is the root, and
        // there are no parent nodes, but the length header still needs to get flipped.
        let root_hash = if self.tree_state.total_groups == 0 {
            self.group_state.finalize()
        } else {
            let (root_hash, new_parents) = self
                .tree_state
                .merge_finalize(&self.group_state.finalize_non_root());
            for parent in &new_parents {
                self.inner.write_all(parent)?;
            }
            root_hash
        };

        // Write the length header, at the end.
        self.inner.write_all(&crate::encode_len(total_len))?;

        // Finally, flip the tree to be pre-order. This means rewriting the
        // entire output, so it's expensive.
        self.flip_post_order_stream()?;

        Ok(root_hash)
    }

    /// Return the underlying writer.
    pub fn into_inner(self) -> T {
        self.inner
    }

    fn flip_post_order_stream(&mut self) -> io::Result<()> {
        let mut write_cursor = self.inner.seek(SeekFrom::End(0))?;
        let mut read_cursor = write_cursor - HEADER_SIZE as u64;
        let mut header = [0; HEADER_SIZE];
        self.inner.seek(SeekFrom::Start(read_cursor))?;
        self.inner.read_exact(&mut header)?;
        let content_len = crate::decode_len(&header);
        let mut flipper = FlipperState::new(self.config, content_len);
        let mut chunk_group_buffer = vec![0; self.config.group_size];
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
                FlipperNext::ChunkGroup(size) => {
                    // In outboard moded, we skip over chunks.
                    if !self.outboard {
                        let buf = &mut chunk_group_buffer[..size];
                        self.inner
                            .seek(SeekFrom::Start(read_cursor - size as u64))?;
                        self.inner.read_exact(buf)?;
                        read_cursor -= size as u64;
                        self.inner
                            .seek(SeekFrom::Start(write_cursor - size as u64))?;
                        self.inner.write_all(buf)?;
                        write_cursor -= size as u64;
                    }
                    flipper.group_moved();
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

impl<T: Read + Write + Seek> Write for Encoder<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        assert!(!self.finalized, "already finalized");

        // Short-circuit if the input is empty.
        if input.is_empty() {
            return Ok(0);
        }

        // If the current group is full, we need to finalize it, add it to
        // the tree state, and write out any completed parent nodes.
        if self.group_state.count() == self.config.group_size as u64 {
            // This can't be the root, because we know more input is coming.
            let group_hash = self.group_state.finalize_non_root().into();
            let new_parents = self.tree_state.push_subtree(&group_hash);
            for parent in &new_parents {
                self.inner.write_all(parent)?;
            }
            self.group_state = Hasher::new();
            self.group_state
                .set_input_offset(self.tree_state.total_groups * self.config.group_size as u64);
        }

        // Add as many bytes as possible to the current group.
        let want = self.config.group_size - self.group_state.count() as usize;
        let take = cmp::min(want, input.len());
        if !self.outboard {
            self.inner.write_all(&input[..take])?;
        }
        self.group_state.update(&input[..take]);
        Ok(take)
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
    config: Config,
    content_len: Option<u64>,
    content_position: u64, // can be in the middle of a group, after a seek
    encoding_position: u64,
    stack_depth: u8,
    upcoming_parents: u8,
    // Tracking this state is crucial for security, see the "final chunk
    // requirement" in the spec. This parser doesn't actually check hashes, but
    // it drives callers that do check.
    final_group_validated: bool,
}

impl ParseState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            content_len: None,
            content_position: 0,
            encoding_position: 0,
            stack_depth: 1,
            upcoming_parents: 0, // set later in feed_header
            final_group_validated: false,
        }
    }

    pub fn content_position(&self) -> u64 {
        self.content_position
    }

    pub fn at_root(&self) -> bool {
        self.content_position < self.config.group_size as u64 && self.stack_depth == 1
    }

    fn at_eof(&self) -> bool {
        if let Some(content_len) = self.content_len {
            if self.content_position >= content_len {
                if self.final_group_validated {
                    // It's security critical that we never get to EOF without
                    // having validated the final chunk. This is part of the
                    // "final chunk requirement" in the spec.
                    return true;
                }
                // For content_len == 0, reads won't move the offset, and the
                // final_group_validated flag is usually the only way to tell
                // that we've gotten to EOF. But for any non-empty encoding, we
                // shouldn't be able to pass the EOF offset without also
                // validating the final chunk.
                if content_len > 0 {
                    debug_assert!(self.content_position < content_len);
                }
            }
        }
        false
    }

    fn next_group_start(&self) -> u64 {
        debug_assert!(!self.at_eof(), "not valid at EOF");
        self.content_position - (self.content_position % self.config.group_size as u64)
    }

    fn next_group_index(&self) -> u64 {
        debug_assert!(!self.at_eof(), "not valid at EOF");
        self.content_position / self.config.group_size as u64
    }

    fn reset_to_root(&mut self) {
        let content_len = self.content_len.expect("reset before header");
        self.content_position = 0;
        self.encoding_position = HEADER_SIZE as u64;
        self.stack_depth = 1;
        self.upcoming_parents = pre_order_parent_nodes(self.config, 0, content_len);
        // The final_group_validated flag is left alone. If the caller has
        // already validated the final chunk, then they can do EOF-relative
        // seeks or read the length without paying that cost again.
    }

    // Reading is done in a loop. The caller may need to read and process
    // several parent nodes before encountering the next group. Done indicates
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
            NextRead::Parent
        } else {
            let skip = self.content_position % self.config.group_size as u64;
            NextRead::ChunkGroup {
                size: self
                    .config
                    .group_size_by_index(self.next_group_index(), content_len),
                is_root: self.at_root(),
                skip: skip as usize,
                input_offset: self.content_position - skip,
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
    // Usually seeking won't instruct the caller to read any chunks/groups, but will
    // instead stop when it gets to the position where the next read loop will
    // finish by reading the target group. This gives the caller more
    // flexibility to read chunk data directly into the destination buffer,
    // rather than copying it twice.
    //
    // The one exception is seeking to or past the end. In that case seek will
    // instruct the caller to read (and validate, if applicable) the final
    // group. This is part of the "final chunk requirement" described in the
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
        // chunk/group has already been validated. If not, we need to validate it as
        // part of seeking.
        let mut verifying_final_group = false;
        if seek_to >= content_len {
            if self.final_group_validated {
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
            verifying_final_group = true;
        }

        // If seek_to is to the left of the next group, reset the whole state,
        // so that we can re-traverse from the beginning. The caller will have
        // to execute an underlying seek in this case. However, if seek_to is
        // just to a different skip offset within the next group, resetting is
        // unnecessary, which is why we use next_group_start() instead of
        // content_position.
        if self.at_eof() || seek_to < self.next_group_start() {
            self.reset_to_root();
        }

        // Now the meat of the seek computation. We know the seek is into or to
        // the right of the next group, and not EOF. Ascend out of as many
        // subtrees as necessary, until we're in the subtree containing the
        // target, and then either finish the seek or descend.
        loop {
            // If the target is within the next group, the seek is usually
            // finished. In that case we set the content_position to the exact
            // seek target, so that if it's in the middle of the group, then
            // the next read will compute the correct skip. The exception is a
            // repointed EOF seek, where we instruct the caller to read the
            // final chunk and call seek_next again.
            let distance = seek_to - self.next_group_start();
            if distance < self.config.group_size as u64 {
                if verifying_final_group {
                    let size = (content_len - self.next_group_start()) as usize;
                    return NextRead::ChunkGroup {
                        size,
                        is_root: self.at_root(),
                        skip: size, // Skip the whole thing.
                        input_offset: self.next_group_start() as u64,
                    };
                } else {
                    self.content_position = seek_to;
                    return NextRead::Done;
                }
            }

            // If the target is within the current subtree but not the next
            // group, we need to descend. Down-shift the distance rather than
            // computing the maximum subtree size, to prevent overflow.
            let downshifted_distance = distance
                .checked_shr(self.upcoming_parents as u32)
                .unwrap_or(0);
            if downshifted_distance < self.config.group_size as u64 {
                debug_assert!(self.upcoming_parents > 0);
                return NextRead::Parent;
            }

            // Otherwise jump out of the current subtree and loop. In this case
            // we know the subtree size is maximal, and computing it won't
            // overflow. The caller will have to execute an underlying seek in
            // this case.
            let subtree_size = (self.config.group_size as u64) << self.upcoming_parents;
            self.content_position = self.next_group_start() + subtree_size;
            self.encoding_position += self.config.encoded_subtree_size(subtree_size);
            self.stack_depth -= 1;
            // This depends on the update to content_position immediately above.
            self.upcoming_parents =
                pre_order_parent_nodes(self.config, self.next_group_index(), content_len);
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
            // We can only return the length once the final group has been
            // validated. This is the "final chunk requirement".
            if self.final_group_validated {
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
        let content_len = crate::decode_len(header);
        self.content_len = Some(content_len);
        self.reset_to_root();
    }

    pub fn advance_parent(&mut self) {
        debug_assert!(
            self.upcoming_parents > 0,
            "too many calls to advance_parent"
        );
        self.encoding_position += PARENT_SIZE as u64;
        self.stack_depth += 1;
        self.upcoming_parents -= 1;
    }

    pub fn advance_group(&mut self) {
        debug_assert_eq!(
            0, self.upcoming_parents,
            "advance_group with non-zero upcoming parents"
        );
        let content_len = self.content_len.expect("advance_group before header");
        let size = self
            .config
            .group_size_by_index(self.next_group_index(), content_len);
        let skip = self.content_position % self.config.group_size as u64;
        self.content_position += size as u64 - skip;
        self.encoding_position += size as u64;
        self.stack_depth -= 1;
        if self.content_position >= content_len {
            debug_assert_eq!(self.content_position, content_len, "position past EOF");
            // We just validated the final group. This is the *only line* where
            // we satisfy the "final chunk requirement". Any transition into an
            // EOF state must go through this line of code.
            self.final_group_validated = true;
        } else {
            // upcoming_parents is only meaningful if we're before EOF.
            self.upcoming_parents =
                pre_order_parent_nodes(self.config, self.next_group_index(), content_len);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NextRead {
    Header,
    Parent,
    ChunkGroup {
        size: usize,
        is_root: bool,
        skip: usize,
        input_offset: u64,
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

    pub fn underlying_seek(&self) -> Option<u64> {
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
            let content = self.new_state.next_group_start();
            let outboard = self.new_state.encoding_position - content;
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

impl<T: Read + Seek> crate::SliceExtractor<T, T> {
    /// Create a new `SliceExtractor` to read from a combined encoding with the default chunk group
    /// size (16 KiB). Note that `slice_start` and `slice_len` are with respect to the *content* of
    /// the encoding, that is, the *original* input bytes. This corresponds to `bao slice
    /// slice_start slice_len`.
    pub fn new(input: T, slice_start: u64, slice_len: u64) -> Self {
        Config::default().new_slice_extractor(input, slice_start, slice_len)
    }
}

impl<T: Read + Seek, O: Read + Seek> crate::SliceExtractor<T, O> {
    /// Create a new `SliceExtractor` to read from an unmodified input file and an outboard
    /// encoding of that same file (see `Encoder::new_outboard`) with the default chunk group size
    /// (16 KiB). As with `SliceExtractor::new`, `slice_start` and `slice_len` are with respect to
    /// the *content* of the encoding, that is, the *original* input bytes. This corresponds to
    /// `bao slice slice_start slice_len --outboard`.
    pub fn new_outboard(input: T, outboard: O, slice_start: u64, slice_len: u64) -> Self {
        Config::default().new_outboard_slice_extractor(input, outboard, slice_start, slice_len)
    }

    /// Return the underlying readers. The second reader is `Some` if and only if this
    /// `SliceExtractor` was created with `new_outboard`.
    pub fn into_inner(self) -> (T, Option<O>) {
        (self.input, self.outboard)
    }

    pub(crate) fn new_inner(
        config: Config,
        input: T,
        outboard: Option<O>,
        slice_start: u64,
        slice_len: u64,
    ) -> Self {
        Self {
            input,
            outboard,
            slice_start,
            // Always try to include at least one byte.
            slice_len: cmp::max(slice_len, 1),
            slice_bytes_read: 0,
            parser: ParseState::new(config),
            buf: vec![0; config.group_size],
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
        let header = self.buf.first_chunk_mut::<HEADER_SIZE>().unwrap();
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
        let parent = self.buf.first_chunk_mut::<PARENT_SIZE>().unwrap();
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

    fn read_group(&mut self, size: usize, skip: usize) -> io::Result<()> {
        debug_assert_eq!(0, self.buf_len(), "read_group with nonempty buffer");
        let group = &mut self.buf[..size];
        self.input.read_exact(group)?;
        self.buf_start = 0;
        self.buf_end = size;
        // After reading a group, increment slice_bytes_read. This will stop
        // the read loop once we've read everything the caller asked for. If
        // the read indicates we should skip partway into the group (because
        // the target of the previous seek was in the middle), we don't count
        // skipped bytes against the total.
        self.slice_bytes_read += (size - skip) as u64;
        self.parser.advance_group();
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
                    self.input.seek(SeekFrom::Start(encoding_position))?;
                }
            }
            let next_read = self.parser.seek_bookkeeping_done(bookkeeping);
            match next_read {
                NextRead::Header => return self.read_header(),
                NextRead::Parent => return self.read_parent(),
                NextRead::ChunkGroup { size, skip, .. } => return self.read_group(size, skip),
                NextRead::Done => self.seek_done = true, // Fall through to read.
            }
        }

        // If we haven't finished the read yet, do a step of that. If we've already supplied all
        // the requested bytes, however, don't read any more.
        if self.slice_bytes_read < self.slice_len {
            match self.parser.read_next() {
                NextRead::Header => unreachable!(),
                NextRead::Parent => return self.read_parent(),
                NextRead::ChunkGroup { size, skip, .. } => return self.read_group(size, skip),
                NextRead::Done => {} // EOF
            }
        }

        Ok(())
    }
}

impl<T: Read + Seek, O: Read + Seek> Read for crate::SliceExtractor<T, O> {
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::decode::make_test_input;
    use crate::CHUNK_SIZE;

    pub const INTERESTING_GROUP_SIZES: &[usize] =
        &[CHUNK_SIZE, 2 * CHUNK_SIZE, 16 * CHUNK_SIZE, 64 * CHUNK_SIZE];

    #[test]
    fn test_encode() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = blake3::hash(&input);
            let (encoded, hash) = crate::encode(&input);
            assert_eq!(expected_hash, hash);
            assert_eq!(
                encoded.len() as u64,
                Config::default().encoded_size(case as u64),
            );
            assert_eq!(encoded.len(), encoded.capacity());
            assert_eq!(
                encoded.len() as u64,
                case as u64 + Config::default().outboard_size(case as u64)
            );
        }
    }

    #[test]
    fn test_outboard_encode() {
        for &case in crate::test::TEST_CASES {
            println!("case {}", case);
            let input = make_test_input(case);
            let expected_hash = blake3::hash(&input);
            let (outboard, hash) = Config::default().encode_outboard(&input);
            assert_eq!(expected_hash, hash);
            assert_eq!(
                outboard.len() as u64,
                Config::default().outboard_size(case as u64),
            );
            assert_eq!(outboard.len(), outboard.capacity());
        }
    }

    fn largest_power_of_two_leq(n: u64) -> u64 {
        ((n / 2) + 1).next_power_of_two()
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
            let split = largest_power_of_two_leq(size - 1);
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
        for &group_size in INTERESTING_GROUP_SIZES {
            let config = Config::new(group_size);
            for total_groups in 1..100 {
                let content_len = total_groups * group_size as u64;
                let pre_post_list = make_pre_post_list(total_groups);
                for group in 0..total_groups {
                    let (expected_pre, expected_post) = pre_post_list[group as usize];
                    let pre = pre_order_parent_nodes(config, group, content_len);
                    let post = if group < total_groups - 1 {
                        post_order_parent_nodes_nonfinal(group)
                    } else {
                        post_order_parent_nodes_final(group)
                    };
                    assert_eq!(
                        expected_pre, pre,
                        "incorrect pre-order parent nodes for group {} of total {}",
                        group, total_groups
                    );
                    assert_eq!(
                        expected_post, post,
                        "incorrect post-order parent nodes for group {} of total {}",
                        group, total_groups
                    );
                }
            }
        }
    }

    fn drive_state(config: Config, mut input: &[u8]) -> Hash {
        if input.len() <= config.group_size {
            return blake3::hash(input);
        }
        let mut state = State::new();
        let mut input_offset = 0;
        while input.len() > config.group_size {
            let hash = Hasher::new()
                .set_input_offset(input_offset)
                .update(&input[..config.group_size])
                .finalize_non_root()
                .into();
            input_offset += config.group_size as u64;
            // Throw away parent nodes. We don't need them.
            _ = state.push_subtree(&hash);
            input = &input[config.group_size..];
        }
        let cv = Hasher::new()
            .set_input_offset(input_offset)
            .update(input)
            .finalize_non_root();
        // Again ignore the parent nodes.
        let (hash, _) = state.merge_finalize(&cv);
        hash
    }

    // These tests just check the different implementations against each other,
    // but explicit test vectors are included in test_vectors.json and checked
    // in the integration tests.

    #[test]
    fn test_state() {
        let buf = [0x42; 65537];
        for &group_size in INTERESTING_GROUP_SIZES {
            dbg!(group_size);
            let config = Config::new(group_size);
            for &case in crate::test::TEST_CASES {
                dbg!(case);
                let input = &buf[..case];
                let expected = blake3::hash(&input);
                let found = drive_state(config, &input);
                assert_eq!(expected, found, "hashes don't match");
            }
        }
    }

    #[test]
    #[should_panic]
    fn test_finalize_twice_panics() {
        let mut encoder = Encoder::new(io::Cursor::new(Vec::<u8>::new()));
        let _ = encoder.finalize();
        let _ = encoder.finalize();
    }

    #[test]
    #[should_panic]
    fn test_write_after_finalize_panics() {
        let mut encoder = Encoder::new(io::Cursor::new(Vec::<u8>::new()));
        let _ = encoder.finalize();
        let _ = encoder.write(&[]);
    }

    #[test]
    fn test_into_inner() {
        let v = vec![1u8, 2, 3];
        let encoder = Encoder::new(io::Cursor::new(v.clone()));
        let extractor =
            crate::SliceExtractor::new(io::Cursor::new(encoder.into_inner().into_inner()), 0, 0);
        let (r1, r2) = extractor.into_inner();
        assert_eq!(r1.into_inner(), v);
        assert_eq!(r2, None);

        let outboard = crate::SliceExtractor::new_outboard(
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
        let mut encoder = Encoder::new(io::Cursor::new(&mut output));
        encoder.write_all(input).unwrap();
        encoder.write(&[]).unwrap();
        let hash = encoder.finalize().unwrap();
        assert_eq!((output, hash), crate::encode(input));
        assert_eq!(hash, blake3::hash(input));
    }
}
