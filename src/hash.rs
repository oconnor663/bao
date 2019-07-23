//! Compute a Bao hash from some input bytes.
//!
//! # Example
//!
//! ```
//! let hash_at_once = bao::hash::hash(b"input bytes");
//!
//! let mut hasher = bao::hash::Writer::new();
//! hasher.update(b"input");
//! hasher.update(b" ");
//! hasher.update(b"bytes");
//! let hash_incremental = hasher.finish();
//!
//! assert_eq!(hash_at_once, hash_incremental);
//! ```

use arrayref::{array_mut_ref, array_ref};
use arrayvec::{ArrayString, ArrayVec};
use blake2s_simd;
use blake2s_simd::many::{HashManyJob, MAX_DEGREE as MAX_SIMD_DEGREE};
use core::cmp;
use core::fmt;
use core::mem;
#[cfg(feature = "std")]
use rayon;
#[cfg(feature = "std")]
use std::io;

/// The size of a `Hash`, 32 bytes.
pub const HASH_SIZE: usize = 32;
pub(crate) const PARENT_SIZE: usize = 2 * HASH_SIZE;
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) const CHUNK_SIZE: usize = 4096;
// NOTE: The max stack depth described in the spec is 52. However this
// implementation pushes the final chunk hash onto the stack before running the
// merge loop, so we need space for one more. That said, 2^52 bytes is already
// an astronomical amount of input that will probably never come up in
// practice.
pub(crate) const MAX_DEPTH: usize = 53;
pub(crate) const MAX_SINGLE_THREADED: usize = 8 * CHUNK_SIZE;

/// An array of `HASH_SIZE` bytes. This will be a wrapper type in a future version.
pub(crate) type ParentNode = [u8; 2 * HASH_SIZE];

/// A Bao hash, with constant-time equality.
#[derive(Clone, Copy)]
pub struct Hash {
    bytes: [u8; HASH_SIZE],
}

impl Hash {
    /// Create a new `Hash` from an array of bytes.
    pub fn new(bytes: &[u8; HASH_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Convert the `Hash` to a byte array. Note that the array type doesn't provide constant time
    /// equality.
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.bytes
    }

    /// Convert the `Hash` to a lowercase hexadecimal
    /// [`ArrayString`](https://docs.rs/arrayvec/0.4/arrayvec/struct.ArrayString.html).
    pub fn to_hex(&self) -> ArrayString<[u8; 2 * HASH_SIZE]> {
        let mut s = ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.bytes.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }
}

/// This implementation is constant time.
impl PartialEq for Hash {
    fn eq(&self, other: &Hash) -> bool {
        constant_time_eq::constant_time_eq(&self.bytes[..], &other.bytes[..])
    }
}

/// This implementation is constant time, if the slice length is `HASH_SIZE`.
impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(&self.bytes[..], other)
    }
}

impl Eq for Hash {}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

pub(crate) fn encode_len(len: u64) -> [u8; HEADER_SIZE] {
    debug_assert_eq!(mem::size_of_val(&len), HEADER_SIZE);
    len.to_le_bytes()
}

pub(crate) fn decode_len(bytes: &[u8; HEADER_SIZE]) -> u64 {
    u64::from_le_bytes(*bytes)
}

fn common_params() -> blake2s_simd::Params {
    let mut params = blake2s_simd::Params::new();
    params
        .hash_length(HASH_SIZE)
        .fanout(2)
        .max_depth(255)
        .max_leaf_length(CHUNK_SIZE as u32)
        .inner_hash_length(HASH_SIZE);
    params
}

// TODO: Clean up these helpers when there are fewer callers.
fn chunk_params_old() -> blake2s_simd::Params {
    let mut params = common_params();
    params.node_depth(0);
    params
}

fn parent_params_old() -> blake2s_simd::Params {
    let mut params = common_params();
    params.node_depth(1);
    params
}

pub(crate) fn new_chunk_state() -> blake2s_simd::State {
    chunk_params_old().to_state()
}

pub(crate) fn new_parent_state() -> blake2s_simd::State {
    parent_params_old().to_state()
}

// The root node is hashed differently from interior nodes. It gets suffixed
// with the length of the entire input, and we set the Blake2 final node flag.
// That means that no root hash can ever collide with an interior hash, or with
// the root of a different size tree.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Finalization {
    NotRoot,
    Root,
}
use self::Finalization::{NotRoot, Root};

pub(crate) fn finalize_hash(state: &mut blake2s_simd::State, finalization: Finalization) -> Hash {
    // For the root node, we set the Blake2 last node flag. One of the reasons
    // for this design is that we don't need to know a given node is the root
    // until the very end, so we don't always need a chunk buffer.
    if let Root = finalization {
        state.set_last_node(true);
    }
    let blake_digest = state.finalize();
    Hash {
        bytes: *array_ref!(blake_digest.as_bytes(), 0, HASH_SIZE),
    }
}

pub(crate) fn hash_chunk(chunk: &[u8], finalization: Finalization) -> Hash {
    debug_assert!(chunk.len() <= CHUNK_SIZE);
    let mut state = new_chunk_state();
    state.update(chunk);
    finalize_hash(&mut state, finalization)
}

pub(crate) fn hash_parent(parent: &[u8], finalization: Finalization) -> Hash {
    debug_assert_eq!(parent.len(), PARENT_SIZE);
    let mut state = new_parent_state();
    state.update(parent);
    finalize_hash(&mut state, finalization)
}

pub(crate) fn parent_hash(left_hash: &Hash, right_hash: &Hash, finalization: Finalization) -> Hash {
    let mut state = new_parent_state();
    state.update(left_hash.as_bytes());
    state.update(right_hash.as_bytes());
    finalize_hash(&mut state, finalization)
}

// Find the largest power of two that's less than or equal to `n`. We use this
// for computing subtree sizes below.
pub(crate) fn largest_power_of_two_leq(n: u64) -> u64 {
    ((n / 2) + 1).next_power_of_two()
}

// Given some input larger than one chunk, find the largest perfect tree of
// chunks that can go on the left.
pub(crate) fn left_len(content_len: u64) -> u64 {
    debug_assert!(content_len > CHUNK_SIZE as u64);
    // Subtract 1 to reserve at least one byte for the right side.
    let full_chunks = (content_len - 1) / CHUNK_SIZE as u64;
    largest_power_of_two_leq(full_chunks) * CHUNK_SIZE as u64
}

fn chunk_params(finalization: Finalization) -> blake2s_simd::Params {
    let mut params = common_params();
    if let Root = finalization {
        params.last_node(true);
    }
    params
}

fn parent_params(finalization: Finalization) -> blake2s_simd::Params {
    let mut params = common_params();
    params.node_depth(1);
    if let Root = finalization {
        params.last_node(true);
    }
    params
}

// Hash a single layer of child hashes into parents. If there's an unpaired
// child left over, append it to the outputs. Return the number of outputs
// written to `out` (including the unpaired child if any). Rather than
// returning a single subtree hash, return a set of simd_degree hashes (if
// there's enough children). That lets each level of the tree take full
// advantage of SIMD parallelism.
fn hash_parents_simd(children: &[u8], finalization: Finalization, out: &mut [u8]) -> usize {
    debug_assert_eq!(children.len() % HASH_SIZE, 0);
    // finalization=Root means that the current set of children will form the
    // top of the tree, but we can't actually apply Root finalization until we
    // get to the very top node.
    let actual_finalization = if children.len() == 2 * HASH_SIZE {
        finalization
    } else {
        NotRoot
    };
    let params = parent_params(actual_finalization);
    let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = ArrayVec::new();
    let mut pairs = children.chunks_exact(2 * HASH_SIZE);
    for pair in &mut pairs {
        let push_result = jobs.try_push(HashManyJob::new(&params, pair));
        debug_assert!(push_result.is_ok(), "too many pushes");
    }
    blake2s_simd::many::hash_many(&mut jobs);
    let mut out_hashes = out.chunks_exact_mut(HASH_SIZE);
    let mut outputs = 0;
    for (job, out_hash) in jobs.iter().zip(&mut out_hashes) {
        *array_mut_ref!(out_hash, 0, HASH_SIZE) = *job.to_hash().as_array();
        outputs += 1;
    }
    // The leftover child case.
    let leftover = pairs.remainder();
    if leftover.len() == HASH_SIZE {
        if let Some(out_hash) = out_hashes.next() {
            *array_mut_ref!(out_hash, 0, HASH_SIZE) = *array_ref!(leftover, 0, HASH_SIZE);
            outputs += 1;
        }
    }
    outputs
}

#[cfg(feature = "std")]
fn join<T: Send>(f1: impl Send + FnOnce() -> T, f2: impl Send + FnOnce() -> T) -> (T, T) {
    rayon::join(f1, f2)
}

#[cfg(not(feature = "std"))]
fn join<T: Send>(f1: impl Send + FnOnce() -> T, f2: impl Send + FnOnce() -> T) -> (T, T) {
    (f1(), f2())
}

// Recursively split the input, combining child hashes into parent hashes at
// each level. Rather than returning a single subtree hash, return a set of
// simd_degree hashes (if there's enough children). That lets each level of the
// tree take full advantage of SIMD parallelism.
fn hash_recurse(
    input: &[u8],
    finalization: Finalization,
    simd_degree: usize,
    out: &mut [u8],
) -> usize {
    // The top level handles the one chunk case.
    debug_assert!(input.len() > 0);

    if input.len() <= simd_degree * CHUNK_SIZE {
        // Because the top level handles the one chunk case, chunk hashing is
        // never Root.
        let chunk_params = chunk_params(NotRoot);
        let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = ArrayVec::new();
        for chunk in input.chunks(CHUNK_SIZE) {
            let push_result = jobs.try_push(HashManyJob::new(&chunk_params, chunk));
            debug_assert!(push_result.is_ok(), "too many pushes");
        }
        blake2s_simd::many::hash_many(jobs.iter_mut());
        for (job, dest) in jobs.iter_mut().zip(out.chunks_exact_mut(HASH_SIZE)) {
            *array_mut_ref!(dest, 0, HASH_SIZE) = *job.to_hash().as_array();
        }
        return jobs.len();
    }

    let (left_input, right_input) = input.split_at(left_len(input.len() as u64) as usize);
    let mut child_out_array = [0; 2 * MAX_SIMD_DEGREE * HASH_SIZE];
    let (left_out, right_out) = child_out_array.split_at_mut(simd_degree * HASH_SIZE);
    let (left_n, right_n) = join(
        || hash_recurse(left_input, NotRoot, simd_degree, left_out),
        || hash_recurse(right_input, NotRoot, simd_degree, right_out),
    );
    // Do one level of parent hashing and give the resulting parent hashes to
    // the caller. We can assert that the left_out slice was filled, which
    // means all the child hashes are laid out contiguously. Note that if the
    // input was less than simd_degree chunks long, recursion will bottom out
    // immediately at the chunks branch above, and we will never get here.
    debug_assert_eq!(simd_degree, left_n, "left subtree always full");
    let num_children = left_n + right_n;
    let children_slice = &child_out_array[..num_children * HASH_SIZE];
    hash_parents_simd(children_slice, finalization, out)
}

// Combine all the children into a single subtree hash, which may be the root.
fn condense_parents(mut children: &mut [u8], finalization: Finalization) -> Hash {
    debug_assert_eq!(children.len() % HASH_SIZE, 0);
    let mut out_array = [0; MAX_SIMD_DEGREE * HASH_SIZE / 2];
    loop {
        if children.len() == HASH_SIZE {
            return Hash {
                bytes: *array_ref!(children, 0, HASH_SIZE),
            };
        }
        let out_n = hash_parents_simd(children, finalization, &mut out_array);
        children[..out_n * HASH_SIZE].copy_from_slice(&out_array[..out_n * HASH_SIZE]);
        children = &mut children[..out_n * HASH_SIZE];
    }
}

/// Hash a slice of input bytes all at once. If the `std` feature is enabled, as it is by default,
/// this will use multiple threads via Rayon. This is the fastest hashing implementation.
///
/// # Example
///
/// ```
/// let hash_at_once = bao::hash::hash(b"input bytes");
/// ```
pub fn hash(input: &[u8]) -> Hash {
    // Handle the single chunk case explicitly.
    if input.len() <= CHUNK_SIZE {
        return Hash::new(chunk_params(Root).hash(input).as_array());
    }
    let simd_degree = blake2s_simd::many::degree();
    let mut children_array = [0; MAX_SIMD_DEGREE * HASH_SIZE];

    let num_children = hash_recurse(input, Root, simd_degree, &mut children_array);

    if simd_degree == 1 {
        debug_assert_eq!(num_children, 1);
    } else {
        debug_assert!(num_children > 1);
    }

    condense_parents(&mut children_array[..num_children * HASH_SIZE], Root)
}

pub(crate) enum StateFinish {
    Parent(ParentNode),
    Root(Hash),
}

/// A minimal state object for incrementally hashing input. Most callers should use the `Writer`
/// interface instead.
///
/// This is designed to be useful for as many callers as possible, including `no_std` callers. It
/// handles merging subtrees and keeps track of subtrees assembled so far. It takes only hashes as
/// input, rather than raw input bytes, so it can be used with e.g. multiple threads hashing chunks
/// in parallel. Callers that need `ParentNode` bytes for building the encoded tree, can use the
/// optional `merge_parent` and `merge_finish` interfaces.
///
/// This struct contains a relatively large buffer on the stack for holding partial subtree hashes:
/// 64 hashes at 32 bytes apiece, 2048 bytes in total. This is enough state space for the largest
/// possible input, `2^64 - 1` bytes or about 18 exabytes. That's impractically large for anything
/// that could be hashed in the real world, and implementations that are starved for stack space
/// could cut that buffer in half and still be able to hash about 17 terabytes (`2^32` times the
/// 4096-byte chunk size).
///
/// Note that this type used to be public, but is currently private. It could be re-exposed if
/// there's demand from no_std callers.
#[derive(Clone)]
pub(crate) struct State {
    subtrees: ArrayVec<[Hash; MAX_DEPTH]>,
    total_len: u64,
}

impl State {
    pub fn new() -> Self {
        Self {
            subtrees: ArrayVec::new(),
            total_len: 0,
        }
    }

    fn count(&self) -> u64 {
        self.total_len
    }

    fn merge_inner(&mut self, finalization: Finalization) -> ParentNode {
        let right_child = self.subtrees.pop().unwrap();
        let left_child = self.subtrees.pop().unwrap();
        let mut parent_node = [0; PARENT_SIZE];
        parent_node[..HASH_SIZE].copy_from_slice(left_child.as_bytes());
        parent_node[HASH_SIZE..].copy_from_slice(right_child.as_bytes());
        let parent_hash = parent_hash(&left_child, &right_child, finalization);
        self.subtrees.push(parent_hash);
        parent_node
    }

    // We keep the subtree hashes in an array without storing their size, and we use this cute
    // trick to figure out when we should merge them. Because every subtree (prior to the
    // finalization step) is a power of two times the chunk size, adding a new subtree to the
    // right/small end is a lot like adding a 1 to a binary number, and merging subtrees is like
    // propagating the carry bit. Each carry represents a place where two subtrees need to be
    // merged, and the final number of 1 bits is the same as the final number of subtrees.
    fn needs_merge(&self) -> bool {
        let chunks = self.total_len / CHUNK_SIZE as u64;
        self.subtrees.len() > chunks.count_ones() as usize
    }

    /// Add a subtree hash to the state.
    ///
    /// For most callers, this will always be the hash of a `CHUNK_SIZE` chunk of input bytes, with
    /// the final chunk possibly having fewer bytes. It's possible to use input subtrees larger
    /// than a single chunk, as long as the size is a power of 2 times `CHUNK_SIZE` and again kept
    /// constant until the final chunk. This can be helpful in a multi-threaded setting, where you
    /// want to hash more than one chunk at a time per thread, but most callers should stick with
    /// single chunks.
    ///
    /// In cases where the total input is a single chunk or less, including the case with no input
    /// bytes at all, callers are expected to finalize that chunk themselves before pushing. (Or
    /// just ignore the State object entirely.) It's of course impossible to back out the input
    /// bytes and re-finalize them.
    ///
    /// # Panic
    ///
    /// This will panic if the total input length overflows a `u64`.
    pub fn push_subtree(&mut self, hash: &Hash, len: usize) {
        // Merge any subtrees that need to be merged before pushing. In the encoding case, the
        // caller will already have done this via merge_parent(), but in the hashing case the
        // caller doesn't care about the parent nodes.
        while self.needs_merge() {
            self.merge_inner(NotRoot);
        }
        self.subtrees.push(*hash);
        // Overflow in the length is practically impossible if we're actually hashing the input,
        // since it would take several hundred CPU years of work. But it could happen if we're
        // doing something fancy with a sparse tree. In general, the Bao hash of more than u64::MAX
        // bytes is not defined, and a correct implementation should refuse to compute it.
        self.total_len = self
            .total_len
            .checked_add(len as u64)
            .expect("addition overflowed");
    }

    /// Returns a `ParentNode` corresponding to a just-completed subtree, if any.
    ///
    /// Callers that want parent node bytes (to build an encoded tree) must call `merge_parent` in
    /// a loop, until it returns `None`. Parent nodes are yielded in smallest-to-largest order.
    /// Callers that only want the final root hash can ignore this function; the next call to
    /// `push_subtree` will take care of merging in that case.
    ///
    /// After the final call to `push_subtree`, you must call `merge_finish` in a loop instead of
    /// this function.
    pub fn merge_parent(&mut self) -> Option<ParentNode> {
        if !self.needs_merge() {
            return None;
        }
        Some(self.merge_inner(NotRoot))
    }

    /// Returns a tuple of `ParentNode` bytes and (in the last call only) the root hash. Callers
    /// who need `ParentNode` bytes must call `merge_finish` in a loop after pushing the final
    /// subtree, until the second return value is `Some`. Callers who don't need parent nodes
    /// should use the simpler `finish` interface instead.
    pub fn merge_finish(&mut self) -> StateFinish {
        if self.subtrees.len() > 2 {
            StateFinish::Parent(self.merge_inner(NotRoot))
        } else if self.subtrees.len() == 2 {
            StateFinish::Parent(self.merge_inner(Root))
        } else {
            StateFinish::Root(self.subtrees[0])
        }
    }

    /// A wrapper around `merge_finish` for callers who don't need the parent
    /// nodes.
    pub fn finish(&mut self) -> Hash {
        loop {
            match self.merge_finish() {
                StateFinish::Parent(_) => {} // ignored
                StateFinish::Root(root) => return root,
            }
        }
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Avoid printing hashes, they might be secret.
        write!(f, "State {{ ... }}")
    }
}

pub const BUF_LEN: usize = MAX_SIMD_DEGREE * CHUNK_SIZE;

/// An incremental hasher. `Writer` is no_std-compatible and does not allocate.
/// The implementation is single-threaded but uses SIMD parallelism.
///
/// # Example
/// ```
/// let mut hasher = bao::hash::Writer::new();
/// hasher.update(b"input");
/// hasher.update(b" ");
/// hasher.update(b"bytes");
/// let hash_incremental = hasher.finish();
/// ```
#[derive(Clone, Debug)]
pub struct Writer {
    chunk_state: blake2s_simd::State,
    tree_state: State,
}

impl Writer {
    /// Create a new `Writer`.
    pub fn new() -> Self {
        Self {
            chunk_state: new_chunk_state(),
            tree_state: State::new(),
        }
    }

    /// Add input to the hash. This is equivalent to `write`, except that it's
    /// also available with `no_std`. For best performance, use an input buffer
    /// of size `BUF_LEN`, or some integer multiple of that.
    pub fn update(&mut self, mut input: &[u8]) {
        // In normal operation, we hash every chunk that comes in using SIMD
        // and push those hashes into the tree state, only retaining a partial
        // chunk in the chunk_state if there's uneven input left over. However,
        // the first chunk is a special case: If we receive exactly one chunk
        // on the first call, we have to retain it in the chunk_state, because
        // we won't know how to finalize it until we get more input. (Receiving
        // less than one chunk would retain it in any case, as uneven input
        // left over.)
        let maybe_root = self.tree_state.count() == 0 && input.len() <= CHUNK_SIZE;
        let have_partial_chunk = self.chunk_state.count() > 0;
        if maybe_root || have_partial_chunk {
            let want = CHUNK_SIZE - self.chunk_state.count() as usize;
            let take = cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];

            // If there's more input coming, finish the chunk before we
            // continue. Otherwise short circuit.
            if !input.is_empty() {
                let chunk_hash = finalize_hash(&mut self.chunk_state, NotRoot);
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
                self.chunk_state = new_chunk_state();
            } else {
                return;
            }
        }

        // Hash all the full chunks that we can, in parallel using SIMD, and
        // incorporate those hashes into the tree state. At this point we know
        // none of these can be the root. Here all the parent hash work is
        // serial, so there's some overhead compared to the fully parallel (not
        // to mention multithreaded) all-at-once hash() function.
        let params = chunk_params(NotRoot);
        let mut chunks = input.chunks_exact(CHUNK_SIZE);
        let mut fused_chunks = chunks.by_ref().fuse();
        loop {
            let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = fused_chunks
                .by_ref()
                .take(MAX_SIMD_DEGREE)
                .map(|chunk| HashManyJob::new(&params, chunk))
                .collect();
            if jobs.is_empty() {
                break;
            }
            blake2s_simd::many::hash_many(&mut jobs);
            for job in &jobs {
                let chunk_hash = Hash::new(job.to_hash().as_array());
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            }
        }

        // Retain any remaining bytes in the chunk_state.
        debug_assert!(chunks.remainder().len() < CHUNK_SIZE);
        debug_assert_eq!(self.chunk_state.count(), 0);
        self.chunk_state.update(chunks.remainder());
    }

    /// Finish computing the root hash. The writer cannot be used after this.
    pub fn finish(&mut self) -> Hash {
        // If the chunk_state contains any chunk data, we have to finalize it
        // and incorporate it into the tree. Also, if there was never any data
        // at all, we have to hash the empty chunk.
        if self.chunk_state.count() > 0 || self.tree_state.count() == 0 {
            let finalization = if self.tree_state.count() == 0 {
                Root
            } else {
                NotRoot
            };
            let hash = finalize_hash(&mut self.chunk_state, finalization);
            self.tree_state
                .push_subtree(&hash, self.chunk_state.count() as usize);
        }
        self.tree_state.finish()
    }
}

#[cfg(feature = "std")]
impl io::Write for Writer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.update(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[doc(hidden)]
pub mod benchmarks {
    pub const CHUNK_SIZE: usize = super::CHUNK_SIZE;
}

// Interesting input lengths to run tests on.
#[cfg(test)]
pub(crate) const TEST_CASES: &[usize] = &[
    0,
    1,
    10,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE - 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 1,
    3 * CHUNK_SIZE - 1,
    3 * CHUNK_SIZE,
    3 * CHUNK_SIZE + 1,
    4 * CHUNK_SIZE - 1,
    4 * CHUNK_SIZE,
    4 * CHUNK_SIZE + 1,
    8 * CHUNK_SIZE - 1,
    8 * CHUNK_SIZE,
    8 * CHUNK_SIZE + 1,
    16 * CHUNK_SIZE - 1,
    16 * CHUNK_SIZE,
    16 * CHUNK_SIZE + 1,
];

#[cfg(test)]
mod test {
    use super::*;
    use std::io::prelude::*;

    #[test]
    fn test_power_of_two() {
        let input_output = &[
            // The zero case is nonsensical, but it does work.
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 4),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 8),
            // the largest possible u64
            (0xffffffffffffffff, 0x8000000000000000),
        ];
        for &(input, output) in input_output {
            assert_eq!(
                output,
                largest_power_of_two_leq(input),
                "wrong output for n={}",
                input
            );
        }
    }

    #[test]
    fn test_left_subtree_len() {
        let s = CHUNK_SIZE as u64;
        let input_output = &[(s + 1, s), (2 * s - 1, s), (2 * s, s), (2 * s + 1, 2 * s)];
        for &(input, output) in input_output {
            println!("testing {} and {}", input, output);
            assert_eq!(left_len(input), output);
        }
    }

    fn drive_state(mut input: &[u8]) -> Hash {
        let mut state = State::new();
        let finalization = if input.len() <= CHUNK_SIZE {
            Root
        } else {
            NotRoot
        };
        while input.len() > CHUNK_SIZE {
            let hash = hash_chunk(&input[..CHUNK_SIZE], NotRoot);
            state.push_subtree(&hash, CHUNK_SIZE);
            input = &input[CHUNK_SIZE..];
        }
        let hash = hash_chunk(input, finalization);
        state.push_subtree(&hash, input.len());
        state.finish()
    }

    // These tests just check the different implementations against each other,
    // but explicit test vectors are included in test_vectors.json and checked
    // in the integration tests.

    #[test]
    fn test_state() {
        for &case in TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let expected = hash(&input);
            let found = drive_state(&input);
            assert_eq!(expected, found, "hashes don't match");
        }
    }

    #[test]
    fn test_writer() {
        for &case in TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let expected = hash(&input);

            let mut writer = Writer::new();
            writer.write_all(&input).unwrap();
            let found = writer.finish();
            assert_eq!(expected, found, "hashes don't match");
        }
    }
}
