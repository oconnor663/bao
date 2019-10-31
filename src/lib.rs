//! [Repo](https://github.com/oconnor663/bao) —
//! [Crate](https://crates.io/crates/bao) —
//! [Spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//!
//! This crate implements the Bao hash function and encoding format. The `bao`
//! [command line utility](https://crates.io/crates/bao_bin) is built on top of
//! it. For more about how Bao works and what the encoding format is doing, see
//! the [project README](https://github.com/oconnor663/bao) and the [full
//! specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md).
//!
//! The `encode` and `decode` modules require the `std` feature, which is
//! enabled by default.
//!
//! **Caution!** Not yet suitable for production use. The output of Bao isn't
//! stable. There might be more changes before 1.0.
//!
//! # Example
//!
//! ```
//! let expected = "6d1128fa367a8d7f6f8dc946ede523e61b881a8b3463014520ad946dad75f820";
//! let hash = bao::hash(b"input bytes");
//! assert_eq!(expected, &hash.to_hex());
//!
//! let mut hasher = bao::Hasher::new();
//! hasher.update(b"input");
//! hasher.update(b" ");
//! hasher.update(b"bytes");
//! assert_eq!(hash, hasher.finalize());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod decode;
#[cfg(feature = "std")]
pub mod encode;

use arrayref::{array_mut_ref, array_ref};
use arrayvec::{ArrayString, ArrayVec};
use blake2s_simd;
use blake2s_simd::many::{HashManyJob, MAX_DEGREE as MAX_SIMD_DEGREE};
use core::cmp;
use core::fmt;
use core::mem;
#[cfg(feature = "std")]
use std::io;

/// The size of a `Hash`, 32 bytes.
pub const HASH_SIZE: usize = 32;
pub(crate) const PARENT_SIZE: usize = 2 * HASH_SIZE;
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) const CHUNK_SIZE: usize = 4096;
// NOTE: The max stack depth described in the spec is 52, the log-base-2 of the
// maximum number of chunks. However this implementation pushes the final chunk
// hash onto the stack before running the merge loop, so we need space for one
// more. That said, 2^64 bytes is an astronomical amount of input that will
// probably never come up in practice.
pub(crate) const MAX_DEPTH: usize = 53;

/// An array of `HASH_SIZE` bytes. This will be a wrapper type in a future version.
pub(crate) type ParentNode = [u8; 2 * HASH_SIZE];

/// A Bao hash, with constant-time equality.
#[derive(Clone, Copy)]
pub struct Hash {
    bytes: [u8; HASH_SIZE],
}

impl Hash {
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

impl From<blake2s_simd::Hash> for Hash {
    /// This calls `blake2s_simd::Hash::as_array`, which panics in debug mode
    /// if the hash length is shorter than the default.
    fn from(hash: blake2s_simd::Hash) -> Self {
        Hash {
            bytes: *hash.as_array(),
        }
    }
}

impl From<[u8; HASH_SIZE]> for Hash {
    fn from(bytes: [u8; HASH_SIZE]) -> Self {
        Hash { bytes }
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

// The root node is hashed differently from interior nodes. It gets suffixed
// with the length of the entire input, and we set the Blake2 final node flag.
// That means that no root hash can ever collide with an interior hash, or with
// the root of a different size tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finalization {
    NotRoot,
    Root,
}
use self::Finalization::{NotRoot, Root};

// Find the largest power of two that's less than or equal to `n`. We use this
// for computing subtree sizes below.
pub(crate) fn largest_power_of_two_leq(n: u64) -> u64 {
    // There are many places in this crate where we assume a usize fits in a
    // u64. Most of them wind up calling this function. Go ahead and assert
    // that here, so that things will explode if we ever run on a platform
    // where this isn't true, and we can reevaluate our life choices.
    debug_assert!(mem::size_of::<usize>() <= mem::size_of::<u64>());

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

pub(crate) fn chunk_params(finalization: Finalization, chunk_index: u64) -> blake2s_simd::Params {
    let mut params = common_params();
    // The BLAKE2X node_offset parameter maxes out at 2^32-1. Just take the
    // lower 32 bits of the offset, and allow that the offset might wrap in a
    // very large tree.
    const OFFSET_UPPER_BOUND: u64 = 1 << 32;
    params.node_offset(chunk_index % OFFSET_UPPER_BOUND);
    if let Root = finalization {
        params.last_node(true);
    }
    params
}

pub(crate) fn parent_params(finalization: Finalization) -> blake2s_simd::Params {
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

#[cfg(feature = "rayon")]
fn join<T: Send>(f1: impl Send + FnOnce() -> T, f2: impl Send + FnOnce() -> T) -> (T, T) {
    rayon::join(f1, f2)
}

#[cfg(not(feature = "rayon"))]
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
    mut chunk_index: u64,
    out: &mut [u8],
) -> usize {
    // The top level handles the one chunk case.
    debug_assert!(input.len() > 0);

    if input.len() <= simd_degree * CHUNK_SIZE {
        // Because the top level handles the one chunk case, chunk hashing is
        // never Root.
        let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = ArrayVec::new();
        for chunk in input.chunks(CHUNK_SIZE) {
            let chunk_params = chunk_params(NotRoot, chunk_index);
            chunk_index += 1;
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
    let right_chunk_index = chunk_index + (left_input.len() as u64 / CHUNK_SIZE as u64);
    let (left_n, right_n) = join(
        || hash_recurse(left_input, NotRoot, simd_degree, chunk_index, left_out),
        || {
            hash_recurse(
                right_input,
                NotRoot,
                simd_degree,
                right_chunk_index,
                right_out,
            )
        },
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

/// Hash a slice of input bytes all at once. If the `std` feature is enabled,
/// as it is by default, this will use multiple threads via Rayon. Other than
/// initializing the global threadpool, this function doesn't allocate. This is
/// the fastest hashing implementation.
///
/// # Example
///
/// ```
/// let hash_at_once = bao::hash(b"input bytes");
/// ```
pub fn hash(input: &[u8]) -> Hash {
    // Handle the single chunk case explicitly.
    if input.len() <= CHUNK_SIZE {
        return chunk_params(Root, 0).hash(input).into();
    }
    let simd_degree = blake2s_simd::many::degree();
    let mut children_array = [0; MAX_SIMD_DEGREE * HASH_SIZE];

    let num_children = hash_recurse(input, Root, simd_degree, 0, &mut children_array);

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

/// A minimal state object for incrementally hashing input. Most callers should use the `Hasher`
/// interface instead.
///
/// This is designed to be useful for as many callers as possible, including `no_std` callers. It
/// handles merging subtrees and keeps track of subtrees assembled so far. It takes only hashes as
/// input, rather than raw input bytes, so it can be used with e.g. multiple threads hashing chunks
/// in parallel. Callers that need `ParentNode` bytes for building the encoded tree, can use the
/// optional `merge_parent` and `merge_finalize` interfaces.
///
/// This struct contains a relatively large buffer on the stack for holding partial subtree hashes:
/// 53 hashes at 32 bytes apiece, 1696 bytes put together. This is enough state space for the largest
/// possible input, `2^64 - 1` bytes or about 18 exabytes. That's impractically large for anything
/// that could be hashed in the real world, and implementations that are starved for stack space
/// could use a smaller buffer and accept a tighter max input length.
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

    pub fn count(&self) -> u64 {
        self.total_len
    }

    fn merge_inner(&mut self, finalization: Finalization) -> ParentNode {
        let right_child = self.subtrees.pop().unwrap();
        let left_child = self.subtrees.pop().unwrap();
        let mut parent_node = [0; PARENT_SIZE];
        parent_node[..HASH_SIZE].copy_from_slice(left_child.as_bytes());
        parent_node[HASH_SIZE..].copy_from_slice(right_child.as_bytes());
        let parent_hash = parent_params(finalization)
            .to_state()
            .update(left_child.as_bytes())
            .update(right_child.as_bytes())
            .finalize()
            .into();
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

    /// Returns a `ParentNode` corresponding to a just-completed subtree, if
    /// any. You must not call this until you're sure there's more input
    /// coming, or else the finalization might be incorrect.
    ///
    /// Callers that want parent node bytes (to build an encoded tree) must call `merge_parent` in
    /// a loop, until it returns `None`. Parent nodes are yielded in smallest-to-largest order.
    /// Callers that only want the final root hash can ignore this function; the next call to
    /// `push_subtree` will take care of merging in that case.
    ///
    /// After the final call to `push_subtree`, you must call `merge_finalize` in a loop instead of
    /// this function.
    pub fn merge_parent(&mut self) -> Option<ParentNode> {
        if !self.needs_merge() {
            return None;
        }
        Some(self.merge_inner(NotRoot))
    }

    /// Returns a tuple of `ParentNode` bytes and (in the last call only) the root hash. Callers
    /// who need `ParentNode` bytes must call `merge_finalize` in a loop after pushing the final
    /// subtree, until the second return value is `Some`. Callers who don't need parent nodes
    /// should use the simpler `finalize` interface instead.
    pub fn merge_finalize(&mut self) -> StateFinish {
        if self.subtrees.len() > 2 {
            StateFinish::Parent(self.merge_inner(NotRoot))
        } else if self.subtrees.len() == 2 {
            StateFinish::Parent(self.merge_inner(Root))
        } else {
            StateFinish::Root(self.subtrees[0])
        }
    }

    /// A wrapper around `merge_finalize` for callers who don't need the parent
    /// nodes.
    pub fn finalize(&mut self) -> Hash {
        loop {
            match self.merge_finalize() {
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

/// An incremental hasher. `Hasher` is no_std-compatible and does not allocate.
/// This implementation is single-threaded.
///
/// Writing to `Hasher` is more efficient when you use a buffer size that's a
/// multiple of [`BUF_SIZE`](constant.BUF_SIZE.html). The
/// [`bao::copy`](fn.copy.html) helper function takes care of this.
///
/// # Example
/// ```
/// let mut hasher = bao::Hasher::new();
/// hasher.update(b"input");
/// hasher.update(b" ");
/// hasher.update(b"bytes");
/// let hash_incremental = hasher.finalize();
/// ```
#[derive(Clone, Debug)]
pub struct Hasher {
    chunk_state: blake2s_simd::State,
    tree_state: State,
}

impl Hasher {
    /// Create a new `Hasher`.
    pub fn new() -> Self {
        Self {
            // The chunk_state will have the Root finalization (the last_node
            // flag) set later if it turns one that the root is a chunk.
            chunk_state: chunk_params(NotRoot, 0).to_state(),
            tree_state: State::new(),
        }
    }

    /// Add input to the hash. This is equivalent to `Write::write`, but also
    /// available under `no_std`.
    ///
    /// Writing to `Hasher` is more efficient when you use a buffer size that's
    /// a multiple of [`BUF_SIZE`](constant.BUF_SIZE.html). The
    /// [`bao::copy`](fn.copy.html) helper function takes care of this, but if
    /// you call `update` in a loop you need to be aware of it.
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

            // If there's more input coming, finalize the chunk before we
            // continue. Otherwise short circuit.
            if !input.is_empty() {
                let chunk_hash = self.chunk_state.finalize().into();
                // At this point the chunk_state needs to be reset. However, we
                // don't know what offset to use until we get to the next
                // partial chunk. We'll reset it then.
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            } else {
                return;
            }
        }

        // Hash all the full chunks that we can, in parallel using SIMD, and
        // incorporate those hashes into the tree state. At this point we know
        // none of these can be the root. Here all the parent hash work is
        // serial, so there's some overhead compared to the fully parallel (not
        // to mention multithreaded) all-at-once hash() function.
        let mut chunk_index = self.tree_state.count() / CHUNK_SIZE as u64;
        let mut chunks = input.chunks_exact(CHUNK_SIZE);
        let mut fused_chunks = chunks.by_ref().fuse();
        loop {
            let mut jobs: ArrayVec<[HashManyJob; MAX_SIMD_DEGREE]> = fused_chunks
                .by_ref()
                .take(MAX_SIMD_DEGREE)
                .map(|chunk| {
                    let params = chunk_params(NotRoot, chunk_index);
                    chunk_index += 1;
                    HashManyJob::new(&params, chunk)
                })
                .collect();
            if jobs.is_empty() {
                break;
            }
            blake2s_simd::many::hash_many(&mut jobs);
            for job in &jobs {
                let chunk_hash = job.to_hash().into();
                self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            }
        }

        // Retain any remaining bytes in the chunk_state. This is where we
        // reset the chunk_state, because we know we're starting a new one.
        if !chunks.remainder().is_empty() {
            debug_assert!(chunks.remainder().len() < CHUNK_SIZE);
            self.chunk_state = chunk_params(NotRoot, chunk_index).to_state();
            self.chunk_state.update(chunks.remainder());
        }
    }

    /// Finish computing the root hash. The hasher cannot be used after this.
    pub fn finalize(&mut self) -> Hash {
        // If the chunk_state contains any chunk data, we have to finalize it
        // and incorporate it into the tree. Also, if there was never any data
        // at all, we have to hash the empty chunk.
        if self.chunk_state.count() > 0 || self.tree_state.count() == 0 {
            if self.tree_state.count() == 0 {
                // This is after-the-fact Root finalization.
                self.chunk_state.set_last_node(true);
            }
            let hash = self.chunk_state.finalize().into();
            self.tree_state
                .push_subtree(&hash, self.chunk_state.count() as usize);
        }
        self.tree_state.finalize()
    }
}

#[cfg(feature = "std")]
impl io::Write for Hasher {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.update(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An efficient buffer size for [`Hasher`](struct.Hasher.html),
/// [`Encoder`](encode/struct.Encoder.html),
/// [`Decoder`](decode/struct.Decoder.html), and
/// [`SliceDecoder`](decode/struct.SliceDecoder.html).
///
/// The streaming implementations are single threaded, but they use SIMD
/// parallelism to get good performance. To avoid unnecessary copying, they
/// rely on the caller to use a buffer size large enough to occupy all the SIMD
/// lanes on the machine. This constant, or an integer multiple of it, is an
/// optimal size.
///
/// On x86 for example, the AVX2 instruction set supports hashing 8 chunks in
/// parallel. Chunks are 4096 bytes each, so `BUF_SIZE` is currently 32768
/// bytes. When Rust adds support for AVX512, the value of `BUF_SIZE` on x86
/// will double to 65536 bytes. It's not expected to grow any larger than that
/// for the foreseeable future, so on not-very-space-constrained platforms it's
/// possible to use `BUF_SIZE` as the size of a stack array. If this constant
/// grows above 65536 on any platform, it will be considered a
/// backwards-incompatible change, and it will be accompanied by a major
/// version bump.
pub const BUF_SIZE: usize = MAX_SIMD_DEGREE * CHUNK_SIZE;

// This is an implementation detail of libstd, and if it changes there we
// should update it here. This is covered in the tests.
#[allow(dead_code)]
const STD_DEFAULT_BUF_SIZE: usize = 8192;

// Const functions can't use if-statements yet, which means that cmp::min and
// cmp::max aren't const. So we have to hardcode the buffer size that copy is
// going to use. This is covered in the tests, and we can replace this with
// cmp::max in the future when it's const.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const COPY_BUF_SIZE: usize = BUF_SIZE;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
const COPY_BUF_SIZE: usize = STD_DEFAULT_BUF_SIZE;

/// Copies the entire contents of a reader into a writer, just like
/// [`std::io::copy`](https://doc.rust-lang.org/std/io/fn.copy.html), using a
/// buffer size that's more efficient for [`Hasher`](struct.Hasher.html),
/// [`Encoder`](encode/struct.Encoder.html),
/// [`Decoder`](decode/struct.Decoder.html), and
/// [`SliceDecoder`](decode/struct.SliceDecoder.html).
///
/// The standard library `copy` function uses a buffer size that's too small to
/// get good SIMD performance on x86. This function uses a buffer size that's a
/// multiple of [`BUF_SIZE`](constant.BUF_SIZE.html).
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut reader = std::io::Cursor::new(b"some bytes");
/// let mut hasher = bao::Hasher::new();
/// bao::copy(&mut reader, &mut hasher)?;
/// assert_eq!(bao::hash(b"some bytes"), hasher.finalize());
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
pub fn copy(reader: &mut impl io::Read, writer: &mut impl io::Write) -> io::Result<u64> {
    let mut buffer = [0; COPY_BUF_SIZE];
    let mut total = 0;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                writer.write_all(&buffer[..n])?;
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[doc(hidden)]
pub mod benchmarks {
    pub const CHUNK_SIZE: usize = super::CHUNK_SIZE;
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    // Interesting input lengths to run tests on.
    pub const TEST_CASES: &[usize] = &[
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
            assert_eq!(left_len(input), output);
        }
    }

    fn drive_state(mut input: &[u8]) -> Hash {
        let last_chunk_finialization = if input.len() <= CHUNK_SIZE {
            Root
        } else {
            NotRoot
        };
        let mut state = State::new();
        let mut chunk_index = 0;
        while input.len() > CHUNK_SIZE {
            let hash = chunk_params(NotRoot, chunk_index)
                .hash(&input[..CHUNK_SIZE])
                .into();
            chunk_index += 1;
            state.push_subtree(&hash, CHUNK_SIZE);
            input = &input[CHUNK_SIZE..];
        }
        let hash = chunk_params(last_chunk_finialization, chunk_index)
            .hash(input)
            .into();
        state.push_subtree(&hash, input.len());
        state.finalize()
    }

    // These tests just check the different implementations against each other,
    // but explicit test vectors are included in test_vectors.json and checked
    // in the integration tests.

    #[test]
    fn test_state() {
        let buf = [0x42; 65537];
        for &case in TEST_CASES {
            let input = &buf[..case];
            let expected = hash(&input);
            let found = drive_state(&input);
            assert_eq!(expected, found, "hashes don't match");
        }
    }

    #[test]
    fn test_hasher() {
        let buf = [0x42; 65537];
        for &case in TEST_CASES {
            let input = &buf[..case];
            let expected = hash(&input);
            let mut hasher = Hasher::new();
            hasher.update(&input);
            let found = hasher.finalize();
            assert_eq!(expected, found, "hashes don't match");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_copy_buffer_sizes() {
        // Check that STD_DEFAULT_BUF_SIZE is actually what libstd is using.
        use io::BufRead;
        let bytes = [0; 2 * STD_DEFAULT_BUF_SIZE];
        let mut buffered_reader = io::BufReader::new(&bytes[..]);
        let internal_buf = buffered_reader.fill_buf().unwrap();
        assert_eq!(internal_buf.len(), STD_DEFAULT_BUF_SIZE);
        assert!(internal_buf.len() < bytes.len());

        // Check that COPY_BUF_SIZE is at least STD_DEFAULT_BUF_SIZE.
        assert!(COPY_BUF_SIZE >= STD_DEFAULT_BUF_SIZE);

        // Check that COPY_BUF_SIZE is a multiple of BUF_SIZE.
        assert!(COPY_BUF_SIZE >= BUF_SIZE);
        assert_eq!(0, COPY_BUF_SIZE % BUF_SIZE);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hasher_write() {
        let input = vec![0xff; 1_000_000];
        let mut hasher = Hasher::new();
        let n = crate::copy(&mut io::Cursor::new(&input), &mut hasher).unwrap();
        assert_eq!(n, input.len() as u64);
        assert_eq!(hash(&input), hasher.finalize());
    }
}
