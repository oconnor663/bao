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

use arrayref::array_ref;
use arrayvec::{ArrayString, ArrayVec};
use blake2s_simd;
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
// NOTE: MAX_DEPTH should be 52, given the 4096 byte CHUNK_SIZE, using a larger value wastes some
// space on the stack. It currently needs to match one of the implementations of arrayvec::Array,
// but dropping that dependency could let us compute MAX_DEPTH from other parameters.
pub(crate) const MAX_DEPTH: usize = 64;
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
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self { bytes }
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
        .node_offset(0)
        .inner_hash_length(HASH_SIZE);
    params
}

fn chunk_params() -> blake2s_simd::Params {
    let mut params = common_params();
    params.node_depth(0);
    params
}

fn node_params() -> blake2s_simd::Params {
    let mut params = common_params();
    params.node_depth(1);
    params
}

pub(crate) fn new_chunk_state() -> blake2s_simd::State {
    chunk_params().to_state()
}

pub(crate) fn new_parent_state() -> blake2s_simd::State {
    node_params().to_state()
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
    // For the root node, we hash in the length as a suffix, and we set the
    // Blake2 last node flag. One of the reasons for this design is that we
    // don't need to know a given node is the root until the very end, so we
    // don't always need a chunk buffer.
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

fn hash_eight_chunk_subtree(
    chunk0: &[u8; CHUNK_SIZE],
    chunk1: &[u8; CHUNK_SIZE],
    chunk2: &[u8; CHUNK_SIZE],
    chunk3: &[u8; CHUNK_SIZE],
    chunk4: &[u8; CHUNK_SIZE],
    chunk5: &[u8; CHUNK_SIZE],
    chunk6: &[u8; CHUNK_SIZE],
    chunk7: &[u8; CHUNK_SIZE],
    finalization: Finalization,
) -> Hash {
    // This relies on the fact that finalize_hash does nothing for non-root nodes.
    let params = chunk_params();
    let mut chunk_jobs = [
        blake2s_simd::many::HashManyJob::new(&params, chunk0),
        blake2s_simd::many::HashManyJob::new(&params, chunk1),
        blake2s_simd::many::HashManyJob::new(&params, chunk2),
        blake2s_simd::many::HashManyJob::new(&params, chunk3),
        blake2s_simd::many::HashManyJob::new(&params, chunk4),
        blake2s_simd::many::HashManyJob::new(&params, chunk5),
        blake2s_simd::many::HashManyJob::new(&params, chunk6),
        blake2s_simd::many::HashManyJob::new(&params, chunk7),
    ];
    blake2s_simd::many::hash_many(chunk_jobs.iter_mut());
    let mut subtree0 = new_parent_state();
    subtree0.update(chunk_jobs[0].to_hash().as_bytes());
    subtree0.update(chunk_jobs[1].to_hash().as_bytes());
    let mut subtree1 = new_parent_state();
    subtree1.update(chunk_jobs[2].to_hash().as_bytes());
    subtree1.update(chunk_jobs[3].to_hash().as_bytes());
    let mut subtree2 = new_parent_state();
    subtree2.update(chunk_jobs[4].to_hash().as_bytes());
    subtree2.update(chunk_jobs[5].to_hash().as_bytes());
    let mut subtree3 = new_parent_state();
    subtree3.update(chunk_jobs[6].to_hash().as_bytes());
    subtree3.update(chunk_jobs[7].to_hash().as_bytes());
    let mut left_subtree = new_parent_state();
    left_subtree.update(subtree0.finalize().as_bytes());
    left_subtree.update(subtree1.finalize().as_bytes());
    let mut right_subtree = new_parent_state();
    right_subtree.update(subtree2.finalize().as_bytes());
    right_subtree.update(subtree3.finalize().as_bytes());
    let mut parent_state = new_parent_state();
    parent_state.update(left_subtree.finalize().as_bytes());
    parent_state.update(right_subtree.finalize().as_bytes());
    finalize_hash(&mut parent_state, finalization)
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

fn hash_recurse(input: &[u8], finalization: Finalization) -> Hash {
    if input.len() <= CHUNK_SIZE {
        return hash_chunk(input, finalization);
    }
    // Special case: If the input is exactly four chunks, hashing those four chunks in parallel
    // with SIMD is more efficient than going one by one.
    if input.len() == 8 * CHUNK_SIZE {
        return hash_eight_chunk_subtree(
            array_ref!(input, 0 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 1 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 2 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 3 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 4 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 5 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 6 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 7 * CHUNK_SIZE, CHUNK_SIZE),
            finalization,
        );
    }
    // We have more than one chunk of input, so recursively hash the left and right sides. The
    // left_len() function determines the shape of the tree.
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    // Child nodes are never the root.
    let left_hash = hash_recurse(left, NotRoot);
    let right_hash = hash_recurse(right, NotRoot);
    parent_hash(&left_hash, &right_hash, finalization)
}

#[cfg(feature = "std")]
fn hash_recurse_rayon(input: &[u8], finalization: Finalization) -> Hash {
    if input.len() <= CHUNK_SIZE {
        return hash_chunk(input, finalization);
    }
    // Special case: If the input is exactly four chunks, hashing those four chunks in parallel
    // with SIMD is more efficient than going one by one.
    if input.len() == 8 * CHUNK_SIZE {
        return hash_eight_chunk_subtree(
            array_ref!(input, 0 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 1 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 2 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 3 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 4 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 5 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 6 * CHUNK_SIZE, CHUNK_SIZE),
            array_ref!(input, 7 * CHUNK_SIZE, CHUNK_SIZE),
            finalization,
        );
    }
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    let (left_hash, right_hash) = rayon::join(
        || hash_recurse_rayon(left, NotRoot),
        || hash_recurse_rayon(right, NotRoot),
    );
    parent_hash(&left_hash, &right_hash, finalization)
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
    #[cfg(feature = "std")]
    {
        if input.len() <= MAX_SINGLE_THREADED {
            hash_recurse(input, Root)
        } else {
            hash_recurse_rayon(input, Root)
        }
    }
    #[cfg(not(feature = "std"))]
    {
        hash_recurse(input, Root)
    }
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

/// An incremental hasher. This implementation is single-threaded.
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
    chunk: blake2s_simd::State,
    state: State,
}

impl Writer {
    /// Create a new `Writer`.
    pub fn new() -> Self {
        Self {
            chunk: new_chunk_state(),
            state: State::new(),
        }
    }

    /// Add input. This is equivalent to `write`, except that it's also available with `no_std`.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk.count() as usize == CHUNK_SIZE {
                let hash = finalize_hash(&mut self.chunk, NotRoot);
                self.state.push_subtree(&hash, CHUNK_SIZE);
                self.chunk = new_chunk_state();
            }
            let want = CHUNK_SIZE - self.chunk.count() as usize;
            let take = cmp::min(want, input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finish computing the root hash. The writer cannot be used after this.
    pub fn finish(&mut self) -> Hash {
        let finalization = if self.state.count() == 0 {
            Root
        } else {
            NotRoot
        };
        let hash = finalize_hash(&mut self.chunk, finalization);
        self.state.push_subtree(&hash, self.chunk.count() as usize);
        self.state.finish()
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

const JOB_SIZE: usize = 8 * CHUNK_SIZE;

#[cfg(feature = "std")]
#[derive(Debug)]
struct Job {
    sender: crossbeam_channel::Sender<(Job, Hash)>,
    receiver: crossbeam_channel::Receiver<(Job, Hash)>,
    buffer: Vec<u8>,
}

#[cfg(feature = "std")]
impl Job {
    fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        Self {
            sender,
            receiver,
            buffer: Vec::with_capacity(JOB_SIZE),
        }
    }

    fn compute_hash(&self, finalization: Finalization) -> Hash {
        debug_assert!(self.buffer.len() <= JOB_SIZE);
        if self.buffer.len() == JOB_SIZE {
            hash_eight_chunk_subtree(
                array_ref!(self.buffer, 0 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 1 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 2 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 3 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 4 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 5 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 6 * CHUNK_SIZE, CHUNK_SIZE),
                array_ref!(self.buffer, 7 * CHUNK_SIZE, CHUNK_SIZE),
                finalization,
            )
        } else {
            hash_recurse(&self.buffer, finalization)
        }
    }
}

/// A multi-threaded version of [`Writer`], which is much faster, but which
/// requires allocation.
///
/// The fastest hashing implementation is the recursive [`hash`] function,
/// which uses [`rayon::join`] to parallelize efficiently without allocating.
/// However, that API only works with in-memory slices or memory-mapped files.
/// For incremental input like we get through the `std::io::Write` interface,
/// we need to buffer input on the heap, so that hashing can continue in the
/// background while control returns to the caller. As a result, this type has
/// more overhead than [`hash`], and it isn't available under `no_std`.
///
/// This implementation is a proof of concept, and it isn't as efficient as it
/// could be. The benchmarks put it at about 85% of the throughput of [`hash`]
/// for long messages. The allocation overhead is costly for short messages,
/// though we could work around that in a future version. Other currently
/// missing features:
///
/// - a `Clone` impl
/// - a way to clear the writer and reuse its allocations
///
/// [`Writer`]: struct.Writer.html
/// [`hash`]: fn.hash.html
/// [`rayon::join`]: https://docs.rs/rayon/latest/rayon/fn.join.html
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ParallelWriter {
    state: State,
    receivers: std::collections::VecDeque<crossbeam_channel::Receiver<(Job, Hash)>>,
    next_job: Job,
    max_jobs: usize,
}

#[cfg(feature = "std")]
impl ParallelWriter {
    /// Create a new `ParallelWriter`.
    pub fn new() -> Self {
        Self {
            state: State::new(),
            receivers: std::collections::VecDeque::new(),
            next_job: Job::new(),
            max_jobs: num_cpus::get(),
        }
    }

    fn await_job(&mut self) -> Job {
        let receiver = self.receivers.pop_front().unwrap();
        let (mut job, hash) = receiver.recv().expect("channel closed");
        self.state.push_subtree(&hash, job.buffer.len());
        job.buffer.clear();
        job
    }

    /// Add input. This is equivalent to `write`.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // There's still input to go, so if the next job is full we need to send it off.
            if self.next_job.buffer.len() == JOB_SIZE {
                // If we've exceeded the maximum number of jobs in flight, await one of them and
                // process its result. Otherwise create a new one.
                let new_job = if self.receivers.len() >= self.max_jobs {
                    self.await_job()
                } else {
                    Job::new()
                };

                // Send off the next job, and replace it with the clean one we just got. Note that
                // rayon::spawn is an extra allocation, but I'm not sure that's avoidable without a
                // custom-built thread pool.
                let next_job = mem::replace(&mut self.next_job, new_job);
                self.receivers.push_back(next_job.receiver.clone());
                rayon::spawn(move || {
                    let hash = next_job.compute_hash(NotRoot);
                    let sender = next_job.sender.clone();
                    sender.send((next_job, hash));
                });
            }

            // Now that we have a next job with some space available, take as much input as we can.
            // If we can't consume the whole input, we'll loop back to the top to send off the job
            // and keep going.
            let want = JOB_SIZE - self.next_job.buffer.len();
            let take = cmp::min(want, input.len());
            self.next_job.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finish computing the root hash. The writer cannot be used after this.
    pub fn finish(&mut self) -> Hash {
        let finalization = if self.receivers.is_empty() && self.state.count() == 0 {
            Root
        } else {
            NotRoot
        };
        let last_job_hash = self.next_job.compute_hash(finalization);

        while !self.receivers.is_empty() {
            self.await_job();
        }

        self.state
            .push_subtree(&last_job_hash, self.next_job.buffer.len());
        self.state.finish()
    }
}

#[cfg(feature = "std")]
impl io::Write for ParallelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[doc(hidden)]
pub mod benchmarks {
    pub const HEADER_SIZE: usize = super::HEADER_SIZE;
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

    #[test]
    fn test_serial_vs_parallel() {
        for &case in TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_serial = hash_recurse(&input, Root);
            let hash_parallel = hash_recurse_rayon(&input, Root);
            let hash_highlevel = hash(&input);
            assert_eq!(hash_serial, hash_parallel, "hashes don't match");
            assert_eq!(hash_serial, hash_highlevel, "hashes don't match");
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

            let mut writer = ParallelWriter::new();
            writer.write_all(&input).unwrap();
            let found = writer.finish();
            assert_eq!(expected, found, "hashes don't match");
        }
    }
}
