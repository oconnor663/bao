use arrayvec::ArrayVec;
use blake2_c::blake2b;
use byteorder::{ByteOrder, LittleEndian};
use rayon;
use std::cmp::min;
use Hash;
use DIGEST_SIZE;
use CHUNK_SIZE;

pub(crate) fn finalize_hash(state: &mut blake2b::State, root_len: Option<u64>) -> Hash {
    // For the root node, we hash in the length as a suffix, and we set the
    // Blake2 last node flag. One of the reasons for this design is that we
    // don't need to know a given node is the root until the very end, so we
    // don't always need a chunk buffer.
    if let Some(len) = root_len {
        let mut len_bytes = [0; 8];
        LittleEndian::write_u64(&mut len_bytes, len);
        state.update(&len_bytes);
        state.set_last_node(true);
    }
    let blake_digest = state.finalize();
    *array_ref!(blake_digest.bytes, 0, DIGEST_SIZE)
}

pub(crate) fn hash_chunk(chunk: &[u8], root_len: Option<u64>) -> Hash {
    debug_assert!(chunk.len() <= CHUNK_SIZE);
    let mut state = blake2b::State::new(DIGEST_SIZE);
    state.update(chunk);
    finalize_hash(&mut state, root_len)
}

pub(crate) fn hash_parent(left_hash: &[u8], right_hash: &[u8], root_len: Option<u64>) -> Hash {
    debug_assert_eq!(left_hash.len(), DIGEST_SIZE);
    debug_assert_eq!(right_hash.len(), DIGEST_SIZE);
    let mut state = blake2b::State::new(DIGEST_SIZE);
    state.update(left_hash);
    state.update(right_hash);
    finalize_hash(&mut state, root_len)
}

// Find the largest power of two that's less than or equal to `n`. We use this
// for computing subtree sizes below.
fn largest_power_of_two(n: u64) -> u64 {
    debug_assert!(n != 0);
    1 << (63 - n.leading_zeros())
}

// Given some input larger than one chunk, find the largest perfect tree of
// chunks that can go on the left.
pub(crate) fn left_len(content_len: u64) -> u64 {
    debug_assert!(content_len > CHUNK_SIZE as u64);
    // Subtract 1 to reserve at least one byte for the right side.
    let full_chunks = (content_len - 1) / CHUNK_SIZE as u64;
    largest_power_of_two(full_chunks) * CHUNK_SIZE as u64
}

pub(crate) fn hash_recurse(input: &[u8], root_len: Option<u64>) -> Hash {
    if input.len() <= CHUNK_SIZE {
        return hash_chunk(input, root_len);
    }
    // If we have more than one chunk of input, recursively hash the left and
    // right sides. The left_len() function determines the shape of the tree.
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    // Child nodes are never the root, so their root_len is None.
    let left_hash = hash_recurse(left, None);
    let right_hash = hash_recurse(right, None);
    hash_parent(&left_hash, &right_hash, root_len)
}

pub fn hash(input: &[u8]) -> Hash {
    hash_recurse(input, Some(input.len() as u64))
}

pub(crate) fn hash_recurse_parallel(input: &[u8], root_len: Option<u64>) -> Hash {
    if input.len() <= CHUNK_SIZE {
        return hash_chunk(input, root_len);
    }
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    let (left_hash, right_hash) = rayon::join(
        || hash_recurse_parallel(left, None),
        || hash_recurse_parallel(right, None),
    );
    hash_parent(&left_hash, &right_hash, root_len)
}

pub fn hash_parallel(input: &[u8]) -> Hash {
    hash_recurse_parallel(input, Some(input.len() as u64))
}

// This is a cute algorithm for merging partially completed trees. We keep only
// the hash of each subtree assembled so far, ordered from largest to smallest
// in an ArrayVec. Because all subtrees (prior to the finalization step) are a
// power of two times the chunk size, adding a new subtree to the small end is
// conceptually very similar to adding two binary numbers and propagating the
// carry bit.
pub(crate) fn rollup_subtree(
    subtrees: &mut ArrayVec<[Hash; 64]>,
    new_total_len: u64,
    new_subtree: Hash,
) {
    let final_num_trees = (new_total_len / CHUNK_SIZE as u64).count_ones();
    subtrees.push(new_subtree);
    while subtrees.len() > final_num_trees as usize {
        let right_child = subtrees.pop().expect("called with too few nodes");
        let left_child = subtrees.pop().expect("called with too few nodes");
        subtrees.push(hash_parent(&left_child, &right_child, None));
    }
}

// Similar to rollup_subtree, but for the finalization step, where we allow
// imperfect subtrees on the right edge. From smallest to largest, every pair
// of subtrees gets merged into a parent node, regardless of their length. The
// rule that all left subtrees are perfect is still preserved.
pub(crate) fn rollup_final(
    subtrees: &mut ArrayVec<[Hash; 64]>,
    final_len: u64,
    new_subtree: Hash,
) -> Hash {
    subtrees.push(new_subtree);
    loop {
        let right_child = subtrees.pop().expect("called with too few nodes");
        let left_child = subtrees.pop().expect("called with too few nodes");
        if subtrees.is_empty() {
            return hash_parent(&left_child, &right_child, Some(final_len));
        }
        subtrees.push(hash_parent(&left_child, &right_child, None));
    }
}

#[derive(Debug, Clone)]
pub struct State {
    chunk_state: blake2b::State,
    count: u64,
    subtrees: ArrayVec<[Hash; 64]>,
}

impl State {
    pub fn new() -> Self {
        Self {
            chunk_state: blake2b::State::new(DIGEST_SIZE),
            count: 0,
            subtrees: ArrayVec::new(),
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If we've completed a chunk, merge it into the subtrees list. We
            // only do this when we know there's more input to come, otherwise
            // we have to wait and see if we need to finalize.
            if self.count > 0 && self.count % CHUNK_SIZE as u64 == 0 {
                let chunk_hash = finalize_hash(&mut self.chunk_state, None);
                self.chunk_state = blake2b::State::new(DIGEST_SIZE);
                rollup_subtree(&mut self.subtrees, self.count, chunk_hash);
            }
            // Take as many bytes as we can, to fill the next chunk.
            let current_chunk_len = (self.count % CHUNK_SIZE as u64) as usize;
            let take = min(input.len(), CHUNK_SIZE - current_chunk_len);
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
            self.count += take as u64;
        }
    }

    /// It's a logic error to call finalize more than once on the same instance.
    pub fn finalize(&mut self) -> Hash {
        // If the tree is a single chunk, give that chunk the root flag and
        // return its hash.
        if self.count <= CHUNK_SIZE as u64 {
            return finalize_hash(&mut self.chunk_state, Some(self.count as u64));
        }
        // Otherwise we need to hash the chunk as usual and do a rollup that
        // flags the root parent node.
        let chunk_hash = finalize_hash(&mut self.chunk_state, None);
        rollup_final(&mut self.subtrees, self.count, chunk_hash)
    }
}

// A little more than one megabyte.
const PARALLEL_BUFFER_SIZE: usize = 256 * CHUNK_SIZE;

pub struct StateParallel {
    buffer: Vec<u8>,
    count: u64,
    subtrees: ArrayVec<[Hash; 64]>,
}

impl StateParallel {
    pub fn new() -> Self {
        debug_assert_eq!(
            0,
            PARALLEL_BUFFER_SIZE % CHUNK_SIZE,
            "buffer must be a multiple of chunk size"
        );
        debug_assert_eq!(
            1,
            (PARALLEL_BUFFER_SIZE / CHUNK_SIZE).count_ones(),
            "buffer must be a power of two multiple of the chunk_size",
        );
        Self {
            buffer: Vec::new(),
            count: 0,
            subtrees: ArrayVec::new(),
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buffer.len() == PARALLEL_BUFFER_SIZE {
                let subtree = hash_recurse_parallel(&self.buffer, None);
                self.buffer.clear();
                rollup_subtree(&mut self.subtrees, self.count, subtree);
            }
            // Take as many bytes as we can, to fill the next chunk.
            let take = min(input.len(), PARALLEL_BUFFER_SIZE - self.buffer.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            self.count += take as u64;
        }
    }

    /// It's a logic error to call finalize more than once on the same instance.
    pub fn finalize(&mut self) -> Hash {
        if self.count <= PARALLEL_BUFFER_SIZE as u64 {
            return hash_parallel(&self.buffer);
        }
        let subtree = hash_recurse_parallel(&self.buffer, None);
        rollup_final(&mut self.subtrees, self.count, subtree)
    }
}

#[cfg(test)]
mod test {
    use hex::ToHex;

    use super::*;

    #[test]
    fn test_compare_python() {
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_hex = hash(&input).to_hex();

            // Have the Python implementation hash the same input, and make
            // sure the result is identical.
            let python_hash = cmd!("python3", "./python/bao.py", "hash")
                .input(input.clone())
                .read()
                .expect("is python3 installed?");
            assert_eq!(hash_hex, python_hash, "hashes don't match");
        }
    }

    #[test]
    fn test_state() {
        // Cover both serial and parallel here.
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_at_once = hash(&input);
            let mut state_serial = State::new();
            let mut state_parallel = StateParallel::new();
            // Use chunks that don't evenly divide 4096, to check the buffering
            // logic.
            for chunk in input.chunks(1000) {
                state_serial.update(chunk);
                state_parallel.update(chunk);
            }
            let hash_state_serial = state_serial.finalize();
            let hash_state_parallel = state_parallel.finalize();
            assert_eq!(hash_at_once, hash_state_serial, "hashes don't match");
            assert_eq!(hash_at_once, hash_state_parallel, "hashes don't match");
        }
    }

    #[test]
    fn test_parallel() {
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_serial = hash(&input);
            let hash_parallel = hash_parallel(&input);
            assert_eq!(hash_serial, hash_parallel, "hashes don't match");
        }
    }

    #[test]
    fn test_state_parallel_10mb() {
        // The internal buffer is about a megabyte, so make sure to test a case
        // that fills it up multiple times.
        let input = &[0; 10_000_000];
        let hash_at_once = hash(input);
        let mut state = StateParallel::new();
        state.update(input);
        let hash_parallel = state.finalize();
        assert_eq!(hash_at_once, hash_parallel, "hashes don't match");
    }
}
