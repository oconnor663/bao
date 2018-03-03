use arrayvec::ArrayVec;
use blake2_c::blake2b;
use byteorder::{ByteOrder, LittleEndian};
use crossbeam::sync::MsQueue;
use num_cpus;
use rayon;
use std::cmp::min;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;

pub type Hash = [u8; DIGEST_SIZE];

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

pub(crate) fn hash_parent(left_hash: &Hash, right_hash: &Hash, root_len: Option<u64>) -> Hash {
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
    // By my measurements on an i5-4590, the overhead of parallel hashing
    // doesn't pay for itself until you have more than two chunks.
    if input.len() <= 2 * CHUNK_SIZE {
        return hash_recurse(input, root_len);
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

// This is a cute algorithm for incrementally merging subtrees. We keep only
// the hash of each subtree assembled so far, ordered from left to right and
// also largest to smallest in a list. Because all subtrees (prior to the
// finalization step) are a power of two times the chunk size, adding a new
// subtree to the right/small end is a lot like adding two binary numbers and
// propagating the carry bit. Each carry represents a place where two subtrees
// need to be merged, and the final number of 1 bits is the same as the final
// number of subtrees.
//
// NB: To preserve the left-to-right and largest-to-smallest ordering, the new
// subtree must not be larger than the smallest/rightmost subtree currently in
// the list. Typically we merge subtrees of a constant size, so we don't have
// to worry about this.
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
// imperfect subtrees on the right edge. From smallest to largest (right to
// left), each pair of subtrees gets merged, regardless of their length. This
// can result in a perfect tree, if the final length is a power of two times
// the smallest subtree size, but generally it doesn't.
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

const WORKER_BUFFER: usize = 64 * CHUNK_SIZE;
lazy_static! {
    static ref MAX_ITEMS: usize = 4 * num_cpus::get();
}

struct ParallelItem {
    buffer: Vec<u8>,
    hash: Hash,
    index: u64,
}

impl ParallelItem {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(WORKER_BUFFER),
            hash: [0; DIGEST_SIZE],
            index: 0,
        }
    }
}

/// This is an example parallel implementation that accepts incremental writes.
/// Rayon's join() primitive is exceptionally easy to use when we have the
/// entire input in memory (either as a large buffer, or as a memory mapped
/// file). However, because join shouldn't block on IO, it's trickier to
/// parallelize reading from a pipe or a socket. This implementation uses a
/// collection of reusable buffers, and it spawns tasks into the Rayon thread
/// pool whenever a buffer is ready.
///
/// Reusing buffers means that we don't have to allocate much for each task,
/// however both Rayon's spawn() and crossbeam's MsQueue do make small
/// allocations internally, so this implementation isn't as efficient as it
/// could be. We use fairly large buffer sizes to spread out that overhead, but
/// another implementation with dedicated threads might be able to get rid of
/// allocations entirely.
pub struct StateParallel {
    free_items: VecDeque<ParallelItem>,
    finished_queue: Arc<MsQueue<ParallelItem>>,
    finished_map: HashMap<u64, ParallelItem>,
    item_count: usize,
    start_index: u64,
    finish_index: u64,
    subtrees: ArrayVec<[Hash; 64]>,
}

impl StateParallel {
    pub fn new() -> Self {
        Self {
            free_items: VecDeque::new(),
            finished_queue: Arc::new(MsQueue::new()),
            finished_map: HashMap::new(),
            item_count: 0,
            start_index: 0,
            finish_index: 0,
            subtrees: ArrayVec::new(),
        }
    }

    fn send_item_to_workers(&mut self, mut item: ParallelItem) {
        item.index = self.start_index;
        self.start_index += 1;
        let queue_arc = self.finished_queue.clone();
        // Hash this item in the background.
        rayon::spawn(move || {
            item.hash = hash_recurse(&item.buffer, None);
            // After hashing is done, stick it on the finish queue.
            queue_arc.push(item);
        });
    }

    // This applies to all items but the very last one.
    fn finish_item(&mut self, mut item: ParallelItem) {
        debug_assert_eq!(self.finish_index, item.index, "oops out of order");
        self.finish_index += 1;
        let new_total = WORKER_BUFFER as u64 * self.finish_index;
        rollup_subtree(&mut self.subtrees, new_total, item.hash);
        // Clear the item buffer so that it's ready for new input.
        item.buffer.clear();
        self.free_items.push_back(item);
    }

    fn blocking_pop_until_index(&mut self, index: u64) {
        while !self.finished_map.contains_key(&index) {
            // This blocks.
            let item = self.finished_queue.pop();
            self.finished_map.insert(item.index, item);
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        // The order of operations in this loop is:
        // 1. If the current item is full *and* there's more input (so we know
        //    we don't need to set the finalization flag), send it to a worker.
        // 2. If we don't have a current item, create one or wait for one.
        // 3. Fill the current item with more data.
        while !input.is_empty() {
            // If the current item (the first item in the free list) is full,
            // send it to the workers.
            if self.free_items
                .front()
                .map(|item| item.buffer.len() == WORKER_BUFFER)
                .unwrap_or(false)
            {
                let item = self.free_items.pop_front().unwrap();
                self.send_item_to_workers(item);
            }

            // Make sure there's a free item.
            if self.free_items.is_empty() {
                // If we haven't reached the item limit yet, just create one.
                if self.item_count < *MAX_ITEMS {
                    self.free_items.push_back(ParallelItem::new());
                    self.item_count += 1;
                } else {
                    // Otherwise we need to do a blocking wait on the finish
                    // queue, roll up a finished item, and then add it back to
                    // the free list. Note that items might not come out of the
                    // finish queue in order, so we might have to pop more than
                    // one before we get the next one we can process.
                    {
                        let finish_index = self.finish_index; // borrowck workaround
                        self.blocking_pop_until_index(finish_index);
                    }

                    // Roll up as many items as we can, and then add them back
                    // to the free list.
                    while let Some(item) = self.finished_map.remove(&self.finish_index) {
                        self.finish_item(item);
                    }
                }
            }

            // Fill up the first free item with as many bytes as we can. Note
            // that we always push_back on the free items queue above, so that
            // the first item remains stable.
            let want = WORKER_BUFFER - self.free_items[0].buffer.len();
            let take = min(want, input.len());
            self.free_items[0].buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize(&mut self) -> Hash {
        // If we never sent any items to workers, we need to hash the current
        // (possibly empty or nonexistent) item with the finalization flag.
        if self.start_index == 0 {
            if let Some(item) = self.free_items.pop_front() {
                return hash(&item.buffer);
            } else {
                return hash(b"");
            }
        }

        // Otherwise we need to send the current item to the workers.
        let item = self.free_items.pop_front().unwrap();
        self.send_item_to_workers(item);

        // Await all the items. Roll them up the usual way, until the very last
        // one, which gets the finalization flag.
        loop {
            {
                let finish_index = self.finish_index; // borrowck workaround
                self.blocking_pop_until_index(finish_index);
            }
            let item = self.finished_map.remove(&self.finish_index).unwrap();
            let total_len = self.finish_index * WORKER_BUFFER as u64 + item.buffer.len() as u64;
            if self.finish_index == self.start_index - 1 {
                return rollup_final(&mut self.subtrees, total_len, item.hash);
            }
            rollup_subtree(&mut self.subtrees, total_len, item.hash);
            self.finish_index += 1;
        }
    }
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
    16 * CHUNK_SIZE - 1,
    16 * CHUNK_SIZE,
    16 * CHUNK_SIZE + 1,
];

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    #[test]
    fn test_power_of_two() {
        let input_output = &[
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
                largest_power_of_two(input),
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
    fn test_compare_python() {
        for &case in TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_hex = hex::encode(hash(&input));

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
        for &case in TEST_CASES {
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
        for &case in TEST_CASES {
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
