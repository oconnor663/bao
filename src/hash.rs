use arrayvec::ArrayVec;
use blake2_c::blake2b;
use byteorder::{ByteOrder, LittleEndian};
use rayon;
use std::cmp;
use std::io;
use std::mem;

pub const HASH_SIZE: usize = 32;
pub(crate) const PARENT_SIZE: usize = 64;
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) const CHUNK_SIZE: usize = 4096;
pub(crate) const MAX_DEPTH: usize = 64;

pub type Hash = [u8; HASH_SIZE];
pub type ParentNode = [u8; 2 * HASH_SIZE];

pub(crate) fn encode_len(len: u64) -> [u8; HEADER_SIZE] {
    debug_assert_eq!(mem::size_of_val(&len), HEADER_SIZE);
    let mut len_bytes = [0; HEADER_SIZE];
    LittleEndian::write_u64(&mut len_bytes, len);
    len_bytes
}

pub(crate) fn decode_len(bytes: &[u8]) -> u64 {
    LittleEndian::read_u64(bytes)
}

// The root node is hashed differently from interior nodes. It gets suffixed
// with the length of the entire input, and we set the Blake2 final node flag.
// That means that no root hash can ever collide with an interior hash, or with
// the root of a different size tree.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Finalization {
    NotRoot,
    Root(u64),
}
use self::Finalization::{NotRoot, Root};

pub(crate) fn finalize_hash(state: &mut blake2b::State, finalization: Finalization) -> Hash {
    // For the root node, we hash in the length as a suffix, and we set the
    // Blake2 last node flag. One of the reasons for this design is that we
    // don't need to know a given node is the root until the very end, so we
    // don't always need a chunk buffer.
    if let Root(root_len) = finalization {
        state.update(&encode_len(root_len));
        state.set_last_node(true);
    }
    let blake_digest = state.finalize();
    *array_ref!(blake_digest.bytes, 0, HASH_SIZE)
}

pub(crate) fn hash_chunk(chunk: &[u8], finalization: Finalization) -> Hash {
    debug_assert!(chunk.len() <= CHUNK_SIZE);
    let mut state = blake2b::State::new(HASH_SIZE);
    state.update(chunk);
    finalize_hash(&mut state, finalization)
}

pub(crate) fn hash_parent(left_hash: &Hash, right_hash: &Hash, finalization: Finalization) -> Hash {
    let mut state = blake2b::State::new(HASH_SIZE);
    state.update(left_hash);
    state.update(right_hash);
    finalize_hash(&mut state, finalization)
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

pub(crate) fn hash_recurse(input: &[u8], finalization: Finalization) -> Hash {
    if input.len() <= CHUNK_SIZE {
        return hash_chunk(input, finalization);
    }
    // If we have more than one chunk of input, recursively hash the left and
    // right sides. The left_len() function determines the shape of the tree.
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    // Child nodes are never the root.
    let left_hash = hash_recurse(left, NotRoot);
    let right_hash = hash_recurse(right, NotRoot);
    hash_parent(&left_hash, &right_hash, finalization)
}

pub fn hash(input: &[u8]) -> Hash {
    hash_recurse(input, Root(input.len() as u64))
}

pub(crate) fn hash_recurse_parallel(input: &[u8], finalization: Finalization) -> Hash {
    // By my measurements on an i5-4590, the overhead of parallel hashing
    // doesn't pay for itself until you have more than two chunks.
    if input.len() <= 2 * CHUNK_SIZE {
        return hash_recurse(input, finalization);
    }
    let (left, right) = input.split_at(left_len(input.len() as u64) as usize);
    let (left_hash, right_hash) = rayon::join(
        || hash_recurse_parallel(left, NotRoot),
        || hash_recurse_parallel(right, NotRoot),
    );
    hash_parent(&left_hash, &right_hash, finalization)
}

pub fn hash_parallel(input: &[u8]) -> Hash {
    hash_recurse_parallel(input, Root(input.len() as u64))
}

pub struct State {
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

    fn merge_inner(&mut self, finalization: Finalization) -> ParentNode {
        let right_child = self.subtrees.pop().unwrap();
        let left_child = self.subtrees.pop().unwrap();
        let mut parent_node = [0; PARENT_SIZE];
        parent_node[..HASH_SIZE].copy_from_slice(&left_child);
        parent_node[HASH_SIZE..].copy_from_slice(&right_child);
        let parent_hash = hash_parent(&left_child, &right_child, finalization);
        self.subtrees.push(parent_hash);
        parent_node
    }

    // We keep the subtree hashes in an array without storing their size, and
    // we use this cute trick to figure out when we should merge them. Because
    // every subtree (prior to the finalization step) is a power of two times
    // the chunk size, adding a new subtree to the right/small end is a lot
    // like adding a 1 to a binary number, and merging subtrees is like
    // propagating the carry bit. Each carry represents a place where two
    // subtrees need to be merged, and the final number of
    // 1 bits is the same as the final number of subtrees.
    fn needs_merge(&self) -> bool {
        self.subtrees.len() > (self.total_len / CHUNK_SIZE as u64).count_ones() as usize
    }

    /// All the chunks must be exactly CHUNK_SIZE
    pub fn push_chunk(&mut self, hash: Hash, len: usize) {
        // TODO: Would it be cleaner to separate push_chunk and push_final?
        debug_assert!(len > 0, "empty chunk");
        debug_assert!(len <= CHUNK_SIZE, "chunk too big");
        debug_assert_eq!(
            0,
            self.total_len % CHUNK_SIZE as u64,
            "only the final chunk may be partial"
        );
        // Merge any subtrees that need to be merged before pushing. In the
        // encoding case, the caller will already have done this via
        // merge_parent(), but in the hashing case the caller doesn't care
        // about the parent nodes.
        while self.needs_merge() {
            self.merge_inner(NotRoot);
        }
        self.subtrees.push(hash);
        self.total_len += len as u64;
    }

    /// Callers making an encoding need to get their hands on the bytes of each
    /// parent node. They should inspect the return value of `push_subtree`,
    /// and then if it's not `None` call this function in a loop until it
    /// returns `None`. This will yield all the parent nodes in
    /// smallest-to-largest order. Callers who don't need parent nodes, and
    /// instead just want the root hash, can skip this function.
    pub fn merge_parent(&mut self) -> Option<ParentNode> {
        if !self.needs_merge() {
            return None;
        }
        Some(self.merge_inner(NotRoot))
    }

    pub fn merge_finish(&mut self) -> FinishResult {
        assert!(self.subtrees.len() >= 2, "not enough subtrees");
        if self.subtrees.len() > 2 {
            FinishResult::Parent(self.merge_inner(NotRoot))
        } else {
            let finalization = Root(self.total_len);
            let root_node = self.merge_inner(finalization);
            let root_hash = self.subtrees.pop().unwrap();
            FinishResult::Root(root_node, root_hash)
        }
    }

    /// A wrapper around `merge_finish` for callers who don't need the parent
    /// nodes.
    pub fn finish(&mut self) -> Hash {
        loop {
            match self.merge_finish() {
                FinishResult::Parent(_) => {}
                FinishResult::Root(_, hash) => return hash,
            }
        }
    }
}

pub enum FinishResult {
    Parent(ParentNode),
    Root(ParentNode, Hash),
}

pub struct Writer {
    chunk: blake2b::State,
    chunk_len: usize,
    first_chunk: bool,
    state: State,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            chunk: blake2b::State::new(HASH_SIZE),
            chunk_len: 0,
            first_chunk: true,
            state: State::new(),
        }
    }

    pub fn finish(&mut self) -> Hash {
        if self.first_chunk {
            let finalization = Root(self.chunk_len as u64);
            return finalize_hash(&mut self.chunk, finalization);
        }
        let last_chunk_hash = finalize_hash(&mut self.chunk, NotRoot);
        self.state.push_chunk(last_chunk_hash, self.chunk_len);
        self.state.finish()
    }
}

impl io::Write for Writer {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let input_len = input.len();
        while !input.is_empty() {
            if self.chunk_len == CHUNK_SIZE {
                let chunk_hash = finalize_hash(&mut self.chunk, NotRoot);
                self.state.push_chunk(chunk_hash, CHUNK_SIZE);
                self.chunk = blake2b::State::new(HASH_SIZE);
                self.chunk_len = 0;
                self.first_chunk = false;
            }

            let want = CHUNK_SIZE - self.chunk_len;
            let take = cmp::min(want, input.len());
            self.chunk.update(&input[..take]);
            self.chunk_len += take;
            input = &input[take..];
        }
        Ok(input_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    use std::io::prelude::*;

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
    fn test_parallel() {
        for &case in TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_serial = hash(&input);
            let hash_parallel = hash_parallel(&input);
            assert_eq!(hash_serial, hash_parallel, "hashes don't match");
        }
    }

    fn drive_state(input: &[u8]) -> Hash {
        if input.len() <= CHUNK_SIZE {
            return hash_chunk(input, Root(input.len() as u64));
        }
        let mut state = State::new();
        let chunk_hashes = input
            .chunks(CHUNK_SIZE)
            .map(|chunk| (hash_chunk(chunk, NotRoot), chunk.len()));
        for (chunk_hash, len) in chunk_hashes {
            state.push_chunk(chunk_hash, len);
        }
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
        }
    }
}
