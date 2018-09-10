use arrayvec::ArrayVec;
use blake2b_simd;
use copy_in_place::copy_in_place;
use hash::Finalization::{self, NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, PARENT_SIZE};
use rayon;
use std::cmp;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom::{End, Start};

pub fn encode(input: &[u8], output: &mut [u8]) -> Hash {
    let content_len = input.len() as u64;
    assert_eq!(
        output.len() as u128,
        encoded_size(content_len),
        "output is the wrong length"
    );
    output[..HEADER_SIZE].copy_from_slice(&hash::encode_len(content_len));
    if input.len() <= hash::MAX_SINGLE_THREADED {
        encode_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
    } else {
        encode_recurse_rayon(input, &mut output[HEADER_SIZE..], Root(content_len))
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
    if content_len <= hash::MAX_SINGLE_THREADED {
        write_parents_in_place(rest, content_len, Root(content_len as u64))
    } else {
        write_parents_in_place_rayon(rest, content_len, Root(content_len as u64))
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
    if input.len() <= hash::MAX_SINGLE_THREADED {
        encode_outboard_recurse(input, &mut output[HEADER_SIZE..], Root(content_len))
    } else {
        encode_outboard_recurse_rayon(input, &mut output[HEADER_SIZE..], Root(content_len))
    }
}

pub fn encode_to_vec(input: &[u8]) -> (Hash, Vec<u8>) {
    let size = encoded_size(input.len() as u64) as usize;
    // Unsafe code here could avoid the cost of initialization, but it's not much.
    let mut output = vec![0; size];
    let hash = encode(input, &mut output);
    (hash, output)
}

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
        copy_in_place(buf, read_offset, write_offset, content_len);
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
pub enum FlipperNext {
    FeedParent,
    TakeParent,
    Chunk(usize),
    Done,
}

fn flip_post_order_stream<T: Read + Write + Seek>(stream: &mut T) -> io::Result<()> {
    let mut write_cursor = stream.seek(End(0))?;
    let mut read_cursor = write_cursor - HEADER_SIZE as u64;
    let mut header = [0; HEADER_SIZE];
    stream.seek(Start(read_cursor))?;
    stream.read_exact(&mut header)?;
    let content_len = hash::decode_len(&header);
    let mut flipper = FlipperState::new(content_len);
    loop {
        match flipper.next() {
            FlipperNext::FeedParent => {
                let mut parent = [0; PARENT_SIZE];
                stream.seek(Start(read_cursor - PARENT_SIZE as u64))?;
                stream.read_exact(&mut parent)?;
                read_cursor -= PARENT_SIZE as u64;
                flipper.feed_parent(parent);
            }
            FlipperNext::TakeParent => {
                let parent = flipper.take_parent();
                stream.seek(Start(write_cursor - PARENT_SIZE as u64))?;
                stream.write_all(&parent)?;
                write_cursor -= PARENT_SIZE as u64;
            }
            FlipperNext::Chunk(size) => {
                let mut chunk = [0; CHUNK_SIZE];
                stream.seek(Start(read_cursor - size as u64))?;
                stream.read_exact(&mut chunk[..size])?;
                read_cursor -= size as u64;
                stream.seek(Start(write_cursor - size as u64))?;
                stream.write_all(&chunk[..size])?;
                write_cursor -= size as u64;
                flipper.chunk_moved();
            }
            FlipperNext::Done => {
                debug_assert_eq!(HEADER_SIZE as u64, write_cursor);
                stream.seek(Start(0))?;
                stream.write_all(&header)?;
                return Ok(());
            }
        }
    }
}

/// Most callers should use this writer for incremental encoding. The writer makes no attempt to
/// recover from IO errors, so callers that want to retry should start from the beginning with a new
/// writer.
#[derive(Clone, Debug)]
pub struct Writer<T: Read + Write + Seek> {
    inner: T,
    chunk_len: usize,
    total_len: u64,
    chunk_state: blake2b_simd::State,
    tree_state: hash::State,
}

impl<T: Read + Write + Seek> Writer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chunk_len: 0,
            total_len: 0,
            chunk_state: hash::new_blake2b_state(),
            tree_state: hash::State::new(),
        }
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
        flip_post_order_stream(&mut self.inner)?;

        Ok(root_hash)
    }
}

impl<T: Read + Write + Seek> Write for Writer<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            // Without more bytes coming, we're not sure how to finalize.
            return Ok(0);
        }
        if self.chunk_len == CHUNK_SIZE {
            let chunk_hash = hash::finalize_hash(&mut self.chunk_state, NotRoot);
            self.chunk_state = hash::new_blake2b_state();
            self.chunk_len = 0;
            self.tree_state.push_subtree(&chunk_hash, CHUNK_SIZE);
            while let Some(parent) = self.tree_state.merge_parent() {
                self.inner.write_all(&parent)?;
            }
        }
        let want = CHUNK_SIZE - self.chunk_len;
        let take = cmp::min(want, buf.len());
        let written = self.inner.write(&buf[..take])?;
        self.chunk_state.update(&buf[..written]);
        self.chunk_len += written;
        self.total_len += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod test {
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

    #[test]
    fn compare_encoded_to_python() {
        for &case in hash::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![9; case];
            let (_, encoded) = encode_to_vec(&input);
            let output = cmd!("python3", "./python/bao.py", "encode")
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
