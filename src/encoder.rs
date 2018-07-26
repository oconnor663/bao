use blake2_c::blake2b;
use hash::Finalization::{NotRoot, Root};
use hash::{self, Hash, CHUNK_SIZE, HASH_SIZE, HEADER_SIZE, PARENT_SIZE};
use std::cmp;
use std::ops::Deref;

/// Encode a given input all at once in memory.
pub fn encode(input: &[u8]) -> (Hash, Vec<u8>) {
    let (mut output, hash) = encode_post_order(input);
    let mut flipper = PostToPreFlipper::new();
    let mut read_cursor = output.len();
    let mut write_cursor = output.len();
    while read_cursor > 0 {
        let (used, out) = flipper.feed_back(&output[..read_cursor]);
        read_cursor -= used;
        debug_assert!(write_cursor - out.len() >= read_cursor, "wrote over input");
        output[write_cursor - out.len()..write_cursor].copy_from_slice(out);
        write_cursor -= out.len();
    }
    (hash, output)
}

fn encode_post_order(mut input: &[u8]) -> (Vec<u8>, Hash) {
    let encoded_len = hash::encode_len(input.len() as u64);
    let finalization = Root(input.len() as u64);
    let mut ret = Vec::new();
    let root_hash;
    if input.len() <= CHUNK_SIZE {
        ret.extend_from_slice(input);
        root_hash = hash::hash_chunk(input, finalization);
    } else {
        let mut state = hash::State::new();
        while input.len() > CHUNK_SIZE {
            ret.extend_from_slice(&input[..CHUNK_SIZE]);
            let chunk_hash = hash::hash_chunk(&input[..CHUNK_SIZE], NotRoot);
            state.push_subtree(chunk_hash);
            while let Some(parent) = state.merge_parent() {
                ret.extend_from_slice(&parent);
            }
            input = &input[CHUNK_SIZE..];
        }
        ret.extend_from_slice(&input);
        let final_chunk_hash = hash::hash_chunk(input, NotRoot);
        state.push_subtree(final_chunk_hash);
        loop {
            let (parent, maybe_root) = state.merge_finish(finalization);
            ret.extend_from_slice(&parent);
            if let Some(root) = maybe_root {
                root_hash = root;
                break;
            }
        }
    }
    ret.extend_from_slice(&encoded_len);
    (ret, root_hash)
}

/// Prior to the final chunk, to calculate the number of post-order parent nodes for a chunk, we
/// need to know the height of the subtree for which the chunk is the rightmost. This is the same as
/// the number of trailing ones in the chunk index (counting from 0). For example, chunk number 11
/// (0b1011) has two trailing parent nodes.
///
/// Note that this is closely related to the trick we're using in hash::State::needs_merge. The
/// number of trailing zeroes at a given index is the same as the number of ones that switched off
/// when we moved rightward from the previous index.
fn post_order_parent_nodes_nonfinal(chunk: u64) -> usize {
    (!chunk).trailing_zeros() as usize
}

/// The final chunk of a post order tree has to have a parent node for each of the not yet merged
/// subtrees behind it. This is the same as the total number of ones in the chunk index (counting
/// from 0).
fn post_order_parent_nodes_final(chunk: u64) -> usize {
    chunk.count_ones() as usize
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
fn pre_order_parent_nodes(chunk: u64, total_chunks: u64) -> usize {
    let remaining = total_chunks - chunk;
    let starting_bound = 64 - (remaining - 1).leading_zeros();
    let interior_bound = chunk.trailing_zeros();
    cmp::min(starting_bound, interior_bound) as usize
}

pub struct PostOrderEncoder {
    subtree_stack: Vec<Hash>,
    total_len: u64,
    chunk_state: blake2b::State,
    chunk_len: usize,
    output_buffer: [u8; PARENT_SIZE],
}

impl PostOrderEncoder {
    pub fn new() -> Self {
        Self {
            subtree_stack: Vec::new(),
            total_len: 0,
            chunk_state: blake2b::State::new(HASH_SIZE),
            chunk_len: 0,
            output_buffer: [0; PARENT_SIZE],
        }
    }

    // Whenever we finish with two subtrees of the same size (once every two
    // chunks, once again every four chunks, etc.), we pop them out of the
    // subtree stack and merge them into a parent node. That node gets emitted
    // to the caller as output, and its hash goes back into the stack as a
    // merged subtree.
    fn merge_parent_node(&mut self, finalization: hash::Finalization) -> &[u8] {
        let right_child = self.subtree_stack.pop().expect("called with too few nodes");
        let left_child = self.subtree_stack.pop().expect("called with too few nodes");
        let parent_hash = hash::hash_parent(&left_child, &right_child, finalization);
        // Push the parent hash back into the subtree stack, fill the parent
        // node buffer, and return it to the caller as a slice of output bytes.
        self.subtree_stack.push(parent_hash);
        self.output_buffer[..HASH_SIZE].copy_from_slice(&left_child);
        self.output_buffer[HASH_SIZE..].copy_from_slice(&right_child);
        &self.output_buffer
    }

    /// Returns a tuple of the count of input bytes consumed and a slice of
    /// output bytes. Some calls will consume no bytes but still produce
    /// output. The encoder may inspect input bytes beyond what it tells you it
    /// consumed, and if you "change your mind" about feeding the unconsumed
    /// bytes again, the result is unspecified.
    pub fn feed<'a>(&'a mut self, input: &'a [u8]) -> (usize, &'a [u8]) {
        // If we don't have any new bytes, short circuit. We don't know whether
        // something might be the root.
        if input.is_empty() {
            return (0, &[]);
        }
        // If we have a full chunk already, finish hashing it. We know it's not
        // the root now, because we have more bytes coming in.
        if self.chunk_len == CHUNK_SIZE {
            let new_subtree = hash::finalize_hash(&mut self.chunk_state, NotRoot);
            self.subtree_stack.push(new_subtree);
            self.chunk_len = 0;
            self.chunk_state = blake2b::State::new(HASH_SIZE);
        }
        // Now, if we need to emit any parent nodes, do them one by one. This
        // lets us avoid holding a big buffer. The trees_after_merging trick
        // here is the same as in hash::rollup_subtree. In this case, in
        // addition to merging subtrees, we need to emit a parent node.
        // (Remember, we're building a *post*-order tree here.)
        let trees_after_merging = (self.total_len / CHUNK_SIZE as u64).count_ones() as usize;
        if self.subtree_stack.len() > trees_after_merging {
            return (0, self.merge_parent_node(NotRoot));
        }
        // Finally, if we didn't stop to emit a node above, consume some more
        // bytes from the caller. We immediately return those back as output
        // also.
        let want = CHUNK_SIZE - self.chunk_len;
        let take = cmp::min(want, input.len());
        self.chunk_state.update(&input[..take]);
        self.chunk_len += take;
        self.total_len += take as u64;
        (take, &input[..take])
    }

    fn length_header(&mut self) -> &[u8] {
        let buf = array_mut_ref!(&mut self.output_buffer, 0, HEADER_SIZE);
        *buf = hash::encode_len(self.total_len);
        buf
    }

    /// Once all the input has been conusmed by `feed`, the caller must call
    /// `finish` _in a loop_, until its first return value is `Some`. Each call
    /// will yield more output bytes. The hash returned by the last call is the
    /// root hash of the whole tree.
    pub fn finish(&mut self) -> (Option<Hash>, &[u8]) {
        // If there was only one chunk, hash it as the root, even if it's empty.
        if self.total_len <= CHUNK_SIZE as u64 {
            let root_hash = hash::finalize_hash(&mut self.chunk_state, Root(self.total_len));
            return (Some(root_hash), self.length_header());
        }
        // Because of the contract above (never change your mind about feeding
        // bytes), the first time we get here, chunk_len will always be
        // non-zero. Finish hashing that chunk, and then zero it out for
        // subsequent calls.
        if self.chunk_len > 0 {
            self.subtree_stack
                .push(hash::finalize_hash(&mut self.chunk_state, NotRoot));
            self.chunk_len = 0;
        }
        // Now we need to merge all the subtrees into parent nodes, whether or
        // not they're full.
        if self.subtree_stack.len() > 1 {
            let finalization = if self.subtree_stack.len() == 2 {
                Root(self.total_len)
            } else {
                NotRoot
            };
            return (None, self.merge_parent_node(finalization));
        }
        // In the final call, all the subtrees have been merged, and the
        // remaining hash is the root hash.
        (Some(self.subtree_stack[0]), self.length_header())
    }
}

/// A buffer that supports efficiently prepending. This is useful for driving
/// the PostToPreFlipper and it's IO wrapper, making reading from the back
/// slightly less inconvenient.
pub(crate) struct BackBuffer {
    buf: Vec<u8>,
    cursor: usize,
    filled: bool,
}

impl BackBuffer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            filled: false,
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len() - self.cursor
    }

    pub fn clear(&mut self) {
        self.cursor = self.buf.len();
        self.filled = false;
    }

    /// Add bytes onto the front of the buffer, reallocating if necessary.
    pub fn extend_front(&mut self, input: &[u8]) {
        if input.len() > self.cursor {
            // Not enough space. Reallocate by at least a factor of 2. That
            // keeps our amortized cost down, and it also means we can copy
            // non-overlapping slices without unsafe code.
            let needed = self.len() + input.len();
            let new_size = needed.max(2 * self.buf.len());
            let old_end = self.buf.len();
            self.buf.resize(new_size, 0);
            let (old_slice, new_slice) = self.buf.split_at_mut(old_end);
            let content = &old_slice[self.cursor..];
            let new_content_start = new_slice.len() - content.len();
            new_slice[new_content_start..].copy_from_slice(content);
            self.cursor = new_size - content.len();
        }
        let start = self.cursor - input.len();
        self.buf[start..self.cursor].copy_from_slice(input);
        self.cursor = start;
    }

    /// The convention for filling the buffer in the PostToPreFlipper is that,
    /// once it's filled to the target length, we set a filled flag. We'll then
    /// automatically empty it in the next call to reinit_fill, so the caller
    /// must finish using the contents before then. This lets us return a slice
    /// from the filled buffer, without needing a destructor somewhere to clear
    /// the buffer after we're done with the slice.
    ///
    /// Note that when this consumes less than the entire input slice, it
    /// consumes from the *back* of it.
    pub fn reinit_fill(&mut self, target_len: usize, input: &[u8]) -> (bool, usize) {
        if self.filled {
            self.clear();
        }
        debug_assert!(self.len() < target_len);
        let wanted = target_len - self.len();
        let used = input.len().min(wanted);
        self.extend_front(&input[input.len() - used..]);
        self.filled = self.len() == target_len;
        (self.filled, used)
    }
}

impl Deref for BackBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[self.cursor..]
    }
}

// When we encounter a node, we start traversing its right subregion
// immediately. Thus the node bytes themselves are stored along with the left
// subregion, since that's what we'll need to get back to.
#[derive(Clone, Copy)]
struct Node {
    bytes: [u8; PARENT_SIZE],
    start: u64,
    left_len: u64,
}

pub struct PostToPreFlipper {
    header: [u8; HEADER_SIZE],
    region_start: u64,
    region_len: u64,
    stack: Vec<Node>,
    buf: BackBuffer,
}

impl PostToPreFlipper {
    pub fn new() -> Self {
        Self {
            header: [0; HEADER_SIZE],
            region_start: 0,
            region_len: 0,
            stack: Vec::new(),
            buf: BackBuffer::new(),
        }
    }

    /// Feed slices from the rear of the post-order encoding towards the front.
    /// Returns (n, output), though the output slice may be empty. Note that n
    /// is the count of bytes consumed from the *back* of the input.
    ///
    /// Note also that there is no finish method. The caller is expected to
    /// know when it's reached the front of its own input.
    pub fn feed_back(&mut self, input: &[u8]) -> (usize, &[u8]) {
        if self.region_len == 0 {
            // The codec is uninitialized. We read the header and then either
            // set region_len to non-zero, or immediately finish (having
            // learned that the encoding has no content).
            let (filled, used) = self.buf.reinit_fill(HEADER_SIZE, input);
            if !filled {
                return (used, &[]);
            }
            self.header = *array_ref!(&self.buf, 0, HEADER_SIZE);
            let len = hash::decode_len(&self.header);
            self.region_start = 0;
            self.region_len = len;
            // If the header length field is zero, then we're already done,
            // and we need to return it as output.
            if len == 0 {
                (used, &self.header)
            } else {
                (used, &[])
            }
        } else if self.region_len > CHUNK_SIZE as u64 {
            // We need to read nodes. We'll keep following the right child of
            // the current node until eventually we reach the rightmost chunk.
            let (filled, used) = self.buf.reinit_fill(PARENT_SIZE, input);
            if !filled {
                return (used, &[]);
            }
            let node = Node {
                bytes: *array_ref!(&self.buf, 0, PARENT_SIZE),
                start: self.region_start,
                left_len: hash::left_len(self.region_len),
            };
            self.stack.push(node);
            self.region_start += node.left_len;
            self.region_len -= node.left_len;
            (used, &[])
        } else {
            // We've reached a chunk. Once we've collected the entire chunk,
            // we'll prepend all the nodes we're finished with, potentially
            // including the header, and emit the whole thing as output.
            let (filled, used) = self.buf.reinit_fill(self.region_len as usize, input);
            if !filled {
                return (used, &[]);
            }
            // Prepend all the nodes that we're finished with, and maybe update
            // our position.
            while let Some(&node) = self.stack.last() {
                if node.start == self.region_start {
                    self.buf.extend_front(&node.bytes);
                    self.stack.pop();
                } else {
                    // We're not done with all the nodes yet. Record our new
                    // position. This is where we descend left; the other
                    // branch which parses nodes always descends right.
                    self.region_start = node.start;
                    self.region_len = node.left_len;
                    break;
                }
            }
            // Prepend the header, if we've reached the beginning.
            if self.stack.is_empty() {
                self.buf.extend_front(&self.header);
            }
            (used, &self.buf)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    fn python_encode(input: &[u8]) -> (Hash, Vec<u8>) {
        let hex_hash = cmd!("python3", "./python/bao.py", "hash")
            .input(input)
            .read()
            .expect("is python3 installed?");
        let hash = hex::decode(&hex_hash).expect("bad hex?");
        let output = cmd!("python3", "./python/bao.py", "encode")
            .input(input)
            .stdout_capture()
            .run()
            .unwrap();
        (*array_ref!(hash, 0, HASH_SIZE), output.stdout)
    }

    #[test]
    fn check_hash() {
        for &case in hash::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![9; case];
            let expected_hash = hash::hash(&input);
            let (encoded_hash, _) = encode(&input);
            assert_eq!(expected_hash, encoded_hash, "hash mismatch");
        }
    }

    #[test]
    fn compare_encoded_to_python() {
        for &case in hash::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![9; case];
            let (_, python_encoded) = python_encode(&input);
            let (_, encoded) = encode(&input);
            assert_eq!(python_encoded, encoded, "encoded mismatch");
        }
    }

    // This is another way to calculate the number of parent nodes, which takes longer but is less
    // magical. We use it for testing below.
    fn make_pre_post_list(total_chunks: u64) -> Vec<(usize, usize)> {
        fn recurse(start: u64, size: u64, answers: &mut Vec<(usize, usize)>) {
            assert!(size > 0);
            if size == 1 {
                return;
            }
            answers[start as usize].0 += 1;
            answers[(start + size - 1) as usize].1 += 1;
            let split = hash::largest_power_of_two(size - 1);
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
            let pre_post_list = make_pre_post_list(total_chunks);
            for chunk in 0..total_chunks {
                let (expected_pre, expected_post) = pre_post_list[chunk as usize];
                let pre = pre_order_parent_nodes(chunk, total_chunks);
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

    // fn test_encode_against_python

    //     // A recursive decoder function for a post-order encoded tree. This is for
    //     // directly unit testing the intermediate output, before the reversal step.
    //     fn validate_post_order_encoding(encoded: &[u8], hash: &Hash) {
    //         let mut encoded = Unverified::wrap(encoded);
    //         let header_bytes = encoded
    //             .read_verify_back(HEADER_SIZE, hash)
    //             .expect("bad header");
    //         let (len, hash) = simple::from_header_bytes(header_bytes);
    //         validate_recurse(&mut encoded, len, &hash);
    //     }

    //     fn split_node(content_len: u64, node_bytes: &[u8]) -> (u64, u64, Hash, Hash) {
    //         let left_len = left_len(content_len);
    //         let right_len = content_len - left_len;
    //         let left_hash = *array_ref!(node_bytes, 0, HASH_SIZE);
    //         let right_hash = *array_ref!(node_bytes, HASH_SIZE, HASH_SIZE);
    //         (left_len, right_len, left_hash, right_hash)
    //     }

    //     fn validate_recurse(encoded: &mut Unverified, region_len: u64, region_hash: &Hash) {
    //         if region_len <= CHUNK_SIZE as u64 {
    //             encoded
    //                 .read_verify_back(region_len as usize, region_hash)
    //                 .unwrap();
    //             return;
    //         }
    //         let node_bytes = encoded.read_verify_back(PARENT_SIZE, region_hash).unwrap();
    //         let (left_len, right_len, left_hash, right_hash) = split_node(region_len, node_bytes);
    //         // Note that we have to validate ***right then left***, because we're
    //         // reading from the back.
    //         validate_recurse(encoded, right_len, &right_hash);
    //         validate_recurse(encoded, left_len, &left_hash);
    //     }

    //     fn post_order_encode_all(mut input: &[u8]) -> (Vec<u8>, Hash) {
    //         let mut encoder = PostOrderEncoder::new();
    //         let mut output = Vec::new();
    //         while input.len() > 0 {
    //             let (n, out_slice) = encoder.feed(input);
    //             output.extend_from_slice(out_slice);
    //             input = &input[n..];
    //         }
    //         let (hash, out_slice) = encoder.finish();
    //         output.extend_from_slice(out_slice);
    //         (output, hash)
    //     }

    //     #[test]
    //     fn test_post_order_encoder() {
    //         for &case in TEST_CASES {
    //             println!("starting case {}", case);
    //             let input = vec![0x33; case];
    //             let (encoded, hash) = post_order_encode_all(&input);
    //             validate_post_order_encoding(&encoded, &hash);

    //             // Also compare against the hash from the standard encoding.
    //             // Despite the difference in tree layout, the hashes should all be
    //             // the same.
    //             let (_, regular_hash) = ::simple::encode(&input);
    //             assert_eq!(
    //                 regular_hash, hash,
    //                 "post order hash doesn't match the standard encoding"
    //             );
    //         }
    //     }

    #[test]
    fn test_back_buffer() {
        let mut buf = BackBuffer::new();

        // Test filling up the buffer with a series of writes.
        buf.extend_front(&[b'r']);
        assert_eq!(buf.buf.len(), 1);
        assert_eq!(buf.cursor, 0);
        assert_eq!(buf.len(), 1);
        buf.extend_front(&[b'a']);
        assert_eq!(buf.buf.len(), 2);
        assert_eq!(buf.cursor, 0);
        assert_eq!(buf.len(), 2);
        buf.extend_front(&[b'b']);
        assert_eq!(buf.buf.len(), 4);
        assert_eq!(buf.cursor, 1);
        assert_eq!(buf.len(), 3);
        buf.extend_front("foo".as_bytes());
        assert_eq!(buf.buf.len(), 8);
        assert_eq!(buf.cursor, 2);
        assert_eq!(buf.len(), 6);
        assert_eq!(&*buf, "foobar".as_bytes());

        // Test clear.
        buf.clear();
        assert_eq!(buf.buf.len(), 8);
        assert_eq!(buf.cursor, 8);
        assert_eq!(buf.len(), 0);

        // Test the reinit_fill convention.
        buf.reinit_fill(2, &[0]);
        assert_eq!(buf.buf.len(), 8);
        assert_eq!(buf.cursor, 7);
        assert_eq!(buf.len(), 1);
        buf.reinit_fill(2, &[0]);
        assert_eq!(buf.buf.len(), 8);
        assert_eq!(buf.cursor, 6);
        assert_eq!(buf.len(), 2);
        // Another fill after the target should reinit the buffer.
        buf.reinit_fill(2, &[0]);
        assert_eq!(buf.buf.len(), 8);
        assert_eq!(buf.cursor, 7);
        assert_eq!(buf.len(), 1);
    }

    //     // Run the PostToPreFlipper across the encoded buffer, flipping it in place.
    //     fn flip_in_place(buf: &mut [u8]) {
    //         let mut flipper = PostToPreFlipper::new();
    //         let mut read_end = buf.len();
    //         let mut write_start = buf.len();
    //         while read_end > 0 {
    //             let (used, output) = flipper.feed_back(&buf[..read_end]);
    //             read_end -= used;
    //             let write_end = write_start;
    //             write_start -= output.len();
    //             assert!(write_start >= read_end, "mustn't write over unread bytes");
    //             buf[write_start..write_end].copy_from_slice(output);
    //         }
    //         assert_eq!(read_end, 0);
    //         assert_eq!(write_start, 0);
    //     }

    //     #[test]
    //     fn test_flipper() {
    //         for &case in TEST_CASES {
    //             println!("starting case {}", case);
    //             let input = vec![0x01; case];
    //             let (mut encoded, hash) = post_order_encode_all(&input);
    //             flip_in_place(&mut encoded);
    //             // Now that the encoding is pre-order, we can test decoding it with
    //             // the regular simple decoder.
    //             let decoded = simple::decode(&encoded, &hash).unwrap();
    //             assert_eq!(input, decoded);
    //         }
    //     }
}
