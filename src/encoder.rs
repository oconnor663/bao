use std::ops::Deref;
use hash::left_len;

use hash::{self, Hash, CHUNK_SIZE, DIGEST_SIZE};

pub const NODE_SIZE: usize = 2 * DIGEST_SIZE;
pub const HEADER_SIZE: usize = 8;

#[derive(Debug, Copy, Clone)]
struct Subtree {
    len: u64,
    hash: Hash,
}

impl Subtree {
    fn from_chunk(chunk: &[u8]) -> Self {
        Self {
            len: chunk.len() as u64,
            hash: hash::hash(chunk),
        }
    }

    fn join(&self, rhs: &Self) -> Self {
        let mut node = [0; NODE_SIZE];
        node[..DIGEST_SIZE].copy_from_slice(&self.hash);
        node[DIGEST_SIZE..].copy_from_slice(&rhs.hash);
        Self {
            len: self.len.checked_add(rhs.len).expect("overflow in encoding"),
            hash: hash::hash(&node),
        }
    }
}

// returns number of bytes used
fn extend_up_to(buf: &mut Vec<u8>, target_len: usize, input: &[u8]) -> usize {
    let wanted = target_len.saturating_sub(buf.len());
    let used = input.len().min(wanted);
    buf.extend_from_slice(&input[..used]);
    used
}

/// This encoder produces a *backwards* tree, with parent nodes to the right of
/// both their children. This is the only flavor of binary tree that we can
/// write in a streaming way. Our approach will be to encode all the input in
/// this form first, and then to transform it into a pre-order tree afterwards.
#[derive(Debug, Clone)]
pub struct PostOrderEncoder {
    stack: Vec<Subtree>,
    buf: Vec<u8>,
}

impl PostOrderEncoder {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            buf: Vec::new(),
        }
    }

    // returns (used, output), where output may be empty
    pub fn feed(&mut self, input: &[u8]) -> (usize, &[u8]) {
        // If the buffer len is >= CHUNK_SIZE, then it was used as output in
        // the last call to feed(), and we need to clear it now. (Note that
        // finish() has the same invariant.)
        if self.buf.len() >= CHUNK_SIZE {
            self.buf.clear()
        }
        // Consume bytes from the caller until the buffer is CHUNK_SIZE. If we
        // don't get there, short circuit and let the caller feed more bytes.
        let used = extend_up_to(&mut self.buf, CHUNK_SIZE, input);
        if self.buf.len() < CHUNK_SIZE {
            return (used, &[]);
        }
        // We have a full chunk in the buffer. Update the node stack, append
        // any nodes that are finished, and emit the result as ouput. The next
        // call to feed() will clear the buffer.
        self.stack.push(Subtree::from_chunk(&self.buf));
        // Fun fact: this loop is metaphorically just like adding one to a
        // binary number and propagating the carry bit :)
        while self.stack.len() >= 2 {
            let left = self.stack[self.stack.len() - 2];
            let right = self.stack[self.stack.len() - 1];
            // In the feed loop, we only build full trees, where the left and
            // right are the same length. All the partial trees (with their
            // roots on the right edge of the final edge) get constructed
            // during finish() below.
            if left.len != right.len {
                break;
            }
            self.buf.extend_from_slice(&left.hash);
            self.buf.extend_from_slice(&right.hash);
            self.stack.pop();
            self.stack.pop();
            self.stack.push(left.join(&right));
        }
        (used, &self.buf)
    }

    pub fn finish(&mut self) -> (Hash, &[u8]) {
        // If the buffer len is >= CHUNK_SIZE, then it was used as output in
        // the last call to feed(), and we need to clear it now. (Note that
        // feed() has the same invariant.)
        if self.buf.len() >= CHUNK_SIZE {
            self.buf.clear()
        }
        // If the buffer is nonempty, then there's a final partial chunk that
        // needs to get added to the node stack. In that case the remaining
        // nodes will get appended to the chunk.
        if self.buf.len() > 0 {
            self.stack.push(Subtree::from_chunk(&self.buf));
        }
        // Joining all the remaining nodes into the final tree is very similar
        // to the feed loop above, except we drop the constraint that the left
        // and right sizes must match. That's another way of saying, nodes
        // where the left len doesn't equal the right len only exist on the
        // rightmost edge of the tree.
        while self.stack.len() >= 2 {
            let left = self.stack[self.stack.len() - 2];
            let right = self.stack[self.stack.len() - 1];
            self.buf.extend_from_slice(&left.hash);
            self.buf.extend_from_slice(&right.hash);
            self.stack.pop();
            self.stack.pop();
            self.stack.push(left.join(&right));
        }
        // Take the the final remaining subtree, or the empty subtree if there
        // was never any input, and turn it into the header.
        let root = self.stack.pop().unwrap_or(Subtree::from_chunk(&[]));
        self.buf.extend_from_slice(&hash::encode_len(root.len));
        // TODO: THIS IS NOT CORRECT YET
        (hash::hash(&[]), &self.buf)
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
    bytes: [u8; NODE_SIZE],
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
            let (filled, used) = self.buf.reinit_fill(NODE_SIZE, input);
            if !filled {
                return (used, &[]);
            }
            let node = Node {
                bytes: *array_ref!(&self.buf, 0, NODE_SIZE),
                start: self.region_start,
                left_len: left_len(self.region_len),
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
    use unverified::Unverified;
    use hash::TEST_CASES;

    // A recursive decoder function for a post-order encoded tree. This is for
    // directly unit testing the intermediate output, before the reversal step.
    fn validate_post_order_encoding(encoded: &[u8], hash: &Hash) {
        let mut encoded = Unverified::wrap(encoded);
        let header_bytes = encoded
            .read_verify_back(HEADER_SIZE, hash)
            .expect("bad header");
        let (len, hash) = simple::from_header_bytes(header_bytes);
        validate_recurse(&mut encoded, len, &hash);
    }

    fn split_node(content_len: u64, node_bytes: &[u8]) -> (u64, u64, Hash, Hash) {
        let left_len = left_len(content_len);
        let right_len = content_len - left_len;
        let left_hash = *array_ref!(node_bytes, 0, DIGEST_SIZE);
        let right_hash = *array_ref!(node_bytes, DIGEST_SIZE, DIGEST_SIZE);
        (left_len, right_len, left_hash, right_hash)
    }

    fn validate_recurse(encoded: &mut Unverified, region_len: u64, region_hash: &Hash) {
        if region_len <= CHUNK_SIZE as u64 {
            encoded
                .read_verify_back(region_len as usize, region_hash)
                .unwrap();
            return;
        }
        let node_bytes = encoded.read_verify_back(NODE_SIZE, region_hash).unwrap();
        let (left_len, right_len, left_hash, right_hash) = split_node(region_len, node_bytes);
        // Note that we have to validate ***right then left***, because we're
        // reading from the back.
        validate_recurse(encoded, right_len, &right_hash);
        validate_recurse(encoded, left_len, &left_hash);
    }

    fn post_order_encode_all(mut input: &[u8]) -> (Vec<u8>, Hash) {
        let mut encoder = PostOrderEncoder::new();
        let mut output = Vec::new();
        while input.len() > 0 {
            let (n, out_slice) = encoder.feed(input);
            output.extend_from_slice(out_slice);
            input = &input[n..];
        }
        let (hash, out_slice) = encoder.finish();
        output.extend_from_slice(out_slice);
        (output, hash)
    }

    #[test]
    fn test_post_order_encoder() {
        for &case in TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0x33; case];
            let (encoded, hash) = post_order_encode_all(&input);
            validate_post_order_encoding(&encoded, &hash);

            // Also compare against the hash from the standard encoding.
            // Despite the difference in tree layout, the hashes should all be
            // the same.
            let (_, regular_hash) = ::simple::encode(&input);
            assert_eq!(
                regular_hash, hash,
                "post order hash doesn't match the standard encoding"
            );
        }
    }

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

    // Run the PostToPreFlipper across the encoded buffer, flipping it in place.
    fn flip_in_place(buf: &mut [u8]) {
        let mut flipper = PostToPreFlipper::new();
        let mut read_end = buf.len();
        let mut write_start = buf.len();
        while read_end > 0 {
            let (used, output) = flipper.feed_back(&buf[..read_end]);
            read_end -= used;
            let write_end = write_start;
            write_start -= output.len();
            assert!(write_start >= read_end, "mustn't write over unread bytes");
            buf[write_start..write_end].copy_from_slice(output);
        }
        assert_eq!(read_end, 0);
        assert_eq!(write_start, 0);
    }

    #[test]
    fn test_flipper() {
        for &case in TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0x01; case];
            let (mut encoded, hash) = post_order_encode_all(&input);
            flip_in_place(&mut encoded);
            // Now that the encoding is pre-order, we can test decoding it with
            // the regular simple decoder.
            let decoded = simple::decode(&encoded, &hash).unwrap();
            assert_eq!(input, decoded);
        }
    }
}
