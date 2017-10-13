use simple::{left_subregion_len, to_header_bytes, from_header_bytes};

#[derive(Debug, Copy, Clone)]
struct Subtree {
    len: u64,
    hash: ::Digest,
}

impl Subtree {
    fn from_chunk(chunk: &[u8]) -> Self {
        Self {
            len: chunk.len() as u64,
            hash: ::hash(chunk),
        }
    }

    fn empty() -> Self {
        Self {
            len: 0,
            hash: ::hash(&[]),
        }
    }

    fn join(&self, rhs: &Self) -> Self {
        let mut node = [0; ::NODE_SIZE];
        node[..::DIGEST_SIZE].copy_from_slice(&self.hash);
        node[::DIGEST_SIZE..].copy_from_slice(&rhs.hash);
        Self {
            len: self.len.checked_add(rhs.len).expect("overflow in encoding"),
            hash: ::hash(&node),
        }
    }
}

/// This encoder produces a *backwards* tree, with parent nodes to the right of
/// both their children. This is the only flavor of binary tree that we can
/// write in a streaming way. Our approach will be to encode all the input in
/// this form first, and then to transform it into a pre-order tree afterwards.
#[derive(Debug, Clone)]
pub struct PostOrderEncoder {
    stack: Vec<Subtree>,
    out_buf: Vec<u8>,
}

impl PostOrderEncoder {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            out_buf: Vec::new(),
        }
    }

    pub fn feed(&mut self, input: &[u8; ::CHUNK_SIZE]) -> &[u8] {
        self.out_buf.clear();
        self.out_buf.extend_from_slice(input);
        self.stack.push(Subtree::from_chunk(input));
        // Fun fact: this loop is metaphorically just like adding one to a
        // binary number and propagating the carry bit :)
        while self.stack.len() >= 2 {
            let left = self.stack[self.stack.len() - 2];
            let right = self.stack[self.stack.len() - 1];
            // In the feed loop, we only build full trees, where the left and
            // right are the same length. All the partial trees (with their
            // roots on the right edge of the final edge) get constructed
            // during finalize() below.
            if left.len != right.len {
                break;
            }
            self.out_buf.extend_from_slice(&left.hash);
            self.out_buf.extend_from_slice(&right.hash);
            self.stack.pop();
            self.stack.pop();
            self.stack.push(left.join(&right));
        }
        &self.out_buf
    }

    pub fn finalize(&mut self, input: &[u8]) -> (&[u8], ::Digest) {
        assert!(
            input.len() < ::CHUNK_SIZE,
            "full chunk or more passed to finalize"
        );
        self.out_buf.clear();
        if !input.is_empty() {
            self.out_buf.extend_from_slice(input);
            self.stack.push(Subtree::from_chunk(input));
        }
        // Joining all the remaining nodes into the final tree is very similar
        // to the feed loop above, except we drop the constraint that the left
        // and right sizes must match. That's another way of saying, nodes
        // where the left len doesn't equal the right len only exist on the
        // rightmost edge of the tree.
        while self.stack.len() >= 2 {
            let left = self.stack[self.stack.len() - 2];
            let right = self.stack[self.stack.len() - 1];
            self.out_buf.extend_from_slice(&left.hash);
            self.out_buf.extend_from_slice(&right.hash);
            self.stack.pop();
            self.stack.pop();
            self.stack.push(left.join(&right));
        }
        // Take the the final remaining subtree, or the empty subtree if there
        // was never any input, and turn it into the header.
        let root = self.stack.pop().unwrap_or_else(Subtree::empty);
        let header_bytes = to_header_bytes(root.len, &root.hash);
        self.out_buf.extend_from_slice(&header_bytes);
        (&self.out_buf, ::hash(&header_bytes))
    }
}

// When we encounter a node, we start traversing its right subregion
// immediately. Thus the node bytes themselves are stored along with the left
// subregion, since that's what we'll need to get back to.
struct Node {
    bytes: [u8; ::NODE_SIZE],
    start: u64,
    left_len: u64,
}

pub struct PostToPreFlipper {
    header: [u8; ::HEADER_SIZE],
    region_start: u64,
    region_len: u64,
    stack: Vec<Node>,
    output: Vec<u8>,
}

impl PostToPreFlipper {
    pub fn new() -> Self {
        Self {
            header: [0; ::HEADER_SIZE],
            region_start: 0,
            region_len: 0,
            stack: Vec::new(),
            output: Vec::new(),
        }
    }

    /// Feed slices from the rear of the post-order encoding towards the front.
    /// If the argument is long enough to make progress, returns (n, output). N
    /// is the number of bytes consumed, from the *back* of the input slice.
    /// Output is Some(&[u8]) if a chunk was consumed, otherwise None. If the
    /// input is too short to make progress, Err(ShortInput) is returned.
    ///
    /// Note that there is no finalize method. The caller is expected to know
    /// when it's reached the front of its own input.
    pub fn feed_back(&mut self, input: &[u8]) -> ::Result<(usize, Option<&[u8]>)> {
        // If region_len is zero, the codec is uninitialized. We read the
        // header and then either set region_len to non-zero, or immediately
        // finish (having learned that the encoding has no content).
        if self.region_len == 0 {
            let header = bytes_from_end(input, ::HEADER_SIZE)?;
            let (len, _) = from_header_bytes(header);
            self.header = *array_ref!(header, 0, ::HEADER_SIZE);
            self.region_start = 0;
            self.region_len = len;
            // If the header length field is zero, then we're already done,
            // and we need to return it as output.
            if len == 0 {
                return Ok((::HEADER_SIZE, Some(&self.header[..])));
            } else {
                return Ok((::HEADER_SIZE, None));
            }
        }
        if self.region_len > ::CHUNK_SIZE as u64 {
            // We need to read nodes. We'll keep following the right child of
            // the current node until eventually we reach the rightmost chunk.
            let left_len = left_subregion_len(self.region_len);
            let node = Node {
                bytes: *array_ref!(bytes_from_end(input, ::NODE_SIZE)?, 0, ::NODE_SIZE),
                start: self.region_start,
                left_len,
            };
            self.stack.push(node);
            self.region_start += left_len;
            self.region_len -= left_len;
            Ok((::NODE_SIZE, None))
        } else {
            // We've reached a chunk. We'll emit it as output, and we'll
            // prepend node bytes for all nodes that we're now finished with,
            // including potentially the header.
            //
            // Grab the chunk first, so that we don't make any mutations in
            // case it's too short.
            let chunk = bytes_from_end(input, self.region_len as usize)?;
            self.output.clear();
            // Figure out how many nodes we just finished with. They'll need to
            // be prepended to the chunk. If we're finished with all the nodes,
            // we'll also prepend the header. It's more common to be finished
            // with 1 node than with n nodes, so start from the end.
            let mut finished_index = self.stack.len();
            while finished_index > 0 && self.region_start == self.stack[finished_index - 1].start {
                finished_index -= 1;
            }
            if finished_index == 0 {
                self.output.extend_from_slice(&self.header[..]);
            }
            for node in self.stack.drain(finished_index..) {
                self.output.extend_from_slice(&node.bytes);
            }
            self.output.extend_from_slice(chunk);
            // If we're not yet done -- and remember, we might not have
            // finished any nodes at all -- update our start and len indices
            // for the following reads. This is where we descend left; the
            // other branch which parses nodes always descends right.
            if let Some(node) = self.stack.last() {
                self.region_start = node.start;
                self.region_len = node.left_len;
            }
            Ok((chunk.len(), Some(&self.output)))
        }
    }
}

fn bytes_from_end(input: &[u8], len: usize) -> ::Result<&[u8]> {
    if input.len() < len {
        Err(::Error::ShortInput)
    } else {
        Ok(&input[input.len() - len..])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use unverified::Unverified;
    use simple;

    // Very similar to the simple decoder function, but for a post-order tree.
    fn validate_post_order_encoding(encoded: &[u8], hash: &::Digest) {
        let mut encoded = Unverified::wrap(encoded);
        let header_bytes = encoded.read_verify_back(::HEADER_SIZE, hash).expect(
            "bad header",
        );
        let (len, hash) = simple::from_header_bytes(header_bytes);
        validate_recurse(&mut encoded, len, &hash);
    }

    fn validate_recurse(encoded: &mut Unverified, region_len: u64, region_hash: &::Digest) {
        if region_len <= ::CHUNK_SIZE as u64 {
            encoded
                .read_verify_back(region_len as usize, region_hash)
                .unwrap();
            return;
        }
        let node_bytes = encoded.read_verify_back(::NODE_SIZE, region_hash).unwrap();
        let (left_len, right_len, left_hash, right_hash) =
            simple::split_node(region_len, node_bytes);
        // Note that we have to validate ***right then left***, because we're
        // reading from the back.
        validate_recurse(encoded, right_len, &right_hash);
        validate_recurse(encoded, left_len, &left_hash);
    }

    fn post_order_encode_all(mut input: &[u8]) -> (Vec<u8>, ::Digest) {
        let mut encoder = PostOrderEncoder::new();
        let mut output = Vec::new();
        while input.len() >= ::CHUNK_SIZE {
            let out_slice = encoder.feed(array_ref!(input, 0, ::CHUNK_SIZE));
            output.extend_from_slice(out_slice);
            input = &input[::CHUNK_SIZE..];
        }
        let (out_slice, hash) = encoder.finalize(input);
        output.extend_from_slice(out_slice);
        (output, hash)
    }

    #[test]
    fn test_post_order_encoder() {
        for &case in ::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0x33; case];
            let (encoded, hash) = post_order_encode_all(&input);
            validate_post_order_encoding(&encoded, &hash);

            // Also compare against the hash from the standard encoding.
            // Despite the difference in tree layout, the hashes should all be
            // the same.
            let (_, regular_hash) = ::simple::encode(&input);
            assert_eq!(
                regular_hash,
                hash,
                "post order hash doesn't match the standard encoding"
            );
        }
    }

    // Run the PostToPreFlipper across the encoded buffer, flipping it in place.
    fn flip_in_place(buf: &mut [u8]) {
        let mut flipper = PostToPreFlipper::new();
        let mut read_cursor = buf.len();
        let mut write_cursor = buf.len();
        while read_cursor > 0 {
            // First try feeding an empty slice, and confirm that we always get
            // a ShortInput error back.
            assert_eq!(Err(::Error::ShortInput), flipper.feed_back(&[]));
            // Then just feed in all the available bytes and let the flipper
            // take what it wants.
            let (n, maybe_output) = flipper.feed_back(&buf[..read_cursor]).unwrap();
            read_cursor -= n;
            if let Some(output) = maybe_output {
                let write_start = write_cursor - output.len();
                assert!(
                    write_start >= read_cursor,
                    "mustn't write over unread bytes"
                );
                buf[write_start..write_cursor].copy_from_slice(output);
                write_cursor = write_start;
            }
        }
        assert_eq!(write_cursor, 0);
    }

    #[test]
    fn test_flipper() {
        for &case in ::TEST_CASES {
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
