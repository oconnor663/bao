// TODO: Unify this with Region somehow?
#[derive(Debug, Copy, Clone)]
pub struct Subtree {
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
    finalized: bool,
}

impl PostOrderEncoder {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            out_buf: Vec::new(),
            finalized: false,
        }
    }

    pub fn feed(&mut self, input: &[u8; ::CHUNK_SIZE]) -> &[u8] {
        if self.finalized {
            panic!("feed called on a finalized encoder");
        }
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
        if self.finalized {
            panic!("finalize called on a finalized encoder");
        }
        assert!(
            input.len() < ::CHUNK_SIZE,
            "full chunk or more passed to finalize"
        );
        self.finalized = true;
        self.out_buf.clear();
        if input.len() > 0 {
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
        let header_bytes = ::node::header_bytes(root.len, &root.hash);
        self.out_buf.extend_from_slice(&header_bytes);
        (&self.out_buf, ::hash(&header_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use unverified::Unverified;
    use node::Region;

    // Very similar to the simple decoder function, but for a post-order tree.
    fn validate_post_order_encoding(encoded: &[u8], hash: &::Digest) {
        let mut encoded = Unverified::wrap(encoded);
        let header_bytes = encoded.read_verify_back(::HEADER_SIZE, hash).expect(
            "bad header",
        );
        let header = Region::from_header_bytes(header_bytes);
        validate_post_order_encoding_inner(&mut encoded, &header);
    }

    fn validate_post_order_encoding_inner(encoded: &mut Unverified, region: &Region) {
        if region.len() <= ::CHUNK_SIZE as u64 {
            encoded
                .read_verify_back(region.len() as usize, &region.hash)
                .unwrap();
            return;
        }
        let node_bytes = encoded.read_verify_back(::NODE_SIZE, &region.hash).unwrap();
        let node = region.parse_node(node_bytes).unwrap();
        // Note that we have to validate right *then* left.
        validate_post_order_encoding_inner(encoded, &node.right);
        validate_post_order_encoding_inner(encoded, &node.left);
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
}
