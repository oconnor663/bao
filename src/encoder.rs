use byteorder::{ByteOrder, BigEndian};

// TODO: Factor this type up and combine it with Region.
#[derive(Debug, Copy, Clone)]
struct Subtree {
    len: u64,
    hash: ::Digest,
}

impl Subtree {
    fn join(&self, rhs: &Subtree) -> Subtree {
        let mut node = [0; 2 * ::DIGEST_SIZE];
        node[..::DIGEST_SIZE].copy_from_slice(&self.hash);
        node[::DIGEST_SIZE..].copy_from_slice(&rhs.hash);
        Subtree {
            len: self.len.checked_add(rhs.len).expect("len overflow"),
            hash: ::hash(&node),
        }
    }

    #[cfg(test)]
    fn children(&self, node_bytes: &[u8]) -> (Subtree, Subtree) {
        let left = Subtree {
            len: ::node::left_subregion_len(self.len),
            hash: *array_ref!(node_bytes, 0, ::DIGEST_SIZE),
        };
        let right = Subtree {
            len: self.len - left.len,
            hash: *array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE),
        };
        (left, right)
    }

    fn to_header_bytes(&self) -> [u8; ::HEADER_SIZE] {
        let mut ret = [0; ::HEADER_SIZE];
        BigEndian::write_u64(&mut ret[..8], self.len);
        ret[8..].copy_from_slice(&self.hash);
        ret
    }

    #[cfg(test)]
    fn from_header_bytes(bytes: &[u8]) -> Subtree {
        Subtree {
            len: BigEndian::read_u64(&bytes[..8]),
            hash: *array_ref!(bytes, 8, ::DIGEST_SIZE),
        }
    }

    fn from_chunk(chunk: &[u8]) -> Subtree {
        Subtree {
            len: chunk.len() as u64,
            hash: ::hash(chunk),
        }
    }

    fn empty() -> Subtree {
        Subtree {
            len: 0,
            hash: ::hash(&*b""),
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
        let header_bytes = root.to_header_bytes();
        self.out_buf.extend_from_slice(&header_bytes);
        (&self.out_buf, ::hash(&header_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use unverified::Unverified;

    // Very similar to the simple decoder function, but for a post-order tree.
    fn validate_post_order_encoding(encoded: &[u8], hash: &::Digest) {
        let mut encoded = Unverified::wrap(encoded);
        let header_bytes = encoded.read_verify_back(::HEADER_SIZE, hash).expect(
            "bad header",
        );
        let header = Subtree::from_header_bytes(header_bytes);
        validate_post_order_encoding_inner(&mut encoded, &header);
    }

    fn validate_post_order_encoding_inner(encoded: &mut Unverified, subtree: &Subtree) {
        if subtree.len <= ::CHUNK_SIZE as u64 {
            encoded
                .read_verify_back(subtree.len as usize, &subtree.hash)
                .expect("bad chunk");
            return;
        }
        let node_bytes = encoded
            .read_verify_back(::NODE_SIZE, &subtree.hash)
            .expect("bad node");
        let (left_subtree, right_subtree) = subtree.children(node_bytes);
        // Note that we have to validate right *then* left.
        validate_post_order_encoding_inner(encoded, &right_subtree);
        validate_post_order_encoding_inner(encoded, &left_subtree);
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
