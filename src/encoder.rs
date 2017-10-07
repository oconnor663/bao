use byteorder::{ByteOrder, BigEndian};

// TODO: Factor this type up and combine it with Region.
#[derive(Debug, Copy, Clone)]
struct Subtree {
    len: u64,
    hash: ::Digest,
}

impl Subtree {
    #[cfg(test)]
    fn encoded_len(&self) -> u64 {
        // Divide rounding up.
        let num_chunks = (self.len / ::CHUNK_SIZE as u64) +
            (self.len % ::CHUNK_SIZE as u64 > 0) as u64;
        // Note that the empty input results in zero nodes, not "-1" nodes.
        self.len + num_chunks.saturating_sub(1) * ::NODE_SIZE as u64
    }

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
    fn children(&self, unverified_node: &::evil::EvilBytes) -> ::Result<(Subtree, Subtree)> {
        let verified_bytes = unverified_node.verify(::NODE_SIZE, &self.hash)?;
        let left = Subtree {
            len: ::node::left_subregion_len(self.len),
            hash: *array_ref!(verified_bytes, 0, ::DIGEST_SIZE),
        };
        let right = Subtree {
            len: self.len - left.len,
            hash: *array_ref!(verified_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE),
        };
        Ok((left, right))
    }

    fn to_header_bytes(&self) -> [u8; ::HEADER_SIZE] {
        let mut ret = [0; ::HEADER_SIZE];
        BigEndian::write_u64(&mut ret[..8], self.len);
        ret[8..].copy_from_slice(&self.hash);
        ret
    }

    #[cfg(test)]
    fn from_header_bytes(
        unverified_header: &::evil::EvilBytes,
        hash: &::Digest,
    ) -> ::Result<Subtree> {
        let verified_bytes = unverified_header.verify(::HEADER_SIZE, hash)?;
        Ok(Subtree {
            len: BigEndian::read_u64(&verified_bytes[..8]),
            hash: *array_ref!(verified_bytes, 8, ::DIGEST_SIZE),
        })
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

    // Very similar to the simple decoder function, but for a post-order tree.
    fn validate_post_order_encoding(encoded: &::evil::EvilBytes, hash: &::Digest) {
        let header_start = encoded.len() - ::HEADER_SIZE;
        let header_encoded = encoded.slice(header_start, encoded.len());
        let header = Subtree::from_header_bytes(&header_encoded, hash).expect("bad header");
        let encoded_rest = encoded.slice(0, header_start);
        assert_eq!(
            header.encoded_len(),
            encoded_rest.len() as u64,
            "encoded len doesn't make sense"
        );
        validate_post_order_encoding_inner(&encoded_rest, &header);
    }

    fn validate_post_order_encoding_inner(encoded: &::evil::EvilBytes, subtree: &Subtree) {
        if encoded.len() <= ::CHUNK_SIZE {
            encoded.verify(encoded.len(), &subtree.hash).expect(
                "bad chunk",
            );
            return;
        }
        let node_start = encoded.len() - ::NODE_SIZE;
        let node_encoded = encoded.slice(node_start, encoded.len());
        let (left_subtree, right_subtree) = subtree.children(&node_encoded).expect("bad node");
        let left_encoded = encoded.slice(0, left_subtree.encoded_len() as usize);
        validate_post_order_encoding_inner(&left_encoded, &left_subtree);
        let right_encoded = encoded.slice(left_encoded.len(), node_start);
        validate_post_order_encoding_inner(&right_encoded, &right_subtree);
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
            validate_post_order_encoding(&::evil::EvilBytes::wrap(&encoded), &hash);

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
