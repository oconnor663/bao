use byteorder::{ByteOrder, BigEndian};

// TODO: Factor this type up and combine it with Region.
#[derive(Debug, Copy, Clone)]
struct Subtree {
    hash: ::Digest,
    len: u64,
}

impl Subtree {
    fn join(&self, rhs: &Subtree) -> Subtree {
        let mut node = [0; 2 * ::CHUNK_SIZE];
        node[..::CHUNK_SIZE].copy_from_slice(&self.hash);
        node[::CHUNK_SIZE..].copy_from_slice(&rhs.hash);
        Subtree {
            len: self.len.checked_add(rhs.len).expect("len overflow"),
            hash: ::hash(&node),
        }
    }

    fn to_header(&self) -> [u8; ::HEADER_SIZE] {
        let mut ret = [0; ::HEADER_SIZE];
        BigEndian::write_u64(&mut ret[..8], self.len);
        ret[8..].copy_from_slice(&self.hash);
        ret
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

    pub fn finalize(&mut self, input: &[u8]) -> &[u8] {
        if self.finalized {
            panic!("finalize called on a finalized encoder");
        }
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
        self.out_buf.extend_from_slice(&root.to_header());
        &self.out_buf
    }
}
