#[derive(Debug, Copy, Clone)]
struct Subtree {
    hash: ::Digest,
    len: u64,
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
        self.stack.push(Subtree {
            hash: ::hash(input),
            len: ::CHUNK_SIZE as u64,
        });
        loop {
            if self.stack.len() < 2 {
                break;
            }
            let subtree1 = self.stack[self.stack.len() - 1];
            let subtree2 = self.stack[self.stack.len() - 2];
            if subtree1.len != subtree2.len {
                break;
            }
            let mut new_node = [0; 2 * ::CHUNK_SIZE];
            new_node[..::CHUNK_SIZE].copy_from_slice(&subtree1.hash);
            new_node[::CHUNK_SIZE..].copy_from_slice(&subtree2.hash);
            self.out_buf.extend_from_slice(&new_node);
            self.stack.pop();
            self.stack.pop();
            self.stack.push(Subtree {
                hash: ::hash(&new_node),
                len: subtree1.len.checked_mul(2).expect("len overflowed"),
            });
        }
        &self.out_buf
    }

    pub fn finalize(&mut self, input: &[u8]) -> &[u8] {
        if self.finalized {
            panic!("finalize called on a finalized encoder");
        }
        self.finalized = true;
        self.out_buf.clear();
        self.out_buf.extend_from_slice(input);
        unimplemented!()
    }
}
