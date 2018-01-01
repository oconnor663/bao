extern crate rayon;

use blake2_c::blake2b;
use self::rayon::prelude::*;
use std::mem;

const PARALLELISM: usize = 8;

pub fn hash(input: &[u8]) -> ::Digest {
    let mut state = State::new();
    state.update(input);
    state.finalize()
}

#[derive(Debug, Clone)]
pub struct State {
    chunks_buffer: Vec<u8>,
    count: u64,
    nodes: Vec<::Digest>,
}

impl State {
    pub fn new() -> Self {
        Self {
            chunks_buffer: Vec::new(),
            count: 0,
            nodes: Vec::new(),
        }
    }

    fn push_node(&mut self, node_hash: ::Digest, len: u64) {
        // As with the serial hash, we use the count one's trick. This trick
        // also works when inserting nodes larger than a single chunk, as long
        // as they're always the same (power of two chunks) size.
        debug_assert_eq!(0, self.count % len, "inconsistent chunk lengths");
        self.count += len;
        self.nodes.push(node_hash);
        while self.nodes.len() > (self.count / ::CHUNK_SIZE as u64).count_ones() as usize {
            let right = self.nodes.pop().unwrap();
            let left = self.nodes.pop().unwrap();
            let mut parent_digest = blake2b::State::new(::DIGEST_SIZE);
            parent_digest.update(&left);
            parent_digest.update(&right);
            let parent_hash = ::finalize_node(&mut parent_digest);
            self.nodes.push(parent_hash);
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        let full_len = ::CHUNK_SIZE * PARALLELISM;
        while !input.is_empty() {
            if self.chunks_buffer.len() == full_len {
                let hashes: Vec<::Digest> = self.chunks_buffer
                    .par_chunks(::CHUNK_SIZE)
                    .map(|window| ::hash_node(window, &[]))
                    .collect();
                for hash in hashes {
                    self.push_node(hash, ::CHUNK_SIZE as u64);
                }
                self.chunks_buffer.clear();
            }
            let need = full_len - self.chunks_buffer.len();
            let take = need.min(input.len());
            self.chunks_buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    /// It's a logic error to call finalize more than once on the same instance.
    pub fn finalize(&mut self) -> ::Digest {
        // Take the remaining bytes.
        let chunks_buffer = mem::replace(&mut self.chunks_buffer, Vec::new());
        // Clean up all the full nodes before the final node.
        let mut input = &chunks_buffer[..];
        while input.len() > ::CHUNK_SIZE {
            let node_hash = ::hash_node(&input[..::CHUNK_SIZE], &[]);
            self.push_node(node_hash, ::CHUNK_SIZE as u64);
            input = &input[::CHUNK_SIZE..];
        }
        // Hash the final block (possibly empty, if the whole input is empty).
        // If this is the only block, we need to suffix it and set the final
        // node flag. Note that if we instead used a prefix, or any of the
        // other Blake2 parameters, we wouldn't be able to store only the
        // Blake2 state as we're doing here -- we would've had to buffer the
        // whole chunk.
        if self.count == 0 {
            return ::hash_root(input, input.len() as u64);
        }
        // We don't use the helper function here, because we might need to
        // finalize the root.
        self.nodes.push(::hash_node(input, &[]));
        self.count += input.len() as u64;
        // Like the loop above, combine nodes into parents along the right
        // edge. But this time do it regardless of their length.
        while self.nodes.len() >= 2 {
            let right = self.nodes.pop().unwrap();
            let left = self.nodes.pop().unwrap();
            let mut parent_digest = blake2b::State::new(::DIGEST_SIZE);
            parent_digest.update(&left);
            parent_digest.update(&right);
            if self.nodes.is_empty() {
                return ::finalize_root(&mut parent_digest, self.count);
            }
            // We don't use the helper function here, because we might need to
            // finalize the root.
            self.nodes.push(::finalize_node(&mut parent_digest));
        }
        unreachable!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compare_serial() {
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_serial = ::hash::hash(&input);
            let hash_parallel = hash(&input);
            assert_eq!(hash_serial, hash_parallel, "hashes don't match");
        }
    }
}
