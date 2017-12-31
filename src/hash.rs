use arrayvec::ArrayVec;
use blake2_c::blake2b;

pub fn hash(input: &[u8]) -> ::Digest {
    let mut state = State::new();
    state.update(input);
    state.finalize()
}

#[derive(Debug, Clone)]
pub struct State {
    chunk_state: blake2b::State,
    count: u64,
    nodes: ArrayVec<[::Digest; 64]>,
}

impl State {
    pub fn new() -> Self {
        Self {
            chunk_state: blake2b::State::new(::DIGEST_SIZE),
            count: 0,
            nodes: ArrayVec::new(),
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If we've completed a chunk, add it to the nodes list. We only do
            // this when we know there's more input to come, so we know we
            // don't need the final node flag or the root suffix.
            if self.count > 0 && self.count % ::CHUNK_SIZE as u64 == 0 {
                let chunk_hash = ::finalize_node(&mut self.chunk_state);
                self.nodes.push(chunk_hash);
                self.chunk_state = blake2b::State::new(::DIGEST_SIZE);
                // When two nodes in the stack have the same size (only ever
                // the last two), they need to be hashed together into a parent
                // node. A cute hack to avoid needing to store the size:
                // Combining nodes is metaphorically similar to adding with a
                // carry bit. The length of the stack should be the same as the
                // number of 1's in the binary representation of the current
                // chunk count.
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
            // Take as many bytes as we can, to fill the next chunk.
            let take = input.len().min(::CHUNK_SIZE);
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
            self.count += take as u64;
        }
    }

    /// It's a logic error to call finalize more than once on the same instance.
    pub fn finalize(&mut self) -> ::Digest {
        // Hash the final block (possibly empty, if the whole input is empty).
        // If this is the only block, we need to suffix it and set the final
        // node flag. Note that if we instead used a prefix, or any of the
        // other Blake2 parameters, we wouldn't be able to store only the
        // Blake2 state as we're doing here -- we would've had to buffer the
        // whole chunk.
        if self.count <= ::CHUNK_SIZE as u64 {
            return ::finalize_root(&mut self.chunk_state, self.count);
        }
        self.nodes.push(::finalize_node(&mut self.chunk_state));
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
            self.nodes.push(::finalize_node(&mut parent_digest));
        }
        self.nodes[0]
    }
}

#[cfg(test)]
mod test {
    use hex::ToHex;

    use super::*;

    #[test]
    fn test_compare_python() {
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_hex = hash(&input).to_hex();

            // Have the Python implementation hash the same input, and make
            // sure the result is identical.
            let python_hash = cmd!("python3", "./python/bao.py", "hash")
                .input(input.clone())
                .read()
                .expect("is python3 installed?");
            assert_eq!(hash_hex, python_hash, "encoding mismatch");
        }
    }
}
