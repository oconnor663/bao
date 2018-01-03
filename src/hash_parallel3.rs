use blake2_c::blake2b;
use std::cmp;

const BUFSIZE: usize = ::CHUNK_SIZE * 256;

pub fn hash(input: &[u8]) -> ::Digest {
    let mut state = State::new();
    state.update(input);
    state.finalize()
}

pub struct State {
    buf: Vec<u8>,
    count: u64,
    nodes: Vec<::Digest>,
}

impl State {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            count: 0,
            nodes: Vec::new(),
        }
    }

    fn push_node(&mut self, new_node: ::Digest) {
        self.nodes.push(new_node);
        // Same trick from hash.rs.
        while self.nodes.len() > (self.count / BUFSIZE as u64).count_ones() as usize {
            let right = self.nodes.pop().unwrap();
            let left = self.nodes.pop().unwrap();
            self.nodes.push(::hash_two(&left, &right));
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        // If there's already input in our buffer, we need to try to fill it.
        if self.buf.len() > 0 {
            self.count += fill_buf(&mut self.buf, &mut input, BUFSIZE) as u64;
            if !input.is_empty() {
                let hash = ::hash_parallel2::hash_recurse(&self.buf, &[]);
                self.buf.clear();
                self.push_node(hash);
            } else {
                return;
            }
        }
        // Now as long as there are BUFSIZE chunks in the input (plus at least
        // one more byte to be sure the chunk doesn't need finalization), hash
        // them directly, to avoid copying overhead.
        while input.len() > BUFSIZE {
            self.count += BUFSIZE as u64;
            let hash = ::hash_parallel2::hash_recurse(&input[..BUFSIZE], &[]);
            input = &input[BUFSIZE..];
            self.push_node(hash);
        }
        // Finally, add any remaining input to the buffer.
        self.count += fill_buf(&mut self.buf, &mut input, BUFSIZE) as u64;
    }

    pub fn finalize(&mut self) -> ::Digest {
        if self.count <= BUFSIZE as u64 {
            return ::hash_parallel2::hash(&self.buf);
        }
        let hash = ::hash_parallel2::hash_recurse(&self.buf, &[]);
        self.nodes.push(hash);
        loop {
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
    }
}

fn fill_buf(buf: &mut Vec<u8>, input: &mut &[u8], target: usize) -> usize {
    let want = target - buf.len();
    let take = cmp::min(want, input.len());
    buf.extend_from_slice(&input[..take]);
    *input = &input[take..];
    take
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compare_serial() {
        let mut cases = ::TEST_CASES.to_vec();
        cases.push(BUFSIZE - 1);
        cases.push(BUFSIZE);
        cases.push(BUFSIZE + 1);
        cases.push(10 * BUFSIZE);
        for case in cases {
            println!("case {}", case);
            let input = vec![0x42; case];
            let hash_serial = ::hash::hash(&input);
            let hash_parallel = hash(&input);
            assert_eq!(hash_serial, hash_parallel, "hashes don't match");
        }
    }
}
