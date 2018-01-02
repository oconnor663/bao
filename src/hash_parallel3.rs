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

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf.len() == BUFSIZE {
                let hash = ::hash_parallel2::hash_recurse(&self.buf, &[]);
                self.nodes.push(hash);
                self.buf.clear();
                // Same trick from hash.rs.
                while self.nodes.len() > (self.count / BUFSIZE as u64).count_ones() as usize {
                    let right = self.nodes.pop().unwrap();
                    let left = self.nodes.pop().unwrap();
                    self.nodes.push(::hash_two(&left, &right));
                }
            }
            let want = BUFSIZE - self.buf.len();
            let take = cmp::min(want, input.len());
            self.buf.extend_from_slice(&input[..take]);
            input = &input[take..];
            self.count += take as u64;
        }
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
