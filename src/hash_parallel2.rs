extern crate rayon;

use blake2_c::blake2b;
use byteorder::{ByteOrder, LittleEndian};

pub fn hash(input: &[u8]) -> ::Digest {
    let mut suffix = [0; 8];
    LittleEndian::write_u64(&mut suffix, input.len() as u64);
    hash_recurse(input, &suffix)
}

pub fn hash_recurse(input: &[u8], suffix: &[u8]) -> ::Digest {
    let mut state = blake2b::State::new(::DIGEST_SIZE);
    if input.len() <= ::CHUNK_SIZE {
        state.update(input);
    } else {
        let left_len = ::simple::left_subtree_len(input.len() as u64) as usize;
        let (left, right) = rayon::join(
            || hash_recurse(&input[..left_len], &[]),
            || hash_recurse(&input[left_len..], &[]),
        );
        state.update(&left);
        state.update(&right);
    }
    if !suffix.is_empty() {
        state.update(suffix);
        state.set_last_node(true);
    }
    ::finalize_node(&mut state)
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
