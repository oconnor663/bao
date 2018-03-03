#[macro_use]
extern crate arrayref;
extern crate arrayvec;
extern crate blake2_c;
extern crate byteorder;
extern crate crossbeam;
#[macro_use]
extern crate lazy_static;
extern crate num_cpus;
extern crate rayon;
extern crate ring;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

use byteorder::{ByteOrder, LittleEndian};
use ring::constant_time;

mod unverified;
pub mod decoder;
pub mod encoder;
pub mod hash;
pub mod io;
pub mod simple;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    HashMismatch,
    ShortInput,
    Overflow,
}

pub type Result<T> = std::result::Result<T, Error>;

fn suffix_root(state: &mut blake2_c::blake2b::State, len: u64) {
    let mut len_bytes = [0; 8];
    LittleEndian::write_u64(&mut len_bytes, len);
    state.update(&len_bytes);
    state.set_last_node(true);
}

fn finalize_node(state: &mut blake2_c::blake2b::State) -> hash::Hash {
    let blake_digest = state.finalize().bytes;
    *array_ref!(blake_digest, 0, hash::DIGEST_SIZE)
}

fn finalize_root(state: &mut blake2_c::blake2b::State, len: u64) -> hash::Hash {
    suffix_root(state, len);
    finalize_node(state)
}

pub fn hash_root(node: &[u8], len: u64) -> hash::Hash {
    let mut state = blake2_c::blake2b::State::new(hash::DIGEST_SIZE);
    state.update(node);
    finalize_root(&mut state, len)
}

// Currently we use blake2b-256, though this will get parametrized.
pub fn hash(input: &[u8]) -> hash::Hash {
    let hash = blake2_c::blake2b_256(input);
    let mut array = [0; hash::DIGEST_SIZE];
    array[..].copy_from_slice(&hash.bytes);
    array
}

pub fn hash_two(input1: &[u8], input2: &[u8]) -> hash::Hash {
    let mut state = blake2_c::blake2b::State::new(hash::DIGEST_SIZE);
    state.update(input1);
    state.update(input2);
    let hash = state.finalize();
    let mut array = [0; hash::DIGEST_SIZE];
    array[..].copy_from_slice(&hash.bytes);
    array
}

fn hash_node(node: &[u8], suffix: &[u8]) -> hash::Hash {
    let mut state = blake2_c::blake2b::State::new(hash::DIGEST_SIZE);
    state.update(node);
    if !suffix.is_empty() {
        state.update(suffix);
        state.set_last_node(true);
    }
    let finalized = state.finalize();
    let mut hash = [0; hash::DIGEST_SIZE];
    hash.copy_from_slice(&finalized.bytes);
    hash
}

fn verify_node<'a>(
    input: &'a [u8],
    len: usize,
    hash: &hash::Hash,
    suffix: &[u8],
) -> Result<&'a [u8]> {
    if input.len() < len {
        return Err(::Error::ShortInput);
    }
    let bytes = &input[..len];
    let computed = hash_node(bytes, suffix);
    if constant_time::verify_slices_are_equal(hash, &computed).is_ok() {
        Ok(bytes)
    } else {
        Err(Error::HashMismatch)
    }
}

fn verify(input: &[u8], hash_: &hash::Hash) -> Result<()> {
    let computed = hash(input);
    constant_time::verify_slices_are_equal(&hash_[..], &computed[..])
        .map_err(|_| Error::HashMismatch)
}

#[cfg(test)]
mod test {
    use ::*;

    #[test]
    fn test_hash_works_at_all() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            let mut hash = hash(input);
            verify(input, &hash).unwrap();
            hash[0] ^= 1;
            verify(input, &hash).unwrap_err();
        }
    }

    #[test]
    fn test_hash_two() {
        assert_eq!(hash(b"foobar"), hash_two(b"foo", b"bar"));
    }
}
