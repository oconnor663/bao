#[macro_use]
extern crate arrayref;
extern crate blake2_c;
extern crate byteorder;
extern crate ring;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

use ring::constant_time;

mod unverified;
pub mod simple;
pub mod encoder;
pub mod decoder;
pub mod io;

pub type Digest = [u8; DIGEST_SIZE];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    HashMismatch,
    ShortInput,
    Overflow,
}

pub type Result<T> = std::result::Result<T, Error>;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;
pub const NODE_SIZE: usize = 2 * DIGEST_SIZE;
pub const HEADER_SIZE: usize = 8 + DIGEST_SIZE;

// Currently we use blake2b-256, though this will get parametrized.
pub fn hash(input: &[u8]) -> Digest {
    let digest = blake2_c::blake2b_256(input);
    let mut array = [0; DIGEST_SIZE];
    array[..].copy_from_slice(&digest.bytes);
    array
}

fn verify(input: &[u8], digest: &Digest) -> Result<()> {
    let computed = hash(input);
    constant_time::verify_slices_are_equal(&digest[..], &computed[..])
        .map_err(|_| Error::HashMismatch)
}

// Interesting input lengths to run tests on.
#[cfg(test)]
const TEST_CASES: &[usize] = &[
    0,
    1,
    10,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE - 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 1,
    3 * CHUNK_SIZE - 1,
    3 * CHUNK_SIZE,
    3 * CHUNK_SIZE + 1,
    4 * CHUNK_SIZE - 1,
    4 * CHUNK_SIZE,
    4 * CHUNK_SIZE + 1,
    16 * CHUNK_SIZE - 1,
    16 * CHUNK_SIZE,
    16 * CHUNK_SIZE + 1,
];

#[cfg(test)]
mod test {
    use ::*;

    #[test]
    fn test_hash_works_at_all() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            let mut digest = hash(input);
            verify(input, &digest).unwrap();
            digest[0] ^= 1;
            verify(input, &digest).unwrap_err();
        }
    }
}
