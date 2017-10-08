#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate ring;

use ring::{constant_time, digest};

#[macro_use]
mod unverified;
mod node;
pub mod simple;
pub mod encoder;
pub mod decoder;
pub mod io;

pub type Digest = [u8; DIGEST_SIZE];

#[derive(Clone, Copy, Debug)]
pub enum Error {
    HashMismatch,
    ShortInput,
    Overflow,
}

pub type Result<T> = std::result::Result<T, Error>;

const CHUNK_SIZE: usize = 4096;
const DIGEST_SIZE: usize = 32;
const NODE_SIZE: usize = 2 * DIGEST_SIZE;
const HEADER_SIZE: usize = 8 + DIGEST_SIZE;

fn hash(input: &[u8]) -> Digest {
    // First 32 bytes of SHA512. (The same as NaCl's crypto_hash.)
    let digest = digest::digest(&digest::SHA512, input);
    let mut ret = [0; DIGEST_SIZE];
    ret.copy_from_slice(&digest.as_ref()[..DIGEST_SIZE]);
    ret
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
    fn test_hash() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            let mut digest = hash(input);
            verify(input, &digest).unwrap();
            digest[0] ^= 1;
            verify(input, &digest).unwrap_err();
        }
    }
}
