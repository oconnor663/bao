#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate ring;

use ring::{constant_time, digest};
use std::mem::size_of;

pub mod simple;
pub mod codec;
mod evil;

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

// The left length is the largest power of 2 count of full chunks that's less
// than the input length, and the right length is the rest. So if the input is
// exactly 4 chunks long, for example, then both subtrees get 2 chunks. But if
// the input is 4 chunks plus 1 byte, then the left side is 4 chunks and the
// right side is 1 byte.
//
// Using this "left subtree is always full" strategy makes it easier to build a
// tree incrementally, as a Writer interface might, because appending only
// touches nodes along the right edge. It also makes it very easy to compute
// the encoded size of a left subtree, for seek offsets.
fn left_len(input_len: u64) -> u64 {
    debug_assert!(input_len > CHUNK_SIZE as u64);
    // Reserve at least one byte for the right side.
    let full_chunks = (input_len - 1) / CHUNK_SIZE as u64;
    largest_power_of_two(full_chunks) * CHUNK_SIZE as u64
}

fn largest_power_of_two(n: u64) -> u64 {
    // n=0 is nonsensical, so we set the first bit of n. This doesn't change
    // the result for any other input, but it ensures that leading_zeros will
    // be at most 63, so the subtraction doesn't underflow.
    let masked_n = n | 1;
    let max_shift = 8 * size_of::<u64>() - 1;
    1 << (max_shift - masked_n.leading_zeros() as usize)
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

    #[test]
    fn test_power_of_two() {
        let input_output = &[
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 4),
            // Make sure to test the largest possible value.
            (u64::max_value(), u64::max_value() ^ (u64::max_value() >> 1)),
        ];
        for &(input, output) in input_output {
            assert_eq!(
                output,
                largest_power_of_two(input),
                "wrong output for n={}",
                input
            );
        }
    }

    #[test]
    fn test_left_len() {
        let s = CHUNK_SIZE as u64;
        let input_output = &[(s + 1, s), (2 * s - 1, s), (2 * s, s), (2 * s + 1, 2 * s)];
        for &(input, output) in input_output {
            println!("testing {} and {}", input, output);
            assert_eq!(left_len(input), output);
        }
    }
}
