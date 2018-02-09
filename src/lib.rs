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

pub mod hash;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;

pub type Hash = [u8; DIGEST_SIZE];

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
