//! [Repo](https://github.com/oconnor663/bao) —
//! [Crate](https://crates.io/crates/bao) —
//! [Spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//!
//! This crate implements the Bao hash function and encoding format. The `bao`
//! [command line utility](https://crates.io/crates/bao_bin) is built on top of
//! it. For more about how Bao works and what the encoding format is doing, see
//! the [project README](https://github.com/oconnor663/bao) and the [full
//! specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md).
//!
//! **Caution!** Not yet suitable for production use. The output of Bao isn't
//! stable. There might be more changes before 1.0.

#![forbid(unsafe_code)]

pub mod decode;
pub mod encode;

pub use blake3::Hash;

use std::mem;

/// The size of a `Hash`, 32 bytes.
pub const HASH_SIZE: usize = 32;
pub(crate) const PARENT_SIZE: usize = 2 * HASH_SIZE;
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) const CHUNK_SIZE: usize = blake3::CHUNK_LEN;
pub(crate) const MAX_DEPTH: usize = blake3::MAX_DEPTH;

/// An array of `HASH_SIZE` bytes. This will be a wrapper type in a future version.
pub(crate) type ParentNode = [u8; 2 * HASH_SIZE];

pub(crate) fn encode_len(len: u64) -> [u8; HEADER_SIZE] {
    debug_assert_eq!(mem::size_of_val(&len), HEADER_SIZE);
    len.to_le_bytes()
}

pub(crate) fn decode_len(bytes: &[u8; HEADER_SIZE]) -> u64 {
    u64::from_le_bytes(*bytes)
}

// The root node is hashed differently from interior nodes. It gets suffixed
// with the length of the entire input, and we set the Blake2 final node flag.
// That means that no root hash can ever collide with an interior hash, or with
// the root of a different size tree.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Finalization {
    NotRoot,
    Root,
}

impl Finalization {
    fn is_root(self) -> bool {
        match self {
            Self::NotRoot => false,
            Self::Root => true,
        }
    }
}

#[doc(hidden)]
pub mod benchmarks {
    pub const CHUNK_SIZE: usize = super::CHUNK_SIZE;
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    // Interesting input lengths to run tests on.
    pub const TEST_CASES: &[usize] = &[
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
        8 * CHUNK_SIZE - 1,
        8 * CHUNK_SIZE,
        8 * CHUNK_SIZE + 1,
        16 * CHUNK_SIZE - 1,
        16 * CHUNK_SIZE,
        16 * CHUNK_SIZE + 1,
    ];
}
