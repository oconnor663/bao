//! [Repo](https://github.com/oconnor663/bao) —
//! [Crate](https://crates.io/crates/bao) —
//! [Spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//!
//! Bao is an implementation of BLAKE3 verified streaming. For more about how
//! verified streaming works and what the Bao format looks like, see the
//! [project README](https://github.com/oconnor663/bao) and the [full
//! specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md).
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::prelude::*;
//!
//! // Encode some example bytes.
//! let input = b"some input";
//! let (encoded, hash) = abao::encode::encode(input);
//!
//! // Decode them with one of the all-at-once functions.
//! let decoded_at_once = abao::decode::decode(&encoded, &hash)?;
//!
//! // Also decode them incrementally.
//! let mut decoded_incrementally = Vec::new();
//! let mut decoder = abao::decode::Decoder::new(&*encoded, &hash);
//! decoder.read_to_end(&mut decoded_incrementally)?;
//!
//! // Assert that we got the same results both times.
//! assert_eq!(decoded_at_once, decoded_incrementally);
//!
//! // Flipping a bit in encoding will cause a decoding error.
//! let mut bad_encoded = encoded.clone();
//! let last_index = bad_encoded.len() - 1;
//! bad_encoded[last_index] ^= 1;
//! let err = abao::decode::decode(&bad_encoded, &hash).unwrap_err();
//! assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod decode;
pub mod encode;

pub use blake3::Hash;

use std::mem;

/// The size of a `Hash`, 32 bytes.
pub const HASH_SIZE: usize = 32;
/// log2(GROUP_CHUNKS)
pub(crate) const GROUP_LOG: usize = 6;
/// The number of chunks in a chunk groups. Must be a power of 2.
pub(crate) const GROUP_CHUNKS: usize = 1 << GROUP_LOG;
/// The size of a chunk group in bytes.
pub(crate) const GROUP_SIZE: usize = GROUP_CHUNKS * CHUNK_SIZE;
pub(crate) const PARENT_SIZE: usize = 2 * HASH_SIZE;
pub(crate) const HEADER_SIZE: usize = 8;
const CHUNK_SIZE: usize = 1024;
pub(crate) const MAX_DEPTH: usize = 54 - GROUP_LOG; // 2^54 * CHUNK_SIZE = 2^64

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
        GROUP_SIZE - 1,
        GROUP_SIZE,
        GROUP_SIZE + 1,
        2 * GROUP_SIZE - 1,
        2 * GROUP_SIZE,
        2 * GROUP_SIZE + 1,
        3 * GROUP_SIZE - 1,
        3 * GROUP_SIZE,
        3 * GROUP_SIZE + 1,
        4 * GROUP_SIZE - 1,
        4 * GROUP_SIZE,
        4 * GROUP_SIZE + 1,
        8 * GROUP_SIZE - 1,
        8 * GROUP_SIZE,
        8 * GROUP_SIZE + 1,
        16 * GROUP_SIZE - 1,
        16 * GROUP_SIZE,
        16 * GROUP_SIZE + 1,
    ];
}

/// A state machine for hashing a chunk group, with the same API as
/// `blake3::guts::ChunkState`. This really should not exist but instead
/// call into blake3, but the required methods are not public.
///
/// See https://github.com/BLAKE3-team/BLAKE3/tree/more_guts
#[derive(Clone, Debug)]
pub(crate) struct ChunkGroupState {
    current_chunk: u64,
    leaf_hashes: [Hash; GROUP_CHUNKS - 1],
    current: blake3::guts::ChunkState,
}

impl ChunkGroupState {
    pub fn new(group_counter: u64) -> Self {
        let chunk_counter = group_counter << GROUP_LOG;
        Self {
            current_chunk: chunk_counter,
            current: blake3::guts::ChunkState::new(chunk_counter),
            leaf_hashes: [Hash::from([0; HASH_SIZE]); GROUP_CHUNKS - 1],
        }
    }

    pub fn len(&self) -> usize {
        self.hashes() * CHUNK_SIZE + self.current.len()
    }

    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        let mut input = input;
        debug_assert!(self.len() + input.len() <= GROUP_SIZE);
        while self.current.len() + input.len() > CHUNK_SIZE {
            let remaining = CHUNK_SIZE - self.current.len();
            self.current.update(&input[..remaining]);
            // we know this is not the root because there is more coming
            self.leaf_hashes[self.hashes()] = self.current.finalize(false);
            self.current_chunk += 1;
            self.current = blake3::guts::ChunkState::new(self.current_chunk);
            input = &input[remaining..];
        }
        self.current.update(input);
        self
    }

    pub fn finalize(&self, is_root: bool) -> Hash {
        if self.hashes() == 0 {
            // we have just current, so pass through is_root
            self.current.finalize(is_root)
        } else {
            // todo: this works only for GROUP_CHUNKS == 2
            let mut leaf_hashes = [Hash::from([0; HASH_SIZE]); GROUP_CHUNKS];
            let n = self.hashes();
            leaf_hashes[..n].copy_from_slice(&self.leaf_hashes[..self.hashes()]);
            leaf_hashes[n] = self.current.finalize(false);
            combine_chunk_hashes(&leaf_hashes[..n + 1], is_root)
        }
    }

    /// number of leaf hashes we have already computed
    fn hashes(&self) -> usize {
        (self.current_chunk & ((GROUP_CHUNKS as u64) - 1)) as usize
    }
}

fn combine_chunk_hashes(chunks: &[Hash], is_root: bool) -> Hash {
    if chunks.len() == 1 {
        chunks[0]
    } else {
        let mid = chunks.len().next_power_of_two() / 2;
        let left = combine_chunk_hashes(&chunks[..mid], false);
        let right = combine_chunk_hashes(&chunks[mid..], false);
        blake3::guts::parent_cv(&left, &right, is_root)
    }
}
