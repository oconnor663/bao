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
//! let (encoded, hash) = bao::encode(input);
//!
//! // Decode them with one of the all-at-once functions.
//! let decoded_at_once = bao::decode(&encoded, &hash)?;
//!
//! // Also decode them incrementally.
//! let mut decoded_incrementally = Vec::new();
//! let mut decoder = bao::Decoder::new(&*encoded, &hash);
//! decoder.read_to_end(&mut decoded_incrementally)?;
//!
//! // Assert that we got the same results both times.
//! assert_eq!(decoded_at_once, decoded_incrementally);
//!
//! // Flipping a bit in encoding will cause a decoding error.
//! let mut bad_encoded = encoded.clone();
//! let last_index = bad_encoded.len() - 1;
//! bad_encoded[last_index] ^= 1;
//! let err = bao::decode(&bad_encoded, &hash).unwrap_err();
//! assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub use blake3::{Hash, Hasher};
use std::cmp;
use std::io;
use std::io::prelude::*;
use std::mem;

mod decode;
mod encode;

/// The size of a `Hash`, 32 bytes.
pub const HASH_SIZE: usize = 32;
pub(crate) const PARENT_SIZE: usize = 2 * HASH_SIZE;
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) const CHUNK_SIZE: usize = 1024;

/// An array of `HASH_SIZE` bytes. This will be a wrapper type in a future version.
pub(crate) type ParentNode = [u8; 2 * HASH_SIZE];

pub(crate) fn encode_len(len: u64) -> [u8; HEADER_SIZE] {
    debug_assert_eq!(mem::size_of_val(&len), HEADER_SIZE);
    len.to_le_bytes()
}

pub(crate) fn decode_len(bytes: &[u8; HEADER_SIZE]) -> u64 {
    u64::from_le_bytes(*bytes)
}

/// Encode an entire slice into a bytes vector in the default combined mode, using a default group
/// size of 16 KiB. This is a convenience wrapper around [`Config`] and [`Encoder`].
pub fn encode(input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
    Config::default().encode(input)
}

/// Decode an entire slice in the default combined mode, with a default group size of 16 KiB, into
/// a bytes vector. This is a convenience wrapper around [`Config`] and [`Encoder`].
pub fn decode(encoded: impl AsRef<[u8]>, hash: &Hash) -> io::Result<Vec<u8>> {
    Config::default().decode(encoded, hash)
}

#[derive(Copy, Clone, Debug)]
pub struct Config {
    group_size: usize,
}

impl Config {
    pub fn new(group_size: usize) -> Self {
        assert!(group_size >= CHUNK_SIZE, "must be at least one chunk",);
        assert_eq!(group_size.count_ones(), 1, "must be a power of two");
        Self { group_size }
    }

    pub fn encode(&self, input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
        let bytes = input.as_ref();
        let mut vec = Vec::with_capacity(self.encoded_size(bytes.len() as u64) as usize);
        let mut encoder = self.new_encoder(io::Cursor::new(&mut vec));
        encoder.write_all(bytes).unwrap();
        let hash = encoder.finalize().unwrap();
        (vec, hash)
    }

    pub fn encode_outboard(&self, input: impl AsRef<[u8]>) -> (Vec<u8>, Hash) {
        let bytes = input.as_ref();
        let mut vec = Vec::with_capacity(self.outboard_size(bytes.len() as u64) as usize);
        let mut encoder = self.new_outboard_encoder(io::Cursor::new(&mut vec));
        encoder.write_all(bytes).unwrap();
        let hash = encoder.finalize().unwrap();
        (vec, hash)
    }

    /// Compute the size of a combined encoding, given the size of the input. Note that for input sizes
    /// close to `u64::MAX`, the result can overflow a `u64`, which will panic.
    pub fn encoded_size(&self, content_len: u64) -> u64 {
        content_len
            .checked_add(self.outboard_size(content_len))
            .expect("overflow")
    }

    /// Compute the size of an outboard encoding, given the size of the input.
    pub fn outboard_size(&self, content_len: u64) -> u64 {
        self.outboard_subtree_size(content_len) + HEADER_SIZE as u64
    }

    fn encoded_subtree_size(&self, content_len: u64) -> u64 {
        content_len + self.outboard_subtree_size(content_len)
    }

    fn outboard_subtree_size(&self, content_len: u64) -> u64 {
        // The number of parent nodes is always the number of groups minus one. To see why this is true,
        // start with a single groups and incrementally add groups to the tree. Each new groups always
        // brings one parent node along with it.
        let num_parents = self.count_groups(content_len) - 1;
        num_parents * PARENT_SIZE as u64
    }

    fn count_groups(&self, content_len: u64) -> u64 {
        // Two things to watch out for here: the 0-length input still counts as 1 group, and we'd
        // rather not to overflow when content_len is u64::MAX_VALUE.
        let full_groups: u64 = content_len / self.group_size as u64;
        let has_partial_group: bool = (content_len % self.group_size as u64) != 0;
        cmp::max(1, full_groups + has_partial_group as u64)
    }

    fn group_size_by_index(&self, group_index: u64, content_len: u64) -> usize {
        let group_start = group_index * self.group_size as u64;
        cmp::min(self.group_size, (content_len - group_start) as usize)
    }

    /// Decode an entire slice in the default combined mode into a bytes vector.
    /// This is a convenience wrapper around `Decoder`.
    pub fn decode(&self, encoded: impl AsRef<[u8]>, hash: &Hash) -> io::Result<Vec<u8>> {
        let bytes = encoded.as_ref();
        let Some(header) = bytes.first_chunk::<HEADER_SIZE>() else {
            return Err(DecodeError::Truncated.into());
        };
        let content_len = crate::decode_len(header);
        // Sanity check the length before making a potentially large allocation.
        if (bytes.len() as u64) < self.encoded_size(content_len) {
            return Err(DecodeError::Truncated.into());
        }
        // There's no way to avoid zeroing this vector without unsafe code, because
        // Decoder::initializer is the default (safe) zeroing implementation anyway.
        let mut vec = vec![0; content_len as usize];
        let mut reader = self.new_decoder(bytes, hash);
        reader.read_exact(&mut vec)?;
        // One more read to confirm EOF. This is redundant in most cases, but in
        // the empty encoding case read_exact won't do any reads at all, and the Ok
        // return from this call will be the only thing that verifies the hash.
        // Note that this will never hit the inner reader; we'll receive EOF from
        // the VerifyState.
        let n = reader.read(&mut [0])?;
        debug_assert_eq!(n, 0, "must be EOF");
        Ok(vec)
    }

    pub fn new_encoder<T: Read + Write + Seek>(&self, output: T) -> Encoder<T> {
        Encoder {
            inner: output,
            config: *self,
            group_state: Hasher::new(),
            tree_state: encode::State::new(),
            outboard: false,
            finalized: false,
        }
    }

    pub fn new_outboard_encoder<T: Read + Write + Seek>(&self, output: T) -> Encoder<T> {
        let mut encoder = self.new_encoder(output);
        encoder.outboard = true;
        encoder
    }

    pub fn new_decoder<T: Read>(&self, input: T, hash: &Hash) -> Decoder<T> {
        Decoder {
            shared: decode::DecoderShared::new(*self, input, None, hash),
        }
    }

    pub fn new_outboard_decoder<T: Read, O: Read>(
        &self,
        input: T,
        outboard: O,
        hash: &Hash,
    ) -> Decoder<T, O> {
        Decoder {
            shared: decode::DecoderShared::new(*self, input, Some(outboard), hash),
        }
    }

    /// Create a new `SliceExtractor` to read from a combined encoding. Note that `slice_start` and
    /// `slice_len` are with respect to the *content* of the encoding, that is, the *original*
    /// input bytes. This corresponds to `bao slice slice_start slice_len`.
    pub fn new_slice_extractor<T: Read + Seek>(
        &self,
        input: T,
        slice_start: u64,
        slice_len: u64,
    ) -> SliceExtractor<T> {
        SliceExtractor::new_inner(*self, input, None, slice_start, slice_len)
    }

    /// Create a new `SliceExtractor` to read from an unmodified input file and an outboard
    /// encoding of that same file (see `Encoder::new_outboard`). As with `SliceExtractor::new`,
    /// `slice_start` and `slice_len` are with respect to the *content* of the encoding, that is,
    /// the *original* input bytes. This corresponds to `bao slice slice_start slice_len
    /// --outboard`.
    pub fn new_outboard_slice_extractor<T: Read + Seek, O: Read + Seek>(
        &self,
        input: T,
        outboard: O,
        slice_start: u64,
        slice_len: u64,
    ) -> SliceExtractor<T, O> {
        SliceExtractor::new_inner(*self, input, Some(outboard), slice_start, slice_len)
    }

    pub fn new_slice_decoder<T: Read>(
        &self,
        inner: T,
        hash: &Hash,
        slice_start: u64,
        slice_len: u64,
    ) -> SliceDecoder<T> {
        SliceDecoder {
            shared: decode::DecoderShared::new(*self, inner, None, hash),
            slice_start,
            slice_remaining: slice_len,
            need_fake_read: slice_len == 0,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // The default group size is 16 KiB.
            group_size: 16 * CHUNK_SIZE,
        }
    }
}

/// An incremental encoder. Note that you must call `finalize` after you're
/// done writing.
///
/// `Encoder` supports both combined and outboard encoding, depending on which
/// constructor you use.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// let mut encoded_incrementally = Vec::new();
/// let encoded_cursor = std::io::Cursor::new(&mut encoded_incrementally);
/// let mut encoder = bao::Encoder::new(encoded_cursor);
/// encoder.write_all(b"some input")?;
/// encoder.finalize()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Encoder<T: Read + Write + Seek> {
    inner: T,
    config: Config,
    group_state: Hasher,
    tree_state: encode::State,
    outboard: bool,
    finalized: bool,
}

/// An incremental slice extractor, which reads encoded bytes and produces a slice.
///
/// `SliceExtractor` supports reading both the combined and outboard encoding, depending on which
/// constructor you use. Though to be clear, there's no such thing as an "outboard slice" per se.
/// Slices always include subtree hashes inline with the content, as a combined encoding does.
///
/// Note that slices always split the encoding at chunk boundaries. The BLAKE3 chunk size is 1024
/// bytes, so using `slice_start` and `slice_len` values that are an even multiple of 1024 avoids
/// wasting space.
///
/// Extracting a slice doesn't re-hash any of the bytes. As a result, it's fast compared to
/// decoding. You can quickly convert an outboard encoding to a combined encoding by "extracting" a
/// slice with a `slice_start` of zero and a `slice_len` equal to the original input length.
///
/// See the `decode` module for decoding slices.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = bao::encode(&input);
/// // These parameters are multiples of the chunk size, which avoids unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 16384;
/// let encoded_cursor = std::io::Cursor::new(&encoded);
/// let mut extractor = bao::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice)?;
///
/// // The slice includes some overhead to store the necessary subtree hashes.
/// assert_eq!(16776, slice.len());
/// # Ok(())
/// # }
/// ```
pub struct SliceExtractor<T: Read + Seek, O: Read + Seek = T> {
    input: T,
    outboard: Option<O>,
    slice_start: u64,
    slice_len: u64,
    slice_bytes_read: u64,
    parser: encode::ParseState,
    buf: Vec<u8>,
    buf_start: usize,
    buf_end: usize,
    seek_done: bool,
}

/// An incremental slice decoder. This reads and verifies the output of the
/// [`SliceExtractor`](../encode/struct.SliceExtractor.html).
///
/// Note that there is no such thing as an "outboard slice". All slices include
/// the content bytes and tree nodes intermixed, as in the combined encoding
/// mode.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Start by encoding some input.
/// let input = vec![0; 1_000_000];
/// let (encoded, hash) = bao::encode(&input);
///
/// // Slice the encoding. These parameters are multiples of the chunk size, which avoids
/// // unnecessary overhead.
/// let slice_start = 65536;
/// let slice_len = 8192;
/// let encoded_cursor = std::io::Cursor::new(&encoded);
/// let mut extractor = bao::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
/// let mut slice = Vec::new();
/// extractor.read_to_end(&mut slice)?;
///
/// // Decode the slice. The result should be the same as the part of the input that the slice
/// // represents. Note that we're using the same hash that encoding produced, which is
/// // independent of the slice parameters. That's the whole point; if we just wanted to re-encode
/// // a portion of the input and wind up with a different hash, we wouldn't need slicing.
/// let mut decoded = Vec::new();
/// let mut decoder = bao::SliceDecoder::new(&*slice, &hash, slice_start, slice_len);
/// decoder.read_to_end(&mut decoded)?;
/// assert_eq!(&input[slice_start as usize..][..slice_len as usize], &*decoded);
///
/// // Like regular decoding, slice decoding will fail if the hash doesn't match.
/// let mut bad_slice = slice.clone();
/// let last_index = bad_slice.len() - 1;
/// bad_slice[last_index] ^= 1;
/// let mut decoder = bao::SliceDecoder::new(&*bad_slice, &hash, slice_start, slice_len);
/// let err = decoder.read_to_end(&mut Vec::new()).unwrap_err();
/// assert_eq!(std::io::ErrorKind::InvalidData, err.kind());
/// # Ok(())
/// # }
/// ```
pub struct SliceDecoder<T: Read> {
    shared: decode::DecoderShared<T, T>,
    slice_start: u64,
    slice_remaining: u64,
    // If the caller requested no bytes, the extractor is still required to
    // include a chunk. We're not required to verify it, but we want to
    // aggressively check for extractor bugs.
    need_fake_read: bool,
}

/// An incremental decoder, which reads and verifies the output of
/// [`Encoder`](../encode/struct.Encoder.html).
///
/// `Decoder` supports both the combined and outboard encoding format,
/// depending on which constructor you use.
///
/// `Decoder` supports
/// [`std::io::Seek`](https://doc.rust-lang.org/std/io/trait.Seek.html) if the
/// underlying reader does, but it's also compatible with non-seekable readers.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::prelude::*;
///
/// // Create both combined and outboard encodings.
/// let input = b"some input";
/// let (encoded, hash) = bao::encode(input);
/// let (outboard, _) = bao::Config::default().encode_outboard(input);
///
/// // Decode the combined mode.
/// let mut combined_output = Vec::new();
/// let mut decoder = bao::Decoder::new(&*encoded, &hash);
/// decoder.read_to_end(&mut combined_output)?;
///
/// // Decode the outboard mode.
/// let mut outboard_output = Vec::new();
/// let mut decoder = bao::Decoder::new_outboard(&input[..], &*outboard, &hash);
/// decoder.read_to_end(&mut outboard_output)?;
///
/// assert_eq!(input, &*combined_output);
/// assert_eq!(input, &*outboard_output);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Decoder<T: Read, O: Read = T> {
    shared: decode::DecoderShared<T, O>,
}

/// Errors that can happen during decoding.
///
/// Two errors are possible when decoding, apart from the usual IO issues: the content bytes might
/// not have the right hash, or the encoding might not be as long as it's supposed to be. In
/// `std::io::Read` interfaces where we have to return `std::io::Error`, these variants are
/// converted to `ErrorKind::InvalidData` and `ErrorKind::UnexpectedEof` respectively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    HashMismatch,
    Truncated,
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
