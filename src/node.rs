//! This module handles fiddly details like byte formatting and overflow
//! checking, so that the encoders and decoders can just focus on the higher
//! level layout of the tree. In general there aren't any loops or recursion in
//! here, just quick operations on nodes and regions.

use simple;

/// A `Region` represents some part of the content (or all of it, if it's the
/// "root region") with a given hash. If the length of the region is less than
/// or equal to the chunk size, the region's hash is simply the hash of that
/// chunk. If it's longer than a chunk, then the region is encoded as a tree,
/// and it's hash is the hash of the node at the top of that tree.
///
/// Regions also track their "encoded offset", the position in the encoding
/// where the region's chunk or node begins. Note how this is different from
/// "start" and "end", which are offsets in the *content*, not the encoding.
#[derive(Debug, Copy, Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub encoded_offset: u64,
    pub hash: ::Digest,
}

impl Region {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn contains(&self, position: u64) -> bool {
        self.start <= position && position < self.end
    }

    pub fn from_header_bytes(bytes: &[u8]) -> Region {
        let (len, hash) = simple::from_header_bytes(bytes);
        Region {
            start: 0,
            end: len,
            encoded_offset: ::HEADER_SIZE as u64,
            hash: hash,
        }
    }

    /// Splits the current region into two subregions, with the key logic
    /// happening in `left_subregion_len`. If calculating the new
    /// `encoded_offset` overflows, return `None`.
    pub fn parse_node(&self, bytes: &[u8]) -> ::Result<Node> {
        let left = Region {
            start: self.start,
            end: self.start + simple::left_subregion_len(self.len()),
            encoded_offset: checked_add(self.encoded_offset, ::NODE_SIZE as u64)?,
            hash: *array_ref!(bytes, 0, ::DIGEST_SIZE),
        };
        let right = Region {
            start: left.end,
            end: self.end,
            encoded_offset: checked_add(left.encoded_offset, encoded_len(left.len())?)?,
            hash: *array_ref!(bytes, ::DIGEST_SIZE, ::DIGEST_SIZE),
        };
        Ok(Node { left, right })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Node {
    pub left: Region,
    pub right: Region,
}

impl Node {
    pub fn contains(&self, position: u64) -> bool {
        self.left.start <= position && position < self.right.end
    }
}

/// Computing the encoded length of a region is surprisingly cheap. All binary
/// trees have a useful property: as long as all interior nodes have exactly two
/// children (ours do), the number of nodes is always equal to the
/// number of leaves minus one. Because we require all the leaves in our tree
/// to be full chunks (except the last one), we only need to divide by the
/// chunk size, which in practice is just a bitshift.
///
/// Note that a complete encoded file is both the encoded "root region", and
/// the bytes of the header itself, which aren't accounted for here.
///
/// Because the encoded len is longer than the input length, it can overflow
/// for very large inputs. In that case, we return `None`.
pub fn encoded_len(region_len: u64) -> ::Result<u64> {
    // Divide rounding up to get the number of chunks.
    let num_chunks = (region_len / ::CHUNK_SIZE as u64) +
        (region_len % ::CHUNK_SIZE as u64 > 0) as u64;
    // The number of nodes is one less, but not less than zero.
    let num_nodes = num_chunks.saturating_sub(1);
    // `all_nodes` can't overflow by itself unless the node size is larger
    // than the chunk size, which would be pathological, but whatever :p
    checked_add(checked_mul(num_nodes, ::NODE_SIZE as u64)?, region_len)
}

fn checked_add(a: u64, b: u64) -> ::Result<u64> {
    a.checked_add(b).ok_or(::Error::Overflow)
}

fn checked_mul(a: u64, b: u64) -> ::Result<u64> {
    a.checked_mul(b).ok_or(::Error::Overflow)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encoded_len() {
        for &case in ::TEST_CASES {
            let found_len = ::simple::encode(&vec![0; case]).0.len() as u64;
            let computed_len = encoded_len(case as u64).unwrap() + ::HEADER_SIZE as u64;
            assert_eq!(found_len, computed_len, "wrong length in case {}", case);
        }
    }
}
