use byteorder::{ByteOrder, BigEndian};

/// We use `None` to represent overflow here, and an equivalent to `try!` helps
/// make that code easier to write.
macro_rules! try_opt {
    ($e:expr) => (
        match $e {
            Some(v) => v,
            None => return None,
        }
    )
}

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

    // pub fn to_header(&self) -> [u8; ::HEADER_SIZE] {
    //     let mut ret = [0; ::HEADER_SIZE];
    //     BigEndian::write_u64(&mut ret[..8], self.len());
    //     ret[8..].copy_from_slice(&self.hash);
    //     ret
    // }

    pub fn from_header(bytes: &[u8; ::HEADER_SIZE]) -> Region {
        Region {
            start: 0,
            end: BigEndian::read_u64(&bytes[..8]),
            encoded_offset: ::HEADER_SIZE as u64,
            hash: *array_ref!(bytes, 8, ::DIGEST_SIZE),
        }
    }

    /// Splits the current region into two subregions, with the key logic
    /// happening in `left_subregion_len`. If calculating the new
    /// `encoded_offset` overflows, return `None`.
    pub fn parse_node(&self, bytes: &[u8; ::NODE_SIZE]) -> Option<Node> {
        let left = Region {
            start: self.start,
            end: self.start + left_subregion_len(self.len()),
            encoded_offset: try_opt!(self.encoded_offset.checked_add(::NODE_SIZE as u64)),
            hash: *array_ref!(bytes, 0, ::DIGEST_SIZE),
        };
        let right = Region {
            start: left.end,
            end: self.end,
            encoded_offset: try_opt!(left.encoded_offset.checked_add(
                try_opt!(encoded_len(left.len())),
            )),
            hash: *array_ref!(bytes, ::DIGEST_SIZE, ::DIGEST_SIZE),
        };
        Some(Node { left, right })
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

    // pub fn to_bytes(&self) -> [u8; ::NODE_SIZE] {
    //     let mut bytes = [0; ::NODE_SIZE];
    //     bytes[..::DIGEST_SIZE].copy_from_slice(&self.left.hash);
    //     bytes[::DIGEST_SIZE..].copy_from_slice(&self.right.hash);
    //     bytes
    // }

    // pub fn region(&self) -> Region {
    //     Region {
    //         start: self.left.start,
    //         end: self.right.end,
    //         encoded_offset: self.left.encoded_offset - ::NODE_SIZE as u64,
    //         hash: ::hash(&self.to_bytes()),
    //     }
    // }
}

/// "Given a region of input length `n`, larger than one chunk, what's the
/// length of its left subregion?" The answer to this question completely
/// determines the shape of the encoded tree. The answer is: the largest power
/// of 2 count of full chunks that's strictly less than the input length.
///
/// Several properties fall out from that one:
/// - All chunks are full, except maybe the last one.
/// - The last chunk is never empty, unless there is no input.
/// - All left subtrees are full, everywhere in the tree.
/// - The tree is balanced.
///
/// We depend on these properties in several places, for example in
/// `encoded_len` below. The stability of the left subtrees makes it efficient
/// to build a tree incrementally, since appending input bytes only affects
/// nodes on the rightmost edge of the tree.
fn left_subregion_len(region_len: u64) -> u64 {
    debug_assert!(region_len > ::CHUNK_SIZE as u64);
    // Reserve at least one byte for the right side.
    let full_chunks = (region_len - 1) / ::CHUNK_SIZE as u64;
    largest_power_of_two(full_chunks) * ::CHUNK_SIZE as u64
}

/// Compute the largest power of two that's less than or equal to `n`.
fn largest_power_of_two(n: u64) -> u64 {
    // n=0 is nonsensical, so we set the first bit of n. This doesn't change
    // the result for any other input, but it ensures that leading_zeros will
    // be at most 63, so the subtraction doesn't underflow.
    let masked_n = n | 1;
    1 << (63 - masked_n.leading_zeros())
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
fn encoded_len(region_len: u64) -> Option<u64> {
    // Divide rounding up to get the number of chunks.
    let num_chunks = (region_len / ::CHUNK_SIZE as u64) +
        (region_len % ::CHUNK_SIZE as u64 > 0) as u64;
    // The number of nodes is one less, but not less than zero.
    let num_nodes = num_chunks.saturating_sub(1);
    // `all_nodes` can't overflow by itself unless the node size is larger
    // than the chunk size, which would be pathological, but whatever :p
    try_opt!(num_nodes.checked_mul(::NODE_SIZE as u64)).checked_add(region_len)
}

// fn checked_add(a: u64, b: u64) -> ::Result<u64> {
//     a.checked_add(b).ok_or(::Error::Overflow)
// }

// fn checked_mul(a: u64, b: u64) -> ::Result<u64> {
//     a.checked_mul(b).ok_or(::Error::Overflow)
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_power_of_two() {
        let input_output = &[
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 4),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 8),
            // the largest possible u64
            (0xffffffffffffffff, 0x8000000000000000),
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
    fn test_left_subregion_len() {
        let s = ::CHUNK_SIZE as u64;
        let input_output = &[(s + 1, s), (2 * s - 1, s), (2 * s, s), (2 * s + 1, 2 * s)];
        for &(input, output) in input_output {
            println!("testing {} and {}", input, output);
            assert_eq!(left_subregion_len(input), output);
        }
    }

    #[test]
    fn test_encoded_len() {
        for &case in ::TEST_CASES {
            let found_len = ::simple::encode(&vec![0; case]).0.len() as u64;
            let computed_len = encoded_len(case as u64).unwrap() + ::HEADER_SIZE as u64;
            assert_eq!(found_len, computed_len, "wrong length in case {}", case);
        }
    }
}
