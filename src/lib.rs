#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate ring;

use byteorder::{ByteOrder, BigEndian};
use ring::{constant_time, digest};
use std::mem::size_of;

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;
pub const NODE_SIZE: usize = 2 * DIGEST_SIZE;
pub const HEADER_SIZE: usize = 8 + DIGEST_SIZE;

pub type Digest = [u8; DIGEST_SIZE];

fn hash(input: &[u8]) -> Digest {
    // First 32 bytes of SHA512. (The same as NaCl's crypto_hash.)
    let digest = digest::digest(&digest::SHA512, input);
    let mut ret = [0; DIGEST_SIZE];
    ret.copy_from_slice(&digest.as_ref()[..DIGEST_SIZE]);
    ret
}

fn verify(input: &[u8], digest: &Digest) -> Result<(), ()> {
    let computed = hash(input);
    constant_time::verify_slices_are_equal(&digest[..], &computed[..]).map_err(|_| ())
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
fn left_len(input_len: usize) -> usize {
    debug_assert!(input_len > CHUNK_SIZE);
    // Reserve at least one byte for the right side.
    let full_chunks = (input_len - 1) / CHUNK_SIZE;
    largest_power_of_two(full_chunks) * CHUNK_SIZE
}

fn left_len64(input_len: u64) -> u64 {
    debug_assert!(input_len > CHUNK_SIZE64);
    // Reserve at least one byte for the right side.
    let full_chunks = (input_len - 1) / CHUNK_SIZE64;
    largest_power_of_two64(full_chunks) * CHUNK_SIZE64
}

fn largest_power_of_two(n: usize) -> usize {
    // n=0 is nonsensical, so we set the first bit of n. This doesn't change
    // the result for any other input, but it ensures that leading_zeros will
    // be at most 63, so the subtraction doesn't underflow.
    let masked_n = n | 1;
    let max_shift = 8 * size_of::<usize>() - 1;
    1 << (max_shift - masked_n.leading_zeros() as usize)
}

fn largest_power_of_two64(n: u64) -> u64 {
    let masked_n = n | 1;
    let max_shift = 8 * size_of::<u64>() - 1;
    1 << (max_shift - masked_n.leading_zeros() as usize)
}

pub fn encode_simple(input: &[u8]) -> (Vec<u8>, Digest) {
    let mut output = vec![0; HEADER_SIZE];
    // Write the length of the input to the first 8 bytes of the header. The
    // remaining 32 bytes in the header are reserved for the root hash.
    BigEndian::write_u64(&mut output[..8], input.len() as u64);
    // Recursively encode all the input, appending to the output vector after
    // the header.
    let root_hash = encode_simple_inner(input, &mut output);
    // Write the root hash to the reserved space in the header.
    output[8..HEADER_SIZE].copy_from_slice(&root_hash);
    // Hash the header and return the results.
    let header_hash = hash(&output[..HEADER_SIZE]);
    (output, header_hash)
}

fn encode_simple_inner(input: &[u8], output: &mut Vec<u8>) -> Digest {
    // If we're down to an individual chunk, write it directly to the ouput, and
    // return its hash.
    if input.len() <= CHUNK_SIZE {
        output.extend_from_slice(input);
        return hash(input);
    }
    // Otherwise we have more than one chunk, and we need to encode a left
    // subtree and a right subtree. The nodes of these trees are the hashes of
    // their left and right children, and the leaves are chunks. Reserve space
    // for the current node.
    let node_start = output.len();
    let node_half = node_start + DIGEST_SIZE;
    let node_end = node_half + DIGEST_SIZE;
    output.resize(node_end, 0);
    // Recursively encode the left and right subtrees, appending them to the
    // output. The left subtree is the largest full tree of full chunks that we
    // can make without leaving the right tree empty.
    let left_len = left_len(input.len());
    let left_hash = encode_simple_inner(&input[..left_len], output);
    let right_hash = encode_simple_inner(&input[left_len..], output);
    // Write the left and right hashes into the space of the current node.
    output[node_start..node_half].copy_from_slice(&left_hash);
    output[node_half..node_end].copy_from_slice(&right_hash);
    // Return the hash of the current node.
    hash(&output[node_start..node_end])
}

pub fn decode_simple(mut encoded_input: &[u8], hash: &Digest) -> Result<Vec<u8>, ()> {
    // Verify the header, and split out the input length and the root hash.
    // We bump `encoded_input` forward as we read, both here and in the
    // recursive helper.
    let header = verify_read_bump(&mut encoded_input, HEADER_SIZE, hash)?;
    let decoded_len = BigEndian::read_u64(&header[..8]);
    if decoded_len > usize::max_value() as u64 {
        panic!("input length is too big to fit in memory");
    }
    let root_hash = array_ref!(header, 8, DIGEST_SIZE);
    // Recursively verify and decode the tree, appending decoded bytes to the
    // output.
    //
    // NOTE: We're respecting `decoded_len` and bumping the input forward as we
    // read it, rather than inspecting `encoded_input.len()`. That means that
    // like a streaming reader, this decoding will ignore any extra trailing
    // bytes appended to a valid encoding. As a result, ENCODED OUTPUT IS NOT
    // NECESSARILY UNIQUE FOR A GIVEN INPUT. Hashes are unique, however, as a
    // basic design requirement.
    let mut output = Vec::with_capacity(decoded_len as usize);
    decode_simple_inner(
        &mut encoded_input,
        decoded_len as usize,
        &root_hash,
        &mut output,
    )?;
    Ok(output)
}

fn decode_simple_inner(
    encoded_input: &mut &[u8],
    decoded_len: usize,
    hash: &Digest,
    output: &mut Vec<u8>,
) -> Result<(), ()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output. We bump the input as we go, to keep track of what's been
    // read.
    if decoded_len <= CHUNK_SIZE {
        let chunk = verify_read_bump(encoded_input, decoded_len as usize, hash)?;
        output.extend_from_slice(chunk);
        return Ok(());
    }
    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes.
    let node = verify_read_bump(encoded_input, NODE_SIZE, hash)?;
    let left_hash = array_ref!(node, 0, DIGEST_SIZE);
    let right_hash = array_ref!(node, DIGEST_SIZE, DIGEST_SIZE);
    // Recursively verify and decode the left and right subtrees.
    let left_len = left_len(decoded_len);
    let right_len = decoded_len - left_len;
    decode_simple_inner(encoded_input, left_len, left_hash, output)?;
    decode_simple_inner(encoded_input, right_len, right_hash, output)?;
    Ok(())
}

// Take a slice from an &mut &[u8], verify its hash, and bump the start of the
// source forward by the same amount. (Fun fact: &[u8] actually implements
// Reader, so we could almost make this generic, but using slices directly lets
// us avoid dealing with IO errors and buffering.)
fn verify_read_bump<'a>(
    input: &mut &'a [u8],
    read_len: usize,
    hash: &Digest,
) -> Result<&'a [u8], ()> {
    if input.len() < read_len {
        return Err(());
    }
    let out = &input[..read_len];
    verify(out, hash)?;
    *input = &input[read_len..];
    Ok(out)
}

pub const CHUNK_SIZE64: u64 = 4096;
pub const DIGEST_SIZE64: u64 = 32;
pub const NODE_SIZE64: u64 = 2 * DIGEST_SIZE64;
pub const HEADER_SIZE64: u64 = 8 + DIGEST_SIZE64;

#[derive(Debug, Clone, Copy)]
struct Region {
    hash: Digest,
    start: u64,
    len: u64,
    encoded_offset: u64,
}

impl Region {
    fn contains(&self, offset: u64) -> bool {
        // Note that start+len cannot overflow, because the start+len of the
        // rightmost region(s) is equal to the overall len.
        self.start <= offset && offset < (self.start + self.len)
    }

    // TODO: This panics on overflow. Not clear what we should do about that.
    fn encoded_len(&self) -> u64 {
        // Divide rounding up.
        let num_chunks = (self.len + CHUNK_SIZE64 - 1) / CHUNK_SIZE64;
        // Note that the empty input results in zero nodes, not "-1" nodes.
        (num_chunks.saturating_sub(1)) * NODE_SIZE64 + self.len
    }
}

#[derive(Debug, Clone, Copy)]
struct Node {
    left: Region,
    right: Region,
}

impl Node {
    fn contains(&self, offset: u64) -> bool {
        self.left.contains(offset) || self.right.contains(offset)
    }

    fn region_for(&self, offset: u64) -> Region {
        if self.left.contains(offset) {
            self.left
        } else if self.right.contains(offset) {
            self.right
        } else {
            panic!("offset outside of the current node")
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    header_hash: Digest,
    header: Option<Region>,
    offset: u64,
    stack: Vec<Node>,
}

impl Decoder {
    pub fn new(header_hash: &Digest) -> Self {
        Self {
            header_hash: *header_hash,
            header: None,
            offset: 0,
            stack: Vec::new(),
        }
    }

    pub fn len(&self) -> Option<u64> {
        self.header.map(|h| h.len)
    }

    pub fn seek(&mut self, offset: u64) {
        self.offset = offset;
        while let Some(&node) = self.stack.last() {
            if node.contains(offset) {
                break;
            }
            self.stack.pop();
        }
    }

    // Give the (offset, size) needed in the next call to feed(). A size of
    // zero means EOF.
    pub fn needed(&self) -> (u64, usize) {
        // Have we even read the header yet?
        let header_region = if let Some(region) = self.header {
            region
        } else {
            return (0, HEADER_SIZE);
        };
        // Are we at EOF?
        if self.offset >= header_region.len {
            return (0, 0);
        }
        // How far down the tree are we right now?
        let current_region = if let Some(node) = self.stack.last() {
            node.region_for(self.offset)
        } else {
            header_region
        };
        // If we're down to chunk size, ask for a chunk. Otherwise more nodes.
        if current_region.len <= CHUNK_SIZE64 {
            (current_region.encoded_offset, current_region.len as usize)
        } else {
            (current_region.encoded_offset, NODE_SIZE)
        }
    }

    // Returns (consumed, output), where output is Some() when a chunk was
    // consumed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Option<&'a [u8]>), ()> {
        let header_region = if let Some(region) = self.header {
            region
        } else {
            verify(&input[..HEADER_SIZE], &self.header_hash)?;
            let decoded_len = BigEndian::read_u64(&input[..8]);
            let root_hash = array_ref!(input, 8, DIGEST_SIZE);
            self.header = Some(Region {
                hash: *root_hash,
                start: 0,
                len: decoded_len,
                encoded_offset: HEADER_SIZE64,
            });
            return Ok((HEADER_SIZE, None));
        };
        // Are we at EOF?
        if self.offset >= header_region.len {
            return Ok((0, None));
        }
        // How far down the tree are we right now?
        let current_region = if let Some(node) = self.stack.last() {
            node.region_for(self.offset)
        } else {
            header_region
        };
        // If we're down to chunk size, ask for a chunk. Otherwise more nodes.
        if current_region.len <= CHUNK_SIZE64 {
            verify(&input[..current_region.len as usize], &current_region.hash)?;
            let chunk_offset = (self.offset - current_region.start) as usize;
            let ret = &input[chunk_offset..current_region.len as usize];
            self.seek(current_region.start + current_region.len);
            Ok((ret.len(), Some(ret)))
        } else {
            verify(&input[..NODE_SIZE], &current_region.hash)?;
            let left_hash = array_ref!(input, 0, DIGEST_SIZE);
            let right_hash = array_ref!(input, DIGEST_SIZE, DIGEST_SIZE);
            let left_region = Region {
                hash: *left_hash,
                start: current_region.start,
                len: left_len64(current_region.len),
                encoded_offset: current_region.encoded_offset + NODE_SIZE64,
            };
            let right_region = Region {
                hash: *right_hash,
                start: left_region.start + left_region.len,
                len: current_region.len - left_region.len,
                encoded_offset: left_region.encoded_offset + left_region.encoded_len(),
            };
            self.stack.push(Node {
                left: left_region,
                right: right_region,
            });
            Ok((NODE_SIZE, None))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Interesting input lengths to run tests on.
    const CASES: &[usize] = &[
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
        1_000_000,
    ];

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
        let input_output: &[(usize, usize)] = &[
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 4),
            // Make sure to test the largest possible value.
            (
                usize::max_value(),
                usize::max_value() ^ (usize::max_value() >> 1),
            ),
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
        let input_output: &[(usize, usize)] = &[
            (CHUNK_SIZE + 1, CHUNK_SIZE),
            (2 * CHUNK_SIZE - 1, CHUNK_SIZE),
            (2 * CHUNK_SIZE, CHUNK_SIZE),
            (2 * CHUNK_SIZE + 2, 2 * CHUNK_SIZE),
        ];
        for &(input, output) in input_output {
            println!("testing {} and {}", input, output);
            assert_eq!(left_len(input), output);
        }
    }

    #[test]
    fn test_simple_encode_decode() {
        for &case in CASES {
            println!("starting case {}", case);
            let input = vec![0xab; case];
            let (encoded, hash) = encode_simple(&input);
            let decoded = decode_simple(&encoded, &hash).unwrap();
            assert_eq!(input, decoded);
        }
    }

    #[test]
    fn test_simple_corrupted() {
        for &case in CASES {
            let input = vec![0xbc; case];
            let (mut encoded, hash) = encode_simple(&input[..]);
            // Tweak different bytes of the encoding, and confirm that all
            // tweaks break the result.
            for &tweak_case in CASES {
                if tweak_case < encoded.len() {
                    encoded[tweak_case] ^= 1;
                    println!("testing input len {} tweak {}", case, tweak_case);
                    assert!(decode_simple(&encoded, &hash).is_err());
                    encoded[tweak_case] ^= 1;
                }
            }
        }
    }

    #[test]
    fn test_encoded_len() {
        for &case in CASES {
            // All dummy values except for len.
            let region = Region {
                hash: [0; DIGEST_SIZE],
                start: 0,
                len: case as u64,
                encoded_offset: 0,
            };
            let found_len = encode_simple(&vec![0; case]).0.len() as u64;
            let computed_len = region.encoded_len() + HEADER_SIZE64;
            assert_eq!(found_len, computed_len, "wrong length in case {}", case);
        }
    }

    #[test]
    fn test_codec() {
        for &case in CASES {
            println!("\n>>>>> starting case {}", case);
            let input = vec![0x72; case];
            let (encoded, hash) = encode_simple(&input);
            println!("encoded.len() {}", encoded.len());
            let mut decoder = Decoder::new(&hash);
            let mut output = Vec::new();
            loop {
                let (offset, len) = decoder.needed();
                println!("needed: {}, {}", offset, len);
                if len == 0 {
                    break;
                }
                let encoded_input = &encoded[offset as usize..offset as usize + len];
                let (consumed, maybe_output) = decoder.feed(encoded_input).unwrap();
                println!(
                    "consumed: {} (gave output: {})",
                    consumed,
                    maybe_output.is_some()
                );
                assert_eq!(consumed, len);
                if let Some(slice) = maybe_output {
                    output.extend_from_slice(slice);
                }
            }
            assert_eq!(input, output);
        }
    }
}
