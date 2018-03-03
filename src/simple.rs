use byteorder::{ByteOrder, LittleEndian};
use std::mem;

/// Given a slice of input bytes, encode the entire thing in memory and return
/// it as a vector, along with its hash.
///
/// This implementation uses recursion, and it's designed to be as simple as
/// possible to read.
pub fn encode(input: &[u8]) -> (Vec<u8>, ::Digest) {
    // Start with the encoded length.
    let mut encoded_len = [0; ::HEADER_SIZE];
    LittleEndian::write_u64(&mut encoded_len, input.len() as u64);
    let mut output = encoded_len.to_vec();

    // Recursively encode all the input, appending to the output vector after
    // the encoded length. The digest of the root node will add the encoded
    // length as a suffix, and set the final node flag.
    let root_hash = encode_recurse(input, &mut output, &encoded_len[..]);

    (output, root_hash)
}

fn encode_recurse(input: &[u8], output: &mut Vec<u8>, suffix: &[u8]) -> ::Digest {
    // If we're down to an individual chunk, write it directly to the ouput, and
    // return its hash. If this chunk is the root node, it'll get suffixed.
    if input.len() <= ::CHUNK_SIZE {
        output.extend_from_slice(input);
        return ::hash_node(input, suffix);
    }

    // Otherwise we have more than one chunk, and we need to encode a left
    // subtree and a right subtree. The nodes of these trees are the hashes of
    // their left and right children, and the leaves are chunks. Reserve space
    // for the current node.
    let node_start = output.len();
    let node_half = node_start + ::DIGEST_SIZE;
    let node_end = node_half + ::DIGEST_SIZE;
    output.resize(node_end, 0);

    // Recursively encode the left and right subtrees, appending them to the
    // output. The left subtree is the largest full tree of full chunks that we
    // can make without leaving the right tree empty. Nodes below the root
    // never have a suffix.
    let left_len = left_subtree_len(input.len() as u64) as usize;
    let left_hash = encode_recurse(&input[..left_len], output, &[]);
    let right_hash = encode_recurse(&input[left_len..], output, &[]);

    // Write the left and right hashes into the space of the current node.
    output[node_start..node_half].copy_from_slice(&left_hash);
    output[node_half..node_end].copy_from_slice(&right_hash);

    // Return the hash of the current node. Again if this is the root node,
    // it'll get hashed with a suffix.
    ::hash_node(&output[node_start..node_end], suffix)
}

/// Recursively verify the encoded tree and return the content.
///
/// Throughout all this slicing and verifying, we never check whether a slice
/// has *more* bytes than we need. That means that after we decode the last
/// chunk, we'll ignore any trailing garbage that might be appended to the
/// encoding, just like a streaming decoder would. As a result, THERE ARE MANY
/// VALID ENCODINGS FOR A GIVEN INPUT, differing only in their trailing
/// garbage. Callers that assume different encoded bytes imply different (or
/// invalid) input bytes, could get tripped up on this.
///
/// It's tempting to solve this problem on our end, with a rule like "decoders
/// must read to EOF and check for trailing garbage." But I think it's better
/// to make no promises, than to make a promise we can't keep. Testing this
/// rule across all future implementation would be very difficult. For example,
/// an implementation might check for trailing garbage at the end of any block
/// that it reads, and thus appear to past most tests, but forget the case
/// where the end of the valid encoding lands precisely on a read boundary.
pub fn decode(encoded: &[u8], hash: &::Digest) -> ::Result<Vec<u8>> {
    // Read the content length from the front of the encoding. These bytes are
    // unverified, but they'll be included as a suffix for the root node in the
    // recursive portion.
    if encoded.len() < ::HEADER_SIZE {
        return Err(::Error::ShortInput);
    }
    let (header, rest) = encoded.split_at(::HEADER_SIZE);
    let content_len = LittleEndian::read_u64(header);

    // Recursively verify and decode the tree, appending decoded bytes to the
    // output.
    let mut output = Vec::with_capacity(content_len as usize);
    decode_recurse(rest, content_len, &hash, header, &mut output)?;
    Ok(output)
}

fn decode_recurse(
    encoded: &[u8],
    content_len: u64,
    hash: &::Digest,
    suffix: &[u8],
    output: &mut Vec<u8>,
) -> ::Result<()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output. Skip the prefix if any.
    if content_len <= ::CHUNK_SIZE as u64 {
        let chunk_bytes = ::verify_node(encoded, as_usize(content_len)?, hash, suffix)?;
        output.extend_from_slice(chunk_bytes);
        return Ok(());
    }

    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes.
    let node_bytes = ::verify_node(encoded, ::NODE_SIZE, hash, suffix)?;
    let left_hash = *array_ref!(node_bytes, 0, ::DIGEST_SIZE);
    let right_hash = *array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE);
    let left_content_len = left_subtree_len(content_len);
    let right_content_len = content_len - left_content_len;
    let left_encoded_len = encoded_len(left_content_len)?;
    let left_encoded_bytes = &encoded[::NODE_SIZE..];
    let right_encoded_bytes = &left_encoded_bytes[as_usize(left_encoded_len)?..];

    // Recursively verify and decode the left and right subtrees. Nodes below
    // the root never have a suffix.
    decode_recurse(
        left_encoded_bytes,
        left_content_len,
        &left_hash,
        &[],
        output,
    )?;
    decode_recurse(
        right_encoded_bytes,
        right_content_len,
        &right_hash,
        &[],
        output,
    )
}

/// "Given input of length `n`, larger than one chunk, how much of it goes in
/// the left subtree?" The answer to this question completely determines the
/// shape of the encoded tree. The answer is: the left subtree is the largest
/// perfect tree (power of 2 leaves) of full chunks that leaves at least one
/// byte for the right side. So for example, if the input is exactly 4 chunks,
/// then the split is 2 chunks on the left and the right, but if it's 4 chunks
/// plus 1 byte, then the split is 4 full chunks on the left and one byte on
/// the right.
///
/// Several properties fall out from this rule, recursively applied:
/// - All chunks are full, except maybe the last one.
/// - The last chunk is never empty, unless there is no input.
/// - All left subtrees are full, everywhere in the tree.
/// - The tree is balanced.
///
/// We depend on these properties in several places, for example in computing
/// the encoded size of a tree. The stability of the left subtrees also makes
/// it efficient to build a tree incrementally, since appending input bytes
/// only affects nodes on the rightmost edge of the tree.
pub(crate) fn left_subtree_len(content_len: u64) -> u64 {
    debug_assert!(content_len > ::CHUNK_SIZE as u64);
    // Subtract 1 to reserve at least one byte for the right side.
    let full_chunks = (content_len - 1) / ::CHUNK_SIZE as u64;
    largest_power_of_two(full_chunks) * ::CHUNK_SIZE as u64
}

/// Compute the largest power of two that's less than or equal to `n`.
fn largest_power_of_two(n: u64) -> u64 {
    // n=0 is nonsensical, so we set the first bit of n. This doesn't change
    // the result for any other input, but it ensures that leading_zeros will
    // be at most 63, so the subtraction doesn't underflow.
    1 << (63 - (n | 1).leading_zeros())
}

pub(crate) fn from_header_bytes(bytes: &[u8]) -> (u64, ::Digest) {
    let len = LittleEndian::read_u64(&bytes[..8]);
    let hash = *array_ref!(bytes, 8, ::DIGEST_SIZE);
    (len, hash)
}

pub(crate) fn to_header_bytes(len: u64, hash: &::Digest) -> [u8; ::HEADER_SIZE] {
    let mut ret = [0; ::HEADER_SIZE];
    LittleEndian::write_u64(&mut ret[..8], len);
    ret[8..].copy_from_slice(hash);
    ret
}

pub fn as_usize(n: u64) -> ::Result<usize> {
    // Maybe someday this code runs on a 128-bit system and we have a problem?
    debug_assert!(mem::size_of::<usize>() <= mem::size_of::<u64>());
    if n > usize::max_value() as u64 {
        Err(::Error::Overflow)
    } else {
        Ok(n as usize)
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
/// for very large inputs. In that case, we return `Err(Overflow)`.
fn encoded_len(region_len: u64) -> ::Result<u64> {
    // Divide rounding up to get the number of chunks.
    let num_chunks =
        (region_len / ::CHUNK_SIZE as u64) + (region_len % ::CHUNK_SIZE as u64 > 0) as u64;
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
    use hex::ToHex;

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
    fn test_left_subtree_len() {
        let s = ::CHUNK_SIZE as u64;
        let input_output = &[(s + 1, s), (2 * s - 1, s), (2 * s, s), (2 * s + 1, 2 * s)];
        for &(input, output) in input_output {
            println!("testing {} and {}", input, output);
            assert_eq!(left_subtree_len(input), output);
        }
    }

    #[test]
    fn test_simple_encode_decode() {
        for &case in ::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0xab; case];
            let (encoded, hash) = ::simple::encode(&input);
            let decoded = ::simple::decode(&encoded, &hash).unwrap();
            assert_eq!(input, decoded);
        }
    }

    #[test]
    fn test_simple_corrupted() {
        for &case in ::TEST_CASES {
            let input = vec![0xbc; case];
            let (mut encoded, hash) = ::simple::encode(&input[..]);
            // Tweak different bytes of the encoding, and confirm that all
            // tweaks break the result.
            for &tweak_case in ::TEST_CASES {
                if tweak_case < encoded.len() {
                    encoded[tweak_case] ^= 1;
                    println!("testing input len {} tweak {}", case, tweak_case);
                    assert!(::simple::decode(&encoded, &hash).is_err());
                    encoded[tweak_case] ^= 1;
                }
            }
        }
    }

    #[test]
    fn test_compare_python() {
        for &case in ::TEST_CASES {
            println!("case {}", case);
            let input = vec![0x99; case];
            let (rust_encoded, rust_digest) = ::simple::encode(&input);

            // Have the Python implementation encode the same input, and make
            // sure the result is identical.
            let python_encoded = cmd!("python3", "./python/bao.py", "encode", "--memory")
                .input(input.clone())
                .stdout_capture()
                .run()
                .expect("is python3 installed?")
                .stdout;
            assert_eq!(&rust_encoded, &python_encoded, "encoding mismatch");

            // Make sure the Python implementation can decode too.
            let python_decoded = cmd!(
                "python3",
                "./python/bao.py",
                "decode",
                "--hash",
                rust_digest.to_hex()
            ).input(python_encoded)
                .stdout_capture()
                .run()
                .expect("decoding failed")
                .stdout;
            assert_eq!(&input, &python_decoded, "decoding mismatch");
        }
    }

    // Tested in both simple.rs and decode.rs.
    #[test]
    fn test_short_header_fails() {
        // A permissive decoder might allow 7 null bytes to be zero just like 8
        // null bytes would be. That would be a bug, and a security bug at
        // that. The hash of 7 nulls isn't the same as the hash of 8, and it's
        // crucial that a given input has a unique hash.
        let encoded = vec![0; 7];
        let hash = ::hash(&encoded);
        assert_eq!(decode(&encoded, &hash).unwrap_err(), ::Error::ShortInput);
    }
}
