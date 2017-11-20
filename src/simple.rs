use byteorder::{ByteOrder, LittleEndian};
use unverified::Unverified;

/// Given a slice of input bytes, encode the entire thing in memory and return
/// it as a vector, along with its hash.
///
/// This implementation uses recursion, and it's designed to be as simple as
/// possible to read.
pub fn encode(input: &[u8]) -> (Vec<u8>, ::Digest) {
    // Start with the encoded length.
    let mut output = vec![0; ::HEADER_SIZE];
    LittleEndian::write_u64(&mut output, input.len() as u64);

    // Recursively encode all the input, appending to the output vector after
    // the encoded length. The root node will incorporate the encoded length as
    // a prefix.
    let root_hash = encode_recurse(input, &mut output, ::HEADER_SIZE);

    (output, root_hash)
}

fn encode_recurse(input: &[u8], output: &mut Vec<u8>, prefix_len: usize) -> ::Digest {
    // If we're down to an individual chunk, write it directly to the ouput, and
    // return its hash.
    if input.len() <= ::CHUNK_SIZE {
        output.extend_from_slice(input);
        return ::hash(&output[output.len() - input.len() - prefix_len..]);
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
    // never have a prefix.
    let left_len = left_subtree_len(input.len() as u64) as usize;
    let left_hash = encode_recurse(&input[..left_len], output, 0);
    let right_hash = encode_recurse(&input[left_len..], output, 0);

    // Write the left and right hashes into the space of the current node.
    output[node_start..node_half].copy_from_slice(&left_hash);
    output[node_half..node_end].copy_from_slice(&right_hash);

    // Return the hash of the current node.
    ::hash(&output[node_start - prefix_len..node_end])
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
    // unverified, but they'll be included as a prefix for the root node in the
    // recursive portion.
    if encoded.len() < ::HEADER_SIZE {
        return Err(::Error::ShortInput);
    }
    let content_len = LittleEndian::read_u64(&encoded[..::HEADER_SIZE]);

    // Recursively verify and decode the tree, appending decoded bytes to the
    // output.
    let mut unverified = Unverified::wrap(encoded);
    let mut output = Vec::with_capacity(content_len as usize);
    decode_recurse(
        &mut unverified,
        content_len,
        ::HEADER_SIZE,
        &hash,
        &mut output,
    )?;
    Ok(output)
}

fn decode_recurse(
    encoded: &mut Unverified,
    content_len: u64,
    prefix_len: usize,
    hash: &::Digest,
    output: &mut Vec<u8>,
) -> ::Result<()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output. Skip the prefix if any.
    if content_len <= ::CHUNK_SIZE as u64 {
        let chunk_bytes = encoded.read_verify(prefix_len + content_len as usize, hash)?;
        output.extend_from_slice(&chunk_bytes[prefix_len..]);
        return Ok(());
    }

    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes. Skip the
    // prefix if any.
    let node_bytes = encoded.read_verify(prefix_len + ::NODE_SIZE, hash)?;
    let (left_len, right_len, left_hash, right_hash) =
        split_node(content_len, &node_bytes[prefix_len..]);

    // Recursively verify and decode the left and right subtrees. Nodes below
    // the root never have a prefix.
    decode_recurse(encoded, left_len, 0, &left_hash, output)?;
    decode_recurse(encoded, right_len, 0, &right_hash, output)?;
    Ok(())
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

pub(crate) fn split_node(content_len: u64, node_bytes: &[u8]) -> (u64, u64, ::Digest, ::Digest) {
    let left_len = left_subtree_len(content_len);
    let right_len = content_len - left_len;
    let left_hash = *array_ref!(node_bytes, 0, ::DIGEST_SIZE);
    let right_hash = *array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE);
    (left_len, right_len, left_hash, right_hash)
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
