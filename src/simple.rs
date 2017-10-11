use byteorder::{ByteOrder, BigEndian};
use unverified::Unverified;

/// Given a slice of input bytes, encode the entire thing in memory and return
/// it as a vector, along with its hash.
///
/// This implementation uses recursion, and it's designed to be as simple as
/// possible to read.
pub fn encode(input: &[u8]) -> (Vec<u8>, ::Digest) {
    // Start with zeros for the header, to reserve space.
    let mut output = vec![0; ::HEADER_SIZE];

    // Recursively encode all the input, appending to the output vector after
    // the header.
    let root_hash = encode_recurse(input, &mut output);

    // Go back and fill in the header.
    let header = to_header_bytes(input.len() as u64, &root_hash);
    output[..::HEADER_SIZE].copy_from_slice(&header);

    (output, ::hash(&header))
}

fn encode_recurse(input: &[u8], output: &mut Vec<u8>) -> ::Digest {
    // If we're down to an individual chunk, write it directly to the ouput, and
    // return its hash.
    if input.len() <= ::CHUNK_SIZE {
        output.extend_from_slice(input);
        return ::hash(input);
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
    // can make without leaving the right tree empty.
    let left_len = left_subregion_len(input.len() as u64) as usize;
    let left_hash = encode_recurse(&input[..left_len], output);
    let right_hash = encode_recurse(&input[left_len..], output);

    // Write the left and right hashes into the space of the current node.
    output[node_start..node_half].copy_from_slice(&left_hash);
    output[node_half..node_end].copy_from_slice(&right_hash);

    // Return the hash of the current node.
    ::hash(&output[node_start..node_end])
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
    // Immediately shadow the encoded input with a wrapper type that only gives
    // us bytes when the hash is correct.
    let mut encoded = Unverified::wrap(encoded);

    // Verify and parse the header. Each successful read_verify moves the
    // encoded input forward.
    let header_bytes = encoded.read_verify(::HEADER_SIZE, hash)?;
    let (len, hash) = from_header_bytes(header_bytes);

    // Recursively verify and decode the tree, appending decoded bytes to the
    // output.
    let mut output = Vec::with_capacity(len as usize);
    decode_recurse(&mut encoded, len, &hash, &mut output)?;
    Ok(output)
}

fn decode_recurse(
    encoded: &mut Unverified,
    region_len: u64,
    hash: &::Digest,
    output: &mut Vec<u8>,
) -> ::Result<()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output.
    if region_len <= ::CHUNK_SIZE as u64 {
        let chunk_bytes = encoded.read_verify(region_len as usize, hash)?;
        output.extend_from_slice(chunk_bytes);
        return Ok(());
    }

    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes.
    let node_bytes = encoded.read_verify(::NODE_SIZE, &hash)?;
    let (left_len, right_len, left_hash, right_hash) = split_node(region_len, node_bytes);

    // Recursively verify and decode the left and right subtrees.
    decode_recurse(encoded, left_len, &left_hash, output)?;
    decode_recurse(encoded, right_len, &right_hash, output)?;
    Ok(())
}

/// "Given a region of input of length `n`, larger than one chunk, what's the
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
/// We depend on these properties in several places, for example in computing
/// the encoded size of a tree. The stability of the left subtrees makes it
/// efficient to build a tree incrementally, since appending input bytes only
/// affects nodes on the rightmost edge of the tree.
pub(crate) fn left_subregion_len(region_len: u64) -> u64 {
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
    1 << (63 - (n | 1).leading_zeros())
}

pub(crate) fn from_header_bytes(bytes: &[u8]) -> (u64, ::Digest) {
    let len = BigEndian::read_u64(&bytes[..8]);
    let hash = *array_ref!(bytes, 8, ::DIGEST_SIZE);
    (len, hash)
}

pub(crate) fn to_header_bytes(len: u64, hash: &::Digest) -> [u8; ::HEADER_SIZE] {
    let mut ret = [0; ::HEADER_SIZE];
    BigEndian::write_u64(&mut ret[..8], len);
    ret[8..].copy_from_slice(hash);
    ret
}

pub(crate) fn split_node(region_len: u64, node_bytes: &[u8]) -> (u64, u64, ::Digest, ::Digest) {
    let left_len = left_subregion_len(region_len);
    let right_len = region_len - left_len;
    let left_hash = *array_ref!(node_bytes, 0, ::DIGEST_SIZE);
    let right_hash = *array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE);
    (left_len, right_len, left_hash, right_hash)
}

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
}
