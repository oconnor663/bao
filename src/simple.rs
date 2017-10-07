use node::{header_bytes, Region};

pub fn encode(input: &[u8]) -> (Vec<u8>, ::Digest) {
    // Start with zeros for the header, to reserve space.
    let mut output = vec![0; ::HEADER_SIZE];

    // Recursively encode all the input, appending to the output vector after
    // the header.
    let root_hash = encode_simple_inner(input, &mut output);

    // Go back and fill in the header.
    let header = header_bytes(input.len() as u64, &root_hash);
    output[..::HEADER_SIZE].copy_from_slice(&header);

    (output, ::hash(&header))
}

fn encode_simple_inner(input: &[u8], output: &mut Vec<u8>) -> ::Digest {
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
    let left_len = ::left_len(input.len() as u64) as usize;
    let left_hash = encode_simple_inner(&input[..left_len], output);
    let right_hash = encode_simple_inner(&input[left_len..], output);

    // Write the left and right hashes into the space of the current node.
    output[node_start..node_half].copy_from_slice(&left_hash);
    output[node_half..node_end].copy_from_slice(&right_hash);

    // Return the hash of the current node.
    ::hash(&output[node_start..node_end])
}

pub fn decode(encoded: &[u8], hash: &::Digest) -> ::Result<Vec<u8>> {
    // Immediately shadow the encoded input with a wrapper type that only gives
    // us bytes when the hash is correct.
    let mut encoded = ::evil::EvilBytes::wrap(encoded);

    // Verify the header, and split out the input length and the root hash. We
    // bump `encoded` forward as we read, both here and in the recursive
    // helper.
    let header_slice = encoded.verify_bump(::HEADER_SIZE, hash)?;
    let header_array = array_ref!(header_slice, 0, ::HEADER_SIZE);
    let header = Region::from_bytes(header_array);

    // Recursively verify and decode the tree, appending decoded bytes to the
    // output.
    //
    // NOTE: Throughout all this slicing and verifying, we never check whether
    // the slice might have *more* bytes than we need. That means that after we
    // decode the last chunk, we'll ignore any trailing garbage that might be
    // appended to the encoding, just like a streaming decoder would. As a
    // result, THERE ARE MANY VALID ENCODINGS FOR A GIVEN INPUT, differing only
    // in their trailing garbage. Callers that assume different encoded bytes
    // imply different (or invalid) input bytes, could get tripped up on this.
    //
    // It's tempting to solve this problem on our end, with a rule like
    // "decoders must read to EOF and check for trailing garbage." But I think
    // it's better to make no promises, than to make a promise we can't keep.
    // Testing this rule across all future implementation would be very
    // difficult. For example, an implementation might check for trailing
    // garbage at the end of any block that it reads, and thus appear to past
    // most tests, but forget the case where the end of the valid encoding
    // lands precisely on a read boundary.

    // This cast to usize could overflow on less-than-64-bit platforms. That's
    // ok. Decoding will produce an Error::Overflow later.
    let mut output = Vec::with_capacity(header.len() as usize);
    decode_simple_inner(&mut encoded, &header, &mut output)?;
    Ok(output)
}

fn decode_simple_inner(
    encoded: &mut ::evil::EvilBytes,
    region: &Region,
    output: &mut Vec<u8>,
) -> ::Result<()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output. We bump the encoded input as we go, to keep track of what's
    // been read.
    if region.len() <= ::CHUNK_SIZE as u64 {
        let chunk = encoded.verify_bump(region.len() as usize, &region.hash)?;
        output.extend_from_slice(chunk);
        return Ok(());
    }

    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes.
    let node_slice = encoded.verify_bump(::NODE_SIZE, &region.hash)?;
    let node_array = array_ref!(node_slice, 0, ::NODE_SIZE);
    let node = region.parse_node(&node_array).ok_or(::Error::Overflow)?;

    // Recursively verify and decode the left and right subtrees.
    decode_simple_inner(encoded, &node.left, output)?;
    decode_simple_inner(encoded, &node.right, output)?;
    Ok(())
}

#[cfg(test)]
mod test {
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
