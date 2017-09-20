use byteorder::{ByteOrder, BigEndian};

pub fn encode(input: &[u8]) -> (Vec<u8>, ::Digest) {
    let mut output = vec![0; ::HEADER_SIZE];
    // Write the length of the input to the first 8 bytes of the header. The
    // remaining 32 bytes in the header are reserved for the root hash.
    BigEndian::write_u64(&mut output[..8], input.len() as u64);
    // Recursively encode all the input, appending to the output vector after
    // the header.
    let root_hash = encode_simple_inner(input, &mut output);
    // Write the root hash to the reserved space in the header.
    output[8..::HEADER_SIZE].copy_from_slice(&root_hash);
    // Hash the header and return the results.
    let header_hash = ::hash(&output[..::HEADER_SIZE]);
    (output, header_hash)
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

pub fn decode(mut encoded_input: &[u8], hash: &::Digest) -> ::Result<Vec<u8>> {
    // Verify the header, and split out the input length and the root hash.
    // We bump `encoded_input` forward as we read, both here and in the
    // recursive helper.
    let header = verify_read_bump(&mut encoded_input, ::HEADER_SIZE, hash)?;
    let decoded_len = BigEndian::read_u64(&header[..8]);
    if decoded_len > usize::max_value() as u64 {
        panic!("input length is too big to fit in memory");
    }
    let root_hash = array_ref!(header, 8, ::DIGEST_SIZE);
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
    hash: &::Digest,
    output: &mut Vec<u8>,
) -> ::Result<()> {
    // If we're down to an individual chunk, verify its hash and append it to
    // the output. We bump the input as we go, to keep track of what's been
    // read.
    if decoded_len <= ::CHUNK_SIZE {
        let chunk = verify_read_bump(encoded_input, decoded_len as usize, hash)?;
        output.extend_from_slice(chunk);
        return Ok(());
    }
    // Otherwise we have a node, and we need to decode its left and right
    // subtrees. Verify the node bytes and read the subtree hashes.
    let node = verify_read_bump(encoded_input, ::NODE_SIZE, hash)?;
    let left_hash = array_ref!(node, 0, ::DIGEST_SIZE);
    let right_hash = array_ref!(node, ::DIGEST_SIZE, ::DIGEST_SIZE);
    // Recursively verify and decode the left and right subtrees.
    let left_len = ::left_len(decoded_len as u64) as usize;
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
    hash: &::Digest,
) -> ::Result<&'a [u8]> {
    if input.len() < read_len {
        return Err(::Error::HashMismatch);
    }
    let out = &input[..read_len];
    ::verify(out, hash)?;
    *input = &input[read_len..];
    Ok(out)
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
