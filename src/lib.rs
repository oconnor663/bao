extern crate ring;

use ring::{constant_time, digest, error};

const CHUNK_SIZE: usize = 4096;
const DIGEST_SIZE: usize = 32;

type Digest = [u8; DIGEST_SIZE];

fn hash(input: &[u8]) -> Digest {
    // First 32 bytes of SHA512. (The same as NaCl's crypto_hash.)
    let digest = digest::digest(&digest::SHA512, input);
    let mut ret = [0; DIGEST_SIZE];
    (&mut ret[..DIGEST_SIZE]).copy_from_slice(&digest.as_ref()[..DIGEST_SIZE]);
    ret
}

fn verify(input: &[u8], digest: Digest) -> Result<(), error::Unspecified> {
    let computed = hash(input);
    constant_time::verify_slices_are_equal(&digest[..], &computed[..])
}

fn left_side_len(input_len: usize) -> usize {
    // Find the first power of 2 times the chunk size that is *strictly* less than the input
    // length. So if the input is exactly 4 chunks long, for example, the answer here will be 2
    // chunks.
    assert!(input_len > CHUNK_SIZE);
    let mut size = CHUNK_SIZE;
    while (size * 2) < input_len {
        size *= 2;
    }
    size
}

pub fn encode(input: &[u8]) -> (Digest, Vec<u8>) {
    if input.len() <= CHUNK_SIZE {
        return (hash(input), input.to_vec());
    }
    let left_len = left_side_len(input.len());
    let (left_hash, left_encoded) = encode(&input[..left_len]);
    let (right_hash, right_encoded) = encode(&input[..left_len]);
    let mut node = [0; 2 * DIGEST_SIZE];
    (&mut node[..DIGEST_SIZE]).copy_from_slice(&left_hash);
    (&mut node[DIGEST_SIZE..]).copy_from_slice(&right_hash);
    let node_hash = hash(&node);
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&node);
    encoded.extend_from_slice(&left_encoded);
    encoded.extend_from_slice(&right_encoded);
    (node_hash, encoded)
}

fn left_side_decoding_len(input_len: usize) -> usize {
    assert!(input_len > CHUNK_SIZE);
    let mut encoded_size = CHUNK_SIZE;
    loop {
        let next_size = 2 * encoded_size + 2 * DIGEST_SIZE;
        if next_size >= input_len {
            return encoded_size;
        }
        encoded_size = next_size;
    }
}

pub fn decode(encoded: &[u8], digest: Digest) -> Result<Vec<u8>, error::Unspecified> {
    if encoded.len() < CHUNK_SIZE {
        return verify(encoded, digest).map(|_| encoded.to_vec());
    }
    unimplemented!()
}

#[cfg(test)]
mod test {
    use super::{hash, verify, left_side_len, left_side_decoding_len, CHUNK_SIZE, DIGEST_SIZE};

    #[test]
    fn test_hash() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            verify(input, hash(input)).unwrap();
        }
    }

    #[test]
    fn test_left_side_len() {
        let cases = &[(CHUNK_SIZE + 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE - 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2, 2 * CHUNK_SIZE)];
        for &case in cases {
            println!("testing {} and {}", case.0, case.1);
            assert_eq!(left_side_len(case.0), case.1);
        }
    }

    #[test]
    fn test_left_side_decoding_len() {
        let cases = &[(CHUNK_SIZE + 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2 * DIGEST_SIZE - 1, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2 * DIGEST_SIZE, CHUNK_SIZE),
                      (2 * CHUNK_SIZE + 2 * DIGEST_SIZE + 1, 2 * CHUNK_SIZE + 2 * DIGEST_SIZE),
                      (4 * CHUNK_SIZE + 6 * DIGEST_SIZE - 1, 2 * CHUNK_SIZE + 2 * DIGEST_SIZE),
                      (4 * CHUNK_SIZE + 6 * DIGEST_SIZE, 2 * CHUNK_SIZE + 2 * DIGEST_SIZE),
                      (4 * CHUNK_SIZE + 6 * DIGEST_SIZE + 1, 4 * CHUNK_SIZE + 6 * DIGEST_SIZE)];
        for &case in cases {
            println!("testing {} and {}", case.0, case.1);
            assert_eq!(left_side_decoding_len(case.0), case.1);
        }
    }
}
