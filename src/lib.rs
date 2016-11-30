#[macro_use]
extern crate arrayref;
extern crate ring;

use ring::{constant_time, digest, error};

pub const CHUNK_SIZE: usize = 4096;
pub const DIGEST_SIZE: usize = 32;

pub type Digest = [u8; DIGEST_SIZE];

fn hash(input: &[u8]) -> Digest {
    // First 32 bytes of SHA512. (The same as NaCl's crypto_hash.)
    let digest = digest::digest(&digest::SHA512, input);
    let mut ret = [0; DIGEST_SIZE];
    (&mut ret[..DIGEST_SIZE]).copy_from_slice(&digest.as_ref()[..DIGEST_SIZE]);
    ret
}

fn verify(input: &[u8], digest: &Digest) -> Result<(), error::Unspecified> {
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
    let (right_hash, right_encoded) = encode(&input[left_len..]);
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

pub fn decode(encoded: &[u8], digest: &Digest) -> Result<Vec<u8>, error::Unspecified> {
    if encoded.len() <= CHUNK_SIZE {
        return verify(encoded, digest).map(|_| encoded.to_vec());
    }
    verify(&encoded[..2 * DIGEST_SIZE], digest)?;
    let left_digest = array_ref![encoded, 0, DIGEST_SIZE];
    let right_digest = array_ref![encoded, DIGEST_SIZE, DIGEST_SIZE];
    let left_start = 2 * DIGEST_SIZE;
    let left_end = left_start + left_side_decoding_len(encoded.len());
    let mut left_plaintext = decode(&encoded[left_start..left_end], left_digest)?;
    let right_plaintext = decode(&encoded[left_end..], right_digest)?;
    left_plaintext.extend_from_slice(&right_plaintext);
    Ok(left_plaintext)
}

#[cfg(test)]
mod test {
    use std::cmp::min;
    use super::*;
    use super::{hash, verify, left_side_len, left_side_decoding_len};

    fn debug_sample(input: &[u8]) -> String {
        let sample_len = min(60, input.len());
        let mut ret = String::from_utf8_lossy(&input[..sample_len]).into_owned();
        if sample_len < input.len() {
            ret += &*format!("... (len {})", input.len());
        }
        ret
    }

    #[test]
    fn test_hash() {
        let inputs: &[&[u8]] = &[b"", b"f", b"foo"];
        for input in inputs {
            verify(input, &hash(input)).unwrap();
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

    #[test]
    fn test_decode() {
        fn one(input: &[u8]) {
            println!("input: {:?}", debug_sample(input));
            let (digest, encoded) = encode(input);
            let output = decode(&encoded, &digest).expect("decode failed");
            assert_eq!(input.len(),
                       output.len(),
                       "input and output lengths don't match");
            assert_eq!(input, &*output, "input and output data doesn't match");
            println!("DONE!!!");
        }

        one(b"");

        one(b"foo");

        one(&vec![0; CHUNK_SIZE - 1]);
        one(&vec![0; CHUNK_SIZE]);
        one(&vec![0; CHUNK_SIZE + 1]);

        const BIGGER: usize = 2 * CHUNK_SIZE + 2 * DIGEST_SIZE;
        one(&vec![0; BIGGER - 1]);
        one(&vec![0; BIGGER]);
        one(&vec![0; BIGGER + 1]);

        const BIGGEST: usize = 2 * BIGGER + 2 * DIGEST_SIZE;
        one(&vec![0; BIGGEST - 1]);
        one(&vec![0; BIGGEST]);
        one(&vec![0; BIGGEST + 1]);
    }
}
