//! The tests in this file run bao against the standard set of test vectors.

extern crate bao;
extern crate blake2b_simd;
extern crate byteorder;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use byteorder::{ByteOrder, LittleEndian};
use std::cmp;

lazy_static! {
    static ref TEST_VECTORS: TestVectors =
        serde_json::from_str(include_str!("test_vectors.json")).unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
struct TestVectors {
    hash: Vec<HashTest>,
    encode: Vec<EncodeTest>,
    outboard: Vec<OutboardTest>,
    seek: Vec<SeekTest>,
    slice: Vec<SliceTest>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HashTest {
    input_len: usize,
    bao_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncodeTest {
    input_len: usize,
    output_len: usize,
    bao_hash: String,
    encoded_blake2b: String,
    corruptions: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OutboardTest {
    input_len: usize,
    output_len: usize,
    bao_hash: String,
    encoded_blake2b: String,
    outboard_corruptions: Vec<usize>,
    input_corruptions: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SeekTest {
    input_len: usize,
    seek_offsets: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SliceTest {
    input_len: usize,
    bao_hash: String,
    slices: Vec<SliceTestSlice>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SliceTestSlice {
    start: usize,
    len: usize,
    output_len: usize,
    output_blake2b: String,
    corruptions: Vec<usize>,
}

fn make_input(len: usize) -> Vec<u8> {
    let mut counter: u32 = 1;
    let mut output = Vec::with_capacity(len);
    while output.len() < len {
        let mut bytes = [0; 4];
        LittleEndian::write_u32(&mut bytes, counter);
        let take = cmp::min(4, len - output.len());
        output.extend_from_slice(&bytes[..take]);
        counter += 1;
    }
    output
}

fn blake2b(bytes: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(16)
        .to_state()
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

#[test]
fn test_hash_vectors() {
    for case in &TEST_VECTORS.hash {
        let input = make_input(case.input_len);
        let hash = bao::hash::hash(&input);
        assert_eq!(case.bao_hash, hex::encode(&hash));
    }
}

#[test]
fn test_encode_vectors() {
    for case in &TEST_VECTORS.encode {
        let input = make_input(case.input_len);
        let (_, encoded) = bao::encode::encode_to_vec(&input);

        // Make sure the encoded output is what it's supposed to be.
        assert_eq!(case.encoded_blake2b, blake2b(&encoded));

        // Test getting the hash from the encoding. TODO: other implementations too
        let hash = bao::decode::hash_from_encoded(&mut &*encoded).unwrap();
        assert_eq!(case.bao_hash, hex::encode(&hash));

        // Test decoding. TODO: other implementations too
        let output = bao::decode::decode_to_vec(&encoded, &hash).unwrap();
        assert_eq!(input, output);

        // Make sure decoding with a bad hash fails.
        let mut bad_hash = hash;
        bad_hash[0] ^= 1;
        let err = bao::decode::decode_to_vec(&encoded, &bad_hash).unwrap_err();
        assert_eq!(bao::decode::Error::HashMismatch, err);

        // Make sure each corruption point fails the decode.
        for &point in &case.corruptions {
            let mut corrupt = encoded.clone();
            corrupt[point] ^= 1;
            bao::decode::decode_to_vec(&corrupt, &hash).unwrap_err();
            // The error can be either HashMismatch or Truncated, depending on whether the header
            // was corrupted.
        }
    }
}
