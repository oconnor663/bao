extern crate rad;
extern crate hex;
#[macro_use]
extern crate arrayref;

use hex::FromHex;

use std::env::args;
use std::io::{copy, stdin, stdout};
use rad::io::Reader;

fn main() {
    let hex_hash = args().skip(1).next();
    if hex_hash.is_none() {
        eprintln!("encode must have a hash argument");
        std::process::exit(1)
    };
    let hash_vec = Vec::from_hex(hex_hash.unwrap().as_bytes()).expect("valid hex");
    if hash_vec.len() != rad::DIGEST_SIZE {
        eprintln!(
            "hash must be {} bytes, got {}",
            rad::DIGEST_SIZE,
            hash_vec.len()
        );
        std::process::exit(1)
    };
    let hash = *array_ref!(&hash_vec, 0, rad::DIGEST_SIZE);
    let mut reader = Reader::new(stdin(), &hash);
    copy(&mut reader, &mut stdout()).unwrap();
}
