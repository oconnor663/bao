extern crate rad;
extern crate hex;

use hex::ToHex;

use std::env::args_os;
use std::fs::OpenOptions;
use std::io::{copy, stdin};
use rad::io::Encoder;

fn main() {
    let filename = args_os().skip(1).next();
    if filename.is_none() {
        eprintln!("encode must have a filename argument");
        std::process::exit(1)
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(filename.unwrap())
        .expect("error opening file");
    let mut encoder = Encoder::new(file);
    copy(&mut stdin(), &mut encoder).unwrap();
    let hash = encoder.finish().unwrap();
    println!("{}", hash.to_hex());
}
