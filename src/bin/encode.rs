extern crate rad;

use std::env::args_os;
use std::fs::OpenOptions;
use std::io::{copy, stdin};
use rad::io::Encoder;

fn main() {
    let filename = args_os().skip(1).next().expect("need a filename argument");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(filename)
        .expect("error opening file");
    let mut encoder = Encoder::new(file);
    copy(&mut stdin(), &mut encoder).unwrap();
}
