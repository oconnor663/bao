extern crate bao;
extern crate hex;
extern crate memmap;

use std::io;
use std::io::prelude::*;
use std::os::unix::prelude::*;
use std::fs::File;
use hex::ToHex;

fn hash_memmap() -> bao::Hash {
    let file = unsafe { File::from_raw_fd(0) };
    let map = unsafe { memmap::Mmap::map(&file).expect("error creating mmap") };
    std::mem::forget(file);
    bao::hash::hash_parallel(&map)
}

fn hash_memmap_serial() -> bao::Hash {
    let file = unsafe { File::from_raw_fd(0) };
    let map = unsafe { memmap::Mmap::map(&file).expect("error creating mmap") };
    std::mem::forget(file);
    bao::hash::hash(&map)
}

fn hash_state_serial() -> bao::Hash {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut digest = bao::hash::State::new();
    let mut read_buffer = [0; 65536];
    loop {
        let n = stdin_lock.read(&mut read_buffer).expect("read error");
        if n == 0 {
            break; // EOF
        }
        digest.update(&read_buffer[..n]);
    }
    digest.finalize()
}

fn hash_state_parallel() -> bao::Hash {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut digest = bao::hash::StateParallel::new();
    let mut read_buffer = [0; 65536];
    loop {
        let n = stdin_lock.read(&mut read_buffer).expect("read error");
        if n == 0 {
            break; // EOF
        }
        digest.update(&read_buffer[..n]);
    }
    digest.finalize()
}

fn main() {
    let arg = std::env::args().skip(1).next().unwrap();
    let hash = match &*arg {
        "memmap" => hash_memmap(),
        "memmap_serial" => hash_memmap_serial(),
        "serial" => hash_state_serial(),
        "parallel" => hash_state_parallel(),
        _ => panic!("unknown arg"),
    };
    println!("{}", hash.to_hex());
}
