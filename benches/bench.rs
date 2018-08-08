#![feature(test)]

extern crate bao;
extern crate blake2_c;
extern crate test;

use std::io::prelude::*;
use test::Bencher;

const SHORT: &[u8] = b"hello world";
const MEDIUM: &[u8] = &[0; 4096 * 4 + 1];
const LONG: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    b.iter(|| blake2_c::blake2b_256(SHORT));
}

#[bench]
fn bench_blake2b_medium(b: &mut Bencher) {
    b.iter(|| blake2_c::blake2b_256(MEDIUM));
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    b.iter(|| blake2_c::blake2b_256(LONG));
}

#[bench]
fn bench_bao_hash_short(b: &mut Bencher) {
    b.iter(|| bao::hash::hash(SHORT));
}

#[bench]
fn bench_bao_hash_medium(b: &mut Bencher) {
    b.iter(|| bao::hash::hash(MEDIUM));
}

#[bench]
fn bench_bao_hash_long(b: &mut Bencher) {
    b.iter(|| bao::hash::hash(LONG));
}

fn hash_serial(input: &[u8]) -> bao::hash::Hash {
    bao::hash::hash_recurse(input, bao::hash::Finalization::Root(input.len() as u64))
}

#[bench]
fn bench_bao_hash_serial_short(b: &mut Bencher) {
    b.iter(|| hash_serial(SHORT))
}

#[bench]
fn bench_bao_hash_serial_medium(b: &mut Bencher) {
    b.iter(|| hash_serial(MEDIUM))
}

#[bench]
fn bench_bao_hash_serial_long(b: &mut Bencher) {
    b.iter(|| hash_serial(LONG))
}

#[bench]
fn bench_bao_hash_writer_short(b: &mut Bencher) {
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(SHORT).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_medium(b: &mut Bencher) {
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(MEDIUM).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_long(b: &mut Bencher) {
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(LONG).unwrap();
        writer.finish()
    });
}
