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

#[bench]
fn bench_bao_hash_serial_short(b: &mut Bencher) {
    b.iter(|| bao::hash::hash_single_threaded(SHORT))
}

#[bench]
fn bench_bao_hash_serial_medium(b: &mut Bencher) {
    b.iter(|| bao::hash::hash_single_threaded(MEDIUM))
}

#[bench]
fn bench_bao_hash_serial_long(b: &mut Bencher) {
    b.iter(|| bao::hash::hash_single_threaded(LONG))
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

fn output_vec(input: &[u8]) -> Vec<u8> {
    vec![0; bao::encode::encoded_size(input.len() as u64) as usize]
}

#[bench]
fn bench_bao_encode_short(b: &mut Bencher) {
    let mut output = output_vec(SHORT);
    b.iter(|| bao::encode::encode(SHORT, &mut output));
}

#[bench]
fn bench_bao_encode_medium(b: &mut Bencher) {
    let mut output = output_vec(MEDIUM);
    b.iter(|| bao::encode::encode(MEDIUM, &mut output));
}

#[bench]
fn bench_bao_encode_long(b: &mut Bencher) {
    let mut output = output_vec(LONG);
    b.iter(|| bao::encode::encode(LONG, &mut output));
}

#[bench]
fn bench_bao_encode_short_serial(b: &mut Bencher) {
    let mut output = output_vec(SHORT);
    b.iter(|| bao::encode::encode_single_threaded(SHORT, &mut output));
}

#[bench]
fn bench_bao_encode_medium_serial(b: &mut Bencher) {
    let mut output = output_vec(MEDIUM);
    b.iter(|| bao::encode::encode_single_threaded(MEDIUM, &mut output));
}

#[bench]
fn bench_bao_encode_long_serial(b: &mut Bencher) {
    let mut output = output_vec(LONG);
    b.iter(|| bao::encode::encode_single_threaded(LONG, &mut output));
}
