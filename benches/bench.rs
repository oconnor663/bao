#![feature(test)]

extern crate bao;
extern crate blake2b_simd;
extern crate test;

use std::io::prelude::*;
use std::io::Cursor;
use test::Bencher;

const SHORT: &[u8] = b"hello world";
const MEDIUM: &[u8] = &[0; 4096 * 4 + 1];
const LONG: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    b.iter(|| blake2b_simd::blake2b(SHORT));
}

#[bench]
fn bench_blake2b_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    b.iter(|| blake2b_simd::blake2b(MEDIUM));
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    b.iter(|| blake2b_simd::blake2b(LONG));
}

#[bench]
fn bench_bao_hash_parallel_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    b.iter(|| bao::hash::hash(SHORT));
}

#[bench]
fn bench_bao_hash_parallel_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    b.iter(|| bao::hash::hash(MEDIUM));
}

#[bench]
fn bench_bao_hash_parallel_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    b.iter(|| bao::hash::hash(LONG));
}

#[bench]
fn bench_bao_hash_serial_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(SHORT))
}

#[bench]
fn bench_bao_hash_serial_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(MEDIUM))
}

#[bench]
fn bench_bao_hash_serial_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(LONG))
}

#[bench]
fn bench_bao_hash_writer_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(SHORT).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(MEDIUM).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(LONG).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(SHORT).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(MEDIUM).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(LONG).unwrap();
        writer.finish()
    });
}

fn output_vec(input: &[u8]) -> Vec<u8> {
    vec![0; bao::encode::encoded_size(input.len() as u64) as usize]
}

#[bench]
fn bench_bao_encode_parallel_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut output = output_vec(SHORT);
    b.iter(|| bao::encode::encode(SHORT, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut output = output_vec(MEDIUM);
    b.iter(|| bao::encode::encode(MEDIUM, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut output = output_vec(LONG);
    b.iter(|| bao::encode::encode(LONG, &mut output));
}

#[bench]
fn bench_bao_encode_serial_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut output = output_vec(SHORT);
    b.iter(|| bao::encode::encode_single_threaded(SHORT, &mut output));
}

#[bench]
fn bench_bao_encode_serial_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut output = output_vec(MEDIUM);
    b.iter(|| bao::encode::encode_single_threaded(MEDIUM, &mut output));
}

#[bench]
fn bench_bao_encode_serial_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut output = output_vec(LONG);
    b.iter(|| bao::encode::encode_single_threaded(LONG, &mut output));
}

#[bench]
fn bench_bao_encode_writer_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(SHORT.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(SHORT).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(MEDIUM.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(MEDIUM).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(LONG.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(LONG).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_decode_parallel_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(SHORT, &mut encoded);
    let mut output = vec![0; SHORT.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(MEDIUM, &mut encoded);
    let mut output = vec![0; MEDIUM.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(LONG, &mut encoded);
    let mut output = vec![0; LONG.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}
#[bench]
fn bench_bao_decode_serial_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(SHORT, &mut encoded);
    let mut output = vec![0; SHORT.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(MEDIUM, &mut encoded);
    let mut output = vec![0; MEDIUM.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(LONG, &mut encoded);
    let mut output = vec![0; LONG.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_reader_short(b: &mut Bencher) {
    b.bytes = SHORT.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(SHORT, &mut encoded);
    let mut output = vec![0; SHORT.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_medium(b: &mut Bencher) {
    b.bytes = MEDIUM.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(MEDIUM, &mut encoded);
    let mut output = vec![0; MEDIUM.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_long(b: &mut Bencher) {
    b.bytes = LONG.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(LONG, &mut encoded);
    let mut output = vec![0; LONG.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}
