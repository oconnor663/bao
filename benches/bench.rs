#![feature(test)]

extern crate bao;
extern crate blake2b_simd;
extern crate test;

use std::io::prelude::*;
use std::io::Cursor;
use test::Bencher;

const SHORT: usize = 128; // one BLAKE2b block
const MEDIUM: usize = 4096; // one chunk
const LONG: usize = 1_000_000; // one MB

#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_blake2b_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_bao_hash_parallel_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash(&input));
}

#[bench]
fn bench_bao_hash_parallel_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash(&input));
}

#[bench]
fn bench_bao_hash_parallel_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash(&input));
}

#[bench]
fn bench_bao_hash_serial_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_serial_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_serial_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    b.iter(|| bao::hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_writer_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    b.iter(|| {
        let mut writer = bao::hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_encode_parallel_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut output = vec![0; bao::encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| bao::encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_writer_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut output = Vec::with_capacity(bao::encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = bao::encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_decode_parallel_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode(&encoded, &mut output, hash));
}
#[bench]
fn bench_bao_decode_serial_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| bao::decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_reader_short(b: &mut Bencher) {
    let input = vec![0; SHORT];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_medium(b: &mut Bencher) {
    let input = vec![0; MEDIUM];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_long(b: &mut Bencher) {
    let input = vec![0; LONG];
    b.bytes = input.len() as u64;
    let mut encoded = Vec::new();
    let hash = bao::encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = bao::decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}
