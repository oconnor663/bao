#![feature(test)]

extern crate bao;
extern crate blake2b_simd;
extern crate rand;
extern crate tempfile;
extern crate test;

use bao::*;
use rand::prelude::*;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom::Start};
use test::Bencher;

// The tiniest relvant benchmark is one that fills a single BLAKE2b block. But if we don't account
// for the header bytes, we'll actually fill two blocks, and the results will look awful.
const SHORT: usize = blake2b_simd::BLOCKBYTES - hash::HEADER_SIZE;

// Same as short, but for a single chunk of input.
const MEDIUM: usize = hash::CHUNK_SIZE - hash::HEADER_SIZE;

const LONG: usize = 10_000_000;

fn input(b: &mut Bencher, size: usize) -> Vec<u8> {
    b.bytes = size as u64;
    vec![0; size]
}

// Note that because of header byte overhead included above, these raw blake2b() benchmarks aren't
// filling up a full BLOCKBYTES block, and so they appear worse than in the upstream crate. All the
// other benchmarks below will pay the same overhead, so this is the correct comparison.
#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_blake2b_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    let input = input(b, LONG);
    b.iter(|| blake2b_simd::blake2b(&input));
}

#[bench]
fn bench_bao_hash_parallel_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    b.iter(|| hash::hash(&input));
}

#[bench]
fn bench_bao_hash_parallel_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    b.iter(|| hash::hash(&input));
}

#[bench]
fn bench_bao_hash_parallel_long(b: &mut Bencher) {
    let input = input(b, LONG);
    b.iter(|| hash::hash(&input));
}

#[bench]
fn bench_bao_hash_serial_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    b.iter(|| hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_serial_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    b.iter(|| hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_serial_long(b: &mut Bencher) {
    let input = input(b, LONG);
    b.iter(|| hash::hash_single_threaded(&input))
}

#[bench]
fn bench_bao_hash_writer_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_writer_long(b: &mut Bencher) {
    let input = input(b, LONG);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    b.iter(|| {
        let mut writer = hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    b.iter(|| {
        let mut writer = hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_rayonwriter_long(b: &mut Bencher) {
    let input = input(b, LONG);
    b.iter(|| {
        let mut writer = hash::RayonWriter::new();
        writer.write_all(&input).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_encode_parallel_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_parallel_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_serial_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut output = vec![0; encode::encoded_size(input.len() as u64) as usize];
    b.iter(|| encode::encode_single_threaded(&input, &mut output));
}

#[bench]
fn bench_bao_encode_writer_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut output = Vec::with_capacity(encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut output = Vec::with_capacity(encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut output = Vec::with_capacity(encode::encoded_size(input.len() as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(&input).unwrap();
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_decode_parallel_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_parallel_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode(&encoded, &mut output, hash));
}
#[bench]
fn bench_bao_decode_serial_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_serial_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| decode::decode_single_threaded(&encoded, &mut output, hash));
}

#[bench]
fn bench_bao_decode_reader_short(b: &mut Bencher) {
    let input = input(b, SHORT);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_medium(b: &mut Bencher) {
    let input = input(b, MEDIUM);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_long(b: &mut Bencher) {
    let input = input(b, LONG);
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut output = vec![0; input.len()];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_seek_memory_no_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(Cursor::new(&encoded), hash);
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).unwrap();
    });
}

#[bench]
fn bench_bao_seek_memory_one_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);
    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(Cursor::new(&encoded), hash);
    let mut buf = [0];
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).unwrap();
        reader.read(&mut buf).unwrap();
    });
}

#[bench]
fn bench_bao_seek_file_no_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);

    let mut file = tempfile::tempfile().expect("tempfile creation error");
    file.write_all(&encoded).expect("file write error");
    file.flush().expect("file flush error");
    file.seek(Start(0)).expect("file seek error");

    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(file, hash);
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).expect("seek error");
    });
}

#[bench]
fn bench_bao_seek_file_one_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut encoded = Vec::new();
    let hash = encode::encode_to_vec(&input, &mut encoded);

    let mut file = tempfile::tempfile().expect("tempfile creation error");
    file.write_all(&encoded).expect("file write error");
    file.flush().expect("file flush error");
    file.seek(Start(0)).expect("file seek error");

    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(file, hash);
    let mut buf = [0];
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).expect("seek error");
        reader.read(&mut buf).expect("read error");
    });
}

#[bench]
fn bench_raw_seek_file_no_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut file = tempfile::tempfile().expect("tempfile creation error");
    file.write_all(&input).expect("file write error");
    file.flush().expect("file flush error");
    file.seek(Start(0)).expect("file seek error");

    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        file.seek(Start(seek_offset)).expect("seek error");
    });
}

#[bench]
fn bench_raw_seek_file_one_read(b: &mut Bencher) {
    let input = vec![0; LONG];
    let mut file = tempfile::tempfile().expect("tempfile creation error");
    file.write_all(&input).expect("file write error");
    file.flush().expect("file flush error");
    file.seek(Start(0)).expect("file seek error");

    let mut rng = rand::XorShiftRng::from_seed(Default::default());
    let mut buf = [0];
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        file.seek(Start(seek_offset)).expect("seek error");
        file.read(&mut buf).expect("read error");
    });
}
