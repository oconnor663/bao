#![feature(test)]

extern crate test;

use bao::*;
use rand::prelude::*;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom::Start};
use test::Bencher;

// 64 bytes, just enough input to fill a single BLAKE2s block.
const SHORT: usize = blake2s_simd::BLOCKBYTES;

// Just enough input to occupy SIMD on a single thread. Currently 32 KiB on x86.
const MEDIUM: usize = hash::benchmarks::CHUNK_SIZE * blake2s_simd::many::MAX_DEGREE;

const LONG: usize = 1 << 24; // about 17 MB

// This struct randomizes two things:
// 1. The actual bytes of input.
// 2. The page offset the input starts at.
pub struct RandomInput {
    buf: Vec<u8>,
    len: usize,
    offsets: Vec<usize>,
    offset_index: usize,
}

impl RandomInput {
    pub fn new(b: &mut Bencher, len: usize) -> Self {
        b.bytes += len as u64;
        let page_size: usize = page_size::get();
        let mut buf = vec![0u8; len + page_size];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut buf);
        let mut offsets: Vec<usize> = (0..page_size).collect();
        offsets.shuffle(&mut rng);
        Self {
            buf,
            len,
            offsets,
            offset_index: 0,
        }
    }

    pub fn get(&mut self) -> &[u8] {
        let offset = self.offsets[self.offset_index];
        self.offset_index += 1;
        if self.offset_index >= self.offsets.len() {
            self.offset_index = 0;
        }
        &self.buf[offset..][..self.len]
    }
}

#[bench]
fn bench_bao_hash_slice_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    b.iter(|| hash::hash(input.get()));
}

#[bench]
fn bench_bao_hash_slice_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    b.iter(|| hash::hash(input.get()));
}

#[bench]
fn bench_bao_hash_slice_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    b.iter(|| hash::hash(input.get()));
}

#[bench]
fn bench_bao_hash_writer_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finalize()
    });
}

#[bench]
fn bench_bao_hash_writer_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finalize()
    });
}

#[bench]
fn bench_bao_hash_writer_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finalize()
    });
}

#[bench]
fn bench_bao_encode_writer_combined_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    let mut output = Vec::with_capacity(encode::encoded_size(SHORT as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_combined_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    let mut output = Vec::with_capacity(encode::encoded_size(MEDIUM as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_combined_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    let mut output = Vec::with_capacity(encode::encoded_size(LONG as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_outboard_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    let mut output = Vec::with_capacity(encode::outboard_size(SHORT as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new_outboard(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_outboard_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    let mut output = Vec::with_capacity(encode::outboard_size(MEDIUM as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new_outboard(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encode_writer_outboard_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    let mut output = Vec::with_capacity(encode::outboard_size(LONG as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new_outboard(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_decode_reader_combined_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decode_reader_combined_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decode_reader_combined_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; hash::BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_seek_memory(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    b.bytes = 0;
    let (encoded, hash) = encode::encode(&input);
    let mut rng = rand_xorshift::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(Cursor::new(&encoded), &hash);
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).unwrap();
    });
}

#[bench]
fn bench_bao_seek_file(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    b.bytes = 0;
    let (encoded, hash) = encode::encode(&input);

    let mut file = tempfile::tempfile().expect("tempfile creation error");
    file.write_all(&encoded).expect("file write error");
    file.flush().expect("file flush error");
    file.seek(Start(0)).expect("file seek error");

    let mut rng = rand_xorshift::XorShiftRng::from_seed(Default::default());
    let mut reader = decode::Reader::new(file, &hash);
    b.iter(|| {
        let seek_offset = rng.gen_range(0, input.len() as u64);
        reader.seek(Start(seek_offset)).expect("seek error");
    });
}
