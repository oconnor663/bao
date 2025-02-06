#![feature(test)]

extern crate test;

use bao::{decode, encode};
use rand::prelude::*;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom::Start};
use test::Bencher;

// one block
const SHORT: usize = 64;

// enough to use AVX-512
const MEDIUM: usize = 16384;

// about 17 MB
const LONG: usize = 1 << 24;

const BUF_SIZE: usize = 16384;

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
        let mut rng = rand::rng();
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
fn bench_bao_encoder_combined_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::encoded_size(SHORT as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encoder_combined_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::encoded_size(MEDIUM as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encoder_combined_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::encoded_size(LONG as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encoder_outboard_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::outboard_size(SHORT as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new_outboard(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encoder_outboard_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::outboard_size(MEDIUM as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new_outboard(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_encoder_outboard_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, BUF_SIZE);
    let mut output = Vec::with_capacity(encode::outboard_size(LONG as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut encoder = encode::Encoder::new_outboard(Cursor::new(&mut output));
        encoder.write_all(input.get()).unwrap();
        encoder.finalize().unwrap()
    });
}

#[bench]
fn bench_bao_decoder_combined_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decoder_combined_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decoder_combined_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (encoded, hash) = encode::encode(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new(&*encoded, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decoder_outboard_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decoder_outboard_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_decoder_outboard_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (outboard, hash) = encode::outboard(&input);
    let mut output = [1; BUF_SIZE];
    b.iter(|| {
        let mut decoder = decode::Decoder::new_outboard(&*input, &*outboard, &hash);
        while decoder.read(&mut output).unwrap() > 0 {}
    });
}

#[bench]
fn bench_bao_seek_memory(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    b.bytes = 0;
    let (encoded, hash) = encode::encode(&input);
    let mut rng = rand_xorshift::XorShiftRng::from_seed(Default::default());
    let mut decoder = decode::Decoder::new(Cursor::new(&encoded), &hash);
    b.iter(|| {
        let seek_offset = rng.random_range(0..input.len() as u64);
        decoder.seek(Start(seek_offset)).unwrap();
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
    let mut decoder = decode::Decoder::new(file, &hash);
    b.iter(|| {
        let seek_offset = rng.random_range(0..input.len() as u64);
        decoder.seek(Start(seek_offset)).expect("seek error");
    });
}
