#![feature(test)]

extern crate test;

use bao::*;
use rand::prelude::*;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom::Start};
use test::Bencher;

// The tiniest relvant benchmark is one that fills a single BLAKE2s block. But if we don't account
// for the header bytes, we'll actually fill two blocks, and the results will look awful.
const SHORT: usize = blake2s_simd::BLOCKBYTES - hash::benchmarks::HEADER_SIZE;

// Same as short, but for a single chunk of input.
const MEDIUM: usize = hash::benchmarks::CHUNK_SIZE - hash::benchmarks::HEADER_SIZE;

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

// Note that because of header byte overhead included above, these raw blake2s() benchmarks aren't
// filling up a full BLOCKBYTES block, and so they appear worse than in the upstream crate. All the
// other benchmarks below will pay the same overhead, so this is the correct comparison.
#[bench]
fn bench_blake2s_whole_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    b.iter(|| blake2s_simd::blake2s(input.get()));
}

#[bench]
fn bench_blake2s_whole_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    b.iter(|| blake2s_simd::blake2s(input.get()));
}

#[bench]
fn bench_blake2s_whole_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    b.iter(|| blake2s_simd::blake2s(input.get()));
}

fn hash_chunks(mut len: usize) {
    // If there are N chunks, there are N-1 parent nodes. Also the last chunk has the header
    // appended. This is all overhead that needs to be accounted for, when we want to see whether
    // our state management is adding anything on top.
    let chunk = [0; hash::benchmarks::CHUNK_SIZE];
    while len > hash::benchmarks::CHUNK_SIZE {
        let mut chunk_state = blake2s_simd::State::new();
        chunk_state.update(&chunk);
        test::black_box(chunk_state.finalize());
        let mut parent_state = blake2s_simd::State::new();
        parent_state.update(&[0; 2 * hash::HASH_SIZE]);
        test::black_box(parent_state.finalize());
        len -= chunk.len();
    }
    let mut chunk_state = blake2s_simd::State::new();
    chunk_state.update(&chunk[..len]);
    chunk_state.update(&[0; hash::benchmarks::HEADER_SIZE]);
    test::black_box(chunk_state.finalize());
}

#[bench]
fn bench_blake2s_chunks_short(b: &mut Bencher) {
    b.bytes = SHORT as u64;
    b.iter(|| hash_chunks(SHORT));
}

#[bench]
fn bench_blake2s_chunks_medium(b: &mut Bencher) {
    b.bytes = MEDIUM as u64;
    b.iter(|| hash_chunks(MEDIUM));
}

#[bench]
fn bench_blake2s_chunks_long(b: &mut Bencher) {
    b.bytes = LONG as u64;
    b.iter(|| hash_chunks(LONG));
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
fn bench_bao_hash_serial_writer_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_serial_writer_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_serial_writer_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    b.iter(|| {
        let mut writer = hash::Writer::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_parallel_writer_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    b.iter(|| {
        let mut writer = hash::ParallelWriter::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_parallel_writer_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    b.iter(|| {
        let mut writer = hash::ParallelWriter::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_hash_parallel_writer_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    b.iter(|| {
        let mut writer = hash::ParallelWriter::new();
        writer.write_all(input.get()).unwrap();
        writer.finish()
    });
}

#[bench]
fn bench_bao_encode_slice_combined_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    let mut output = vec![0; encode::encoded_size(SHORT as u64) as usize];
    b.iter(|| encode::encode(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_combined_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    let mut output = vec![0; encode::encoded_size(MEDIUM as u64) as usize];
    b.iter(|| encode::encode(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_combined_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    let mut output = vec![0; encode::encoded_size(LONG as u64) as usize];
    b.iter(|| encode::encode(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_outboard_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    let mut output = vec![0; encode::outboard_size(SHORT as u64) as usize];
    b.iter(|| encode::encode_outboard(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_outboard_medium(b: &mut Bencher) {
    let mut input = RandomInput::new(b, MEDIUM);
    let mut output = vec![0; encode::outboard_size(MEDIUM as u64) as usize];
    b.iter(|| encode::encode_outboard(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_outboard_long(b: &mut Bencher) {
    let mut input = RandomInput::new(b, LONG);
    let mut output = vec![0; encode::outboard_size(LONG as u64) as usize];
    b.iter(|| encode::encode_outboard(input.get(), &mut output));
}

#[bench]
fn bench_bao_encode_slice_in_place_short(b: &mut Bencher) {
    let mut buf = RandomInput::new(b, SHORT).get().to_vec();
    let content_len = buf.len();
    buf.resize(encode::encoded_size(content_len as u64) as usize, 0);
    // Repeatedly encode the same input. It'll give a different result every
    // time, but all we care about here it the performance.
    b.iter(|| encode::encode_in_place(&mut buf, content_len));
}

#[bench]
fn bench_bao_encode_slice_in_place_medium(b: &mut Bencher) {
    let mut buf = RandomInput::new(b, MEDIUM).get().to_vec();
    let content_len = buf.len();
    buf.resize(encode::encoded_size(content_len as u64) as usize, 0);
    // Repeatedly encode the same input. It'll give a different result every
    // time, but all we care about here it the performance.
    b.iter(|| encode::encode_in_place(&mut buf, content_len));
}

#[bench]
fn bench_bao_encode_slice_in_place_long(b: &mut Bencher) {
    let mut buf = RandomInput::new(b, LONG).get().to_vec();
    let content_len = buf.len();
    buf.resize(encode::encoded_size(content_len as u64) as usize, 0);
    // Repeatedly encode the same input. It'll give a different result every
    // time, but all we care about here it the performance.
    b.iter(|| encode::encode_in_place(&mut buf, content_len));
}

#[bench]
fn bench_bao_encode_writer_combined_short(b: &mut Bencher) {
    let mut input = RandomInput::new(b, SHORT);
    let mut output = Vec::with_capacity(encode::encoded_size(SHORT as u64) as usize);
    b.iter(|| {
        output.clear();
        let mut writer = encode::Writer::new(Cursor::new(&mut output));
        writer.write_all(input.get()).unwrap();
        writer.finish().unwrap()
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
        writer.finish().unwrap()
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
        writer.finish().unwrap()
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
        writer.finish().unwrap()
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
        writer.finish().unwrap()
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
        writer.finish().unwrap()
    });
}

#[bench]
fn bench_bao_decode_slice_combined_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; SHORT];
    b.iter(|| decode::decode(&encoded, &mut output, &hash));
}

#[bench]
fn bench_bao_decode_slice_combined_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; MEDIUM];
    b.iter(|| decode::decode(&encoded, &mut output, &hash));
}

#[bench]
fn bench_bao_decode_slice_combined_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; LONG];
    b.iter(|| decode::decode(&encoded, &mut output, &hash));
}

#[bench]
fn bench_bao_decode_slice_in_place_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    // For the purposes of this benchmark, we use a tweaked version of
    // decode_in_place that doesn't actually trash the input.
    let mut fake_buf = encoded.clone();
    b.iter(|| {
        decode::benchmarks::decode_in_place_fake(&encoded, &hash, &mut fake_buf).unwrap();
    });
}

#[bench]
fn bench_bao_decode_slice_in_place_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    // For the purposes of this benchmark, we use a tweaked version of
    // decode_in_place that doesn't actually trash the input.
    let mut fake_buf = encoded.clone();
    b.iter(|| {
        decode::benchmarks::decode_in_place_fake(&encoded, &hash, &mut fake_buf).unwrap();
    });
}

#[bench]
fn bench_bao_decode_slice_in_place_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    // For the purposes of this benchmark, we use a tweaked version of
    // decode_in_place that doesn't actually trash the input.
    let mut fake_buf = encoded.clone();
    b.iter(|| {
        decode::benchmarks::decode_in_place_fake(&encoded, &hash, &mut fake_buf).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_combined_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; SHORT];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_combined_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; MEDIUM];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_combined_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (hash, encoded) = encode::encode_to_vec(&input);
    let mut output = vec![0; LONG];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new(&*encoded, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_short(b: &mut Bencher) {
    let input = RandomInput::new(b, SHORT).get().to_vec();
    let (hash, outboard) = encode::encode_outboard_to_vec(&input);
    let mut output = vec![0; SHORT];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_medium(b: &mut Bencher) {
    let input = RandomInput::new(b, MEDIUM).get().to_vec();
    let (hash, outboard) = encode::encode_outboard_to_vec(&input);
    let mut output = vec![0; MEDIUM];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_decode_reader_outboard_long(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    let (hash, outboard) = encode::encode_outboard_to_vec(&input);
    let mut output = vec![0; LONG];
    b.iter(|| {
        output.clear();
        let mut decoder = decode::Reader::new_outboard(&*input, &*outboard, &hash);
        decoder.read_to_end(&mut output).unwrap();
    });
}

#[bench]
fn bench_bao_seek_memory(b: &mut Bencher) {
    let input = RandomInput::new(b, LONG).get().to_vec();
    b.bytes = 0;
    let (hash, encoded) = encode::encode_to_vec(&input);
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
    let (hash, encoded) = encode::encode_to_vec(&input);

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
