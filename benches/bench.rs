#![feature(test)]

extern crate blake2_c;
extern crate bao;
extern crate test;

use test::Bencher;

const ZERO: &[u8] = b"";
const ONECHUNK: &[u8] = &[0; bao::CHUNK_SIZE];
const ONECHUNKPLUS: &[u8] = &[0; bao::CHUNK_SIZE + 1];
const MEGABYTE: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_zero(b: &mut Bencher) {
    b.iter(|| { blake2_c::blake2b_256(ZERO); });
}

#[bench]
fn bench_blake2b_one_chunk(b: &mut Bencher) {
    b.iter(|| { blake2_c::blake2b_256(ONECHUNK); });
}

#[bench]
fn bench_blake2b_one_chunk_plus(b: &mut Bencher) {
    b.iter(|| { blake2_c::blake2b_256(ONECHUNKPLUS); });
}

#[bench]
fn bench_blake2b_megabyte(b: &mut Bencher) {
    b.iter(|| { blake2_c::blake2b_256(MEGABYTE); });
}

#[bench]
fn bench_bao_recursive_zero(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash(ZERO); });
}

#[bench]
fn bench_bao_recursive_one_chunk(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash(ONECHUNK); });
}

#[bench]
fn bench_bao_recursive_one_chunk_plus(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash(ONECHUNKPLUS); });
}

#[bench]
fn bench_bao_recursive_megabyes(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash(MEGABYTE); });
}

#[bench]
fn bench_bao_parallel_zero(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash_parallel(ZERO); });
}

#[bench]
fn bench_bao_parallel_one_chunk(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash_parallel(ONECHUNK); });
}

#[bench]
fn bench_bao_parallel_one_chunk_plus(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash_parallel(ONECHUNKPLUS); });
}

#[bench]
fn bench_bao_parallel_megabyes(b: &mut Bencher) {
    b.iter(|| { bao::hash::hash_parallel(MEGABYTE); });
}

#[bench]
fn bench_bao_state_zero(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        // No update with zero bytes of input.
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_one_chunk(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(ONECHUNK);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_one_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(ONECHUNKPLUS);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_megabyes(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(MEGABYTE);
        state.finalize();
    });
}
