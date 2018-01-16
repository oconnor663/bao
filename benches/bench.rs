#![feature(test)]

extern crate bao;
extern crate blake2_c;
extern crate test;

use test::Bencher;

const ZERO: &[u8] = b"";
const TWOCHUNKS: &[u8] = &[0; 2 * bao::CHUNK_SIZE];
const TWOCHUNKSPLUS: &[u8] = &[0; 2 * bao::CHUNK_SIZE + 1];
const MEGABYTE: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_zero(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(ZERO);
    });
}

#[bench]
fn bench_blake2b_two_chunk(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(TWOCHUNKS);
    });
}

#[bench]
fn bench_blake2b_two_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(TWOCHUNKSPLUS);
    });
}

#[bench]
fn bench_blake2b_megabyte(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(MEGABYTE);
    });
}

#[bench]
fn bench_bao_recursive_serial_zero(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(ZERO);
    });
}

#[bench]
fn bench_bao_recursive_serial_two_chunk(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(TWOCHUNKS);
    });
}

#[bench]
fn bench_bao_recursive_serial_two_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(TWOCHUNKSPLUS);
    });
}

#[bench]
fn bench_bao_recursive_serial_megabyes(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(MEGABYTE);
    });
}

#[bench]
fn bench_bao_recursive_parallel_zero(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash_parallel(ZERO);
    });
}

#[bench]
fn bench_bao_recursive_parallel_two_chunk(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash_parallel(TWOCHUNKS);
    });
}

#[bench]
fn bench_bao_recursive_parallel_two_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash_parallel(TWOCHUNKSPLUS);
    });
}

#[bench]
fn bench_bao_recursive_parallel_megabyes(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash_parallel(MEGABYTE);
    });
}

#[bench]
fn bench_bao_state_serial_zero(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        // No update with zero bytes of input.
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_serial_two_chunk(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(TWOCHUNKS);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_serial_two_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(TWOCHUNKSPLUS);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_serial_megabyes(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(MEGABYTE);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_parallel_zero(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::StateParallel::new();
        // No update with zero bytes of input.
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_parallel_two_chunk(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::StateParallel::new();
        state.update(TWOCHUNKS);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_parallel_two_chunk_plus(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::StateParallel::new();
        state.update(TWOCHUNKSPLUS);
        state.finalize();
    });
}

#[bench]
fn bench_bao_state_parallel_megabyes(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::StateParallel::new();
        state.update(MEGABYTE);
        state.finalize();
    });
}
