#![feature(test)]

extern crate blake2_c;
extern crate bao;
extern crate test;

use test::Bencher;

const SHORT: &[u8] = b"hello world";
const LONG: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    b.iter(|| {
        let mut state = blake2_c::blake2b::State::new(32);
        state.update(SHORT);
        state.finalize();
    });
}

#[bench]
fn bench_bao_hash_short(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(SHORT);
        state.finalize();
    });
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    b.iter(|| {
        let mut state = blake2_c::blake2b::State::new(32);
        state.update(LONG);
        state.finalize();
    });
}

#[bench]
fn bench_bao_hash_long(b: &mut Bencher) {
    b.iter(|| {
        let mut state = bao::hash::State::new();
        state.update(LONG);
        state.finalize();
    });
}
