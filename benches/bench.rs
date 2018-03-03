#![feature(test)]

extern crate bao;
extern crate blake2_c;
extern crate test;

use test::Bencher;

const SHORT: &[u8] = b"hello world";
const LONG: &[u8] = &[0; 1_000_000];

#[bench]
fn bench_blake2b_short(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(SHORT);
    });
}

#[bench]
fn bench_blake2b_long(b: &mut Bencher) {
    b.iter(|| {
        blake2_c::blake2b_256(LONG);
    });
}

#[bench]
fn bench_bao_hash_short(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(SHORT);
    });
}

#[bench]
fn bench_bao_hash_long(b: &mut Bencher) {
    b.iter(|| {
        bao::hash::hash(LONG);
    });
}

#[bench]
fn bench_bao_hash_parallel1_short(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel1::hash(SHORT);
    });
}

#[bench]
fn bench_bao_hash_parallel1_long(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel1::hash(LONG);
    });
}

#[bench]
fn bench_bao_hash_parallel2_short(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel2::hash(SHORT);
    });
}

#[bench]
fn bench_bao_hash_parallel2_long(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel2::hash(LONG);
    });
}

#[bench]
fn bench_bao_hash_parallel3_short(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel3::hash(SHORT);
    });
}

#[bench]
fn bench_bao_hash_parallel3_long(b: &mut Bencher) {
    b.iter(|| {
        bao::hash_parallel3::hash(LONG);
    });
}

#[bench]
fn bench_bao_encode_simple_short(b: &mut Bencher) {
    b.iter(|| {
        bao::simple::encode(SHORT);
    });
}

#[bench]
fn bench_bao_encode_simple_long(b: &mut Bencher) {
    b.iter(|| {
        bao::simple::encode(LONG);
    });
}

#[bench]
fn bench_bao_decode_simple_short(b: &mut Bencher) {
    let (encoded, hash) = bao::simple::encode(SHORT);
    b.iter(|| {
        bao::simple::decode(&encoded, &hash).unwrap();
    });
}

#[bench]
fn bench_bao_decode_simple_long(b: &mut Bencher) {
    let (encoded, hash) = bao::simple::encode(LONG);
    b.iter(|| {
        bao::simple::decode(&encoded, &hash).unwrap();
    });
}
