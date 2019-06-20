extern crate bao;
#[macro_use]
extern crate duct;
extern crate rand;
extern crate tempfile;

use rand::RngCore;
use std::env::consts::EXE_EXTENSION;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Once, ONCE_INIT};
use tempfile::tempdir;

pub fn bao_exe() -> PathBuf {
    // `cargo test` doesn't automatically run `cargo build`, so we do that ourselves.
    static CARGO_BUILD_ONCE: Once = ONCE_INIT;
    CARGO_BUILD_ONCE.call_once(|| {
        cmd!("cargo", "build", "--quiet")
            .run()
            .expect("build failed");
    });

    Path::new("target")
        .join("debug")
        .join("bao")
        .with_extension(EXE_EXTENSION)
}

#[test]
fn test_hash_one() {
    let expected = bao::hash::hash(b"foo").to_hex();
    let output = cmd!(bao_exe(), "hash").input("foo").read().unwrap();
    assert_eq!(&*expected, &*output);
}

#[test]
fn test_hash_many() {
    let dir = tempdir().unwrap();
    let file1 = dir.path().join("file1");
    fs::write(&file1, b"foo").unwrap();
    let file2 = dir.path().join("file2");
    fs::write(&file2, b"bar").unwrap();
    let output = cmd!(bao_exe(), "hash", &file1, &file2, "-")
        .input("baz")
        .read()
        .unwrap();
    let foo_hash = bao::hash::hash(b"foo");
    let bar_hash = bao::hash::hash(b"bar");
    let baz_hash = bao::hash::hash(b"baz");
    let expected = format!(
        "{}  {}\n{}  {}\n{}  -",
        foo_hash.to_hex(),
        file1.to_string_lossy(),
        bar_hash.to_hex(),
        file2.to_string_lossy(),
        baz_hash.to_hex(),
    );
    assert_eq!(expected, output);
}

#[test]
fn test_encode_decode_combined() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input");
    let input_bytes = &b"abc"[..];
    fs::write(&input_path, input_bytes).unwrap();
    let encoded_path = dir.path().join("encoded");
    cmd!(bao_exe(), "encode", &input_path, &encoded_path)
        .run()
        .unwrap();
    let encoded_bytes = fs::read(&encoded_path).unwrap();

    // Test hash --encoded.
    let input_hash = cmd!(bao_exe(), "hash").input(input_bytes).read().unwrap();
    let encoded_hash = cmd!(bao_exe(), "hash", "--encoded", &encoded_path)
        .read()
        .unwrap();
    assert_eq!(input_hash, encoded_hash);

    // Test decode using stdin and stdout.
    let decoded_bytes = cmd!(bao_exe(), "decode", &input_hash)
        .input(encoded_bytes)
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    assert_eq!(input_bytes, &*decoded_bytes);

    // Test decode using files. This exercises memmapping.
    let decoded_path = dir.path().join("decoded");
    cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        &encoded_path,
        &decoded_path
    )
    .run()
    .unwrap();
    assert_eq!(input_bytes, &*decoded_bytes);

    // Test decode using --start and --count. Note that --start requires that the input is a file.
    let partial_output = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        &encoded_path,
        "--start=1",
        "--count=1"
    )
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(input_bytes[1..2], *partial_output);
}

#[test]
fn test_encode_decode_outboard() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input");
    let input_bytes = &b"abc"[..];
    fs::write(&input_path, input_bytes).unwrap();
    let outboard_path = dir.path().join("outboard");
    cmd!(
        bao_exe(),
        "encode",
        &input_path,
        "--outboard",
        &outboard_path
    )
    .run()
    .unwrap();

    // Test hash --outboard.
    let input_hash = cmd!(bao_exe(), "hash").input(input_bytes).read().unwrap();
    let outboard_hash = cmd!(bao_exe(), "hash", &input_path, "--outboard", &outboard_path)
        .read()
        .unwrap();
    assert_eq!(input_hash, outboard_hash);

    // Test decode using stdin and stdout.
    let decoded_bytes = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        "--outboard",
        &outboard_path
    )
    .input(input_bytes)
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(input_bytes, &*decoded_bytes);

    // Test decode using --start and --count. Note that --start requires that the input is a file.
    // (Note that the outboard case is never memmapped, so we don't need a separate test for that.)
    let partial_output = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        &input_path,
        "--outboard",
        &outboard_path,
        "--start=1",
        "--count=1"
    )
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(input_bytes[1..2], *partial_output);
}

#[test]
fn test_slice() {
    let input_len = 1_000_000;
    let slice_start = input_len / 4;
    let slice_len = input_len / 2;

    let mut input = vec![0; input_len];
    rand::thread_rng().fill_bytes(&mut input);
    let dir = tempdir().unwrap();
    let encoded_path = dir.path().join("encoded");
    cmd!(bao_exe(), "encode", "-", &encoded_path)
        .input(&*input)
        .run()
        .unwrap();
    let hash = cmd!(bao_exe(), "hash", "--encoded", &encoded_path)
        .read()
        .unwrap();
    let outboard_path = dir.path().join("outboard");
    cmd!(bao_exe(), "encode", "-", "--outboard", &outboard_path)
        .input(&*input)
        .run()
        .unwrap();
    let outboard_hash = cmd!(bao_exe(), "hash", "--outboard", &outboard_path)
        .read()
        .unwrap();
    assert_eq!(hash, outboard_hash);

    // Do a combined mode slice to a file.
    let slice_path = dir.path().join("slice");
    cmd!(
        bao_exe(),
        "slice",
        slice_start.to_string(),
        slice_len.to_string(),
        &encoded_path,
        &slice_path
    )
    .run()
    .unwrap();
    let slice_bytes = fs::read(&slice_path).unwrap();

    // Make sure the outboard mode gives the same result. Do this one to stdout.
    let outboard_slice_bytes = cmd!(
        bao_exe(),
        "slice",
        slice_start.to_string(),
        slice_len.to_string(),
        &encoded_path
    )
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(slice_bytes, outboard_slice_bytes);
}
