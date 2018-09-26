#[macro_use]
extern crate duct;
extern crate rand;
extern crate tempfile;

use rand::RngCore;
use std::env::consts::EXE_EXTENSION;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::{Once, ONCE_INIT};

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
    let output = cmd!(bao_exe(), "hash").input("foo").read().unwrap();
    assert_eq!(
        "81fcbc391ab46bfb6a0c68393c0c48a55abc6d6e6cd6705447bc7c2ae67e5946",
        output
    );
}

#[test]
fn test_hash_many() {
    let mut file1 = tempfile::NamedTempFile::new().unwrap();
    file1.write_all(b"foo").unwrap();
    file1.flush().unwrap();
    let mut file2 = tempfile::NamedTempFile::new().unwrap();
    file2.write_all(b"bar").unwrap();
    file2.flush().unwrap();
    let output = cmd!(bao_exe(), "hash", file1.path(), file2.path(), "-")
        .input("baz")
        .read()
        .unwrap();
    let expected = format!(
        "\
81fcbc391ab46bfb6a0c68393c0c48a55abc6d6e6cd6705447bc7c2ae67e5946  {}
86cb1ecbc885b22862b5800f86d5f5588eaef9c7b967287ef4596e526ee06e65  {}
d99e7ff490091c550718f89a6046974ec84a0bcc4d9c393f32eb9e7afa4146a0  -",
        file1.path().to_string_lossy(),
        file2.path().to_string_lossy()
    );
    assert_eq!(expected, output);
}

#[test]
fn test_encode_decode_combined() {
    let input_bytes = &b"abc"[..];
    let mut input_file = tempfile::NamedTempFile::new().unwrap();
    input_file.write_all(input_bytes).unwrap();
    input_file.flush().unwrap();
    let encoded_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(bao_exe(), "encode", input_file.path(), encoded_file.path())
        .run()
        .unwrap();
    let encoded_bytes = fs::read(encoded_file.path()).unwrap();

    // Test hash --encoded.
    let input_hash = cmd!(bao_exe(), "hash").input(input_bytes).read().unwrap();
    let encoded_hash = cmd!(bao_exe(), "hash", "--encoded", encoded_file.path())
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
    let decoded_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        encoded_file.path(),
        decoded_file.path()
    ).run()
    .unwrap();
    assert_eq!(input_bytes, &*decoded_bytes);

    // Test decode using --start and --count. Note that --start requires that the input is a file.
    let partial_output = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        encoded_file.path(),
        "--start=1",
        "--count=1"
    ).stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(input_bytes[1..2], *partial_output);
}

#[test]
fn test_encode_decode_outboard() {
    let input_bytes = &b"abc"[..];
    let mut input_file = tempfile::NamedTempFile::new().unwrap();
    input_file.write_all(input_bytes).unwrap();
    input_file.flush().unwrap();
    let outboard_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(
        bao_exe(),
        "encode",
        input_file.path(),
        "--outboard",
        outboard_file.path()
    ).run()
    .unwrap();

    // Test hash --outboard.
    let input_hash = cmd!(bao_exe(), "hash").input(input_bytes).read().unwrap();
    let outboard_hash = cmd!(
        bao_exe(),
        "hash",
        input_file.path(),
        "--outboard",
        outboard_file.path()
    ).read()
    .unwrap();
    assert_eq!(input_hash, outboard_hash);

    // Test decode using stdin and stdout.
    let decoded_bytes = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        "--outboard",
        outboard_file.path()
    ).input(input_bytes)
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
        input_file.path(),
        "--outboard",
        outboard_file.path(),
        "--start=1",
        "--count=1"
    ).stdout_capture()
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
    let encoded_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(bao_exe(), "encode", "-", encoded_file.path())
        .input(&*input)
        .run()
        .unwrap();
    let hash = cmd!(bao_exe(), "hash", "--encoded", encoded_file.path())
        .read()
        .unwrap();
    let outboard_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(bao_exe(), "encode", "-", "--outboard", outboard_file.path())
        .input(&*input)
        .run()
        .unwrap();
    let outboard_hash = cmd!(bao_exe(), "hash", "--outboard", outboard_file.path())
        .read()
        .unwrap();
    assert_eq!(hash, outboard_hash);

    // Do a combined mode slice to a file.
    let slice_file = tempfile::NamedTempFile::new().unwrap();
    cmd!(
        bao_exe(),
        "slice",
        slice_start.to_string(),
        slice_len.to_string(),
        encoded_file.path(),
        slice_file.path()
    ).run()
    .unwrap();
    let slice_bytes = fs::read(slice_file.path()).unwrap();

    // Make sure the outboard mode gives the same result. Do this one to stdout.
    let outboard_slice_bytes = cmd!(
        bao_exe(),
        "slice",
        slice_start.to_string(),
        slice_len.to_string(),
        encoded_file.path()
    ).stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(slice_bytes, outboard_slice_bytes);
}
