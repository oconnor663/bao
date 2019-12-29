use duct::cmd;
use rand::prelude::*;
use std::env::consts::EXE_EXTENSION;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;
use tempfile::tempdir;

pub fn bao_exe() -> PathBuf {
    // `cargo test` doesn't automatically run `cargo build`, so we do that ourselves.
    static CARGO_BUILD_ONCE: Once = Once::new();
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
    let expected = blake3::hash(b"foo").to_hex();
    let output = cmd!(bao_exe(), "hash").stdin_bytes("foo").read().unwrap();
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
        .stdin_bytes("baz")
        .read()
        .unwrap();
    let foo_hash = blake3::hash(b"foo");
    let bar_hash = blake3::hash(b"bar");
    let baz_hash = blake3::hash(b"baz");
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

fn assert_hash_mismatch(output: &std::process::Output) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(bao::decode::Error::HashMismatch.to_string().as_str()));
}

#[test]
fn test_encode_decode_combined() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input");
    let input_bytes = &b"abc"[..];
    fs::write(&input_path, input_bytes).unwrap();
    let input_hash = cmd!(bao_exe(), "hash")
        .stdin_bytes(input_bytes)
        .read()
        .unwrap();
    let encoded_path = dir.path().join("encoded");
    cmd!(bao_exe(), "encode", &input_path, &encoded_path)
        .run()
        .unwrap();
    let encoded_bytes = fs::read(&encoded_path).unwrap();

    // Test decode using stdin and stdout.
    let decoded_bytes = cmd!(bao_exe(), "decode", &input_hash)
        .stdin_bytes(&*encoded_bytes)
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    assert_eq!(input_bytes, &*decoded_bytes);

    // Make sure decoding with the wrong hash fails.
    let zero_hash = "0".repeat(input_hash.len());
    let output = cmd!(bao_exe(), "decode", &zero_hash)
        .stdin_bytes(&*encoded_bytes)
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    assert_hash_mismatch(&output);

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
    let input_hash = cmd!(bao_exe(), "hash")
        .stdin_bytes(input_bytes)
        .read()
        .unwrap();
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

    // Test decode using stdin and stdout.
    let decoded_bytes = cmd!(
        bao_exe(),
        "decode",
        &input_hash,
        "--outboard",
        &outboard_path
    )
    .stdin_bytes(input_bytes)
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(input_bytes, &*decoded_bytes);

    // Make sure decoding with the wrong hash fails.
    let zero_hash = "0".repeat(input_hash.len());
    let output = cmd!(
        bao_exe(),
        "decode",
        &zero_hash,
        "--outboard",
        &outboard_path
    )
    .stdin_bytes(input_bytes)
    .stdout_capture()
    .stderr_capture()
    .unchecked()
    .run()
    .unwrap();
    assert_hash_mismatch(&output);

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
    let hash = cmd!(bao_exe(), "hash").stdin_bytes(&*input).read().unwrap();
    let dir = tempdir().unwrap();
    let encoded_path = dir.path().join("encoded");
    cmd!(bao_exe(), "encode", "-", &encoded_path)
        .stdin_bytes(&*input)
        .run()
        .unwrap();
    let outboard_path = dir.path().join("outboard");
    cmd!(bao_exe(), "encode", "-", "--outboard", &outboard_path)
        .stdin_bytes(&*input)
        .run()
        .unwrap();

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

    // Test decoding the slice.
    let decoded = cmd!(
        bao_exe(),
        "decode-slice",
        &hash,
        slice_start.to_string(),
        slice_len.to_string()
    )
    .stdin_bytes(&*slice_bytes)
    .stdout_capture()
    .run()
    .unwrap()
    .stdout;
    assert_eq!(&input[slice_start..][..slice_len], &*decoded);

    // Test that decode-slice with the wrong hash fails.
    let zero_hash = "0".repeat(hash.len());
    let output = cmd!(
        bao_exe(),
        "decode-slice",
        &zero_hash,
        slice_start.to_string(),
        slice_len.to_string()
    )
    .stdin_bytes(&*slice_bytes)
    .stdout_capture()
    .stderr_capture()
    .unchecked()
    .run()
    .unwrap();
    assert_hash_mismatch(&output);
}
