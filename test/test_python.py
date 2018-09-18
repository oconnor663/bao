#! /usr/bin/env python3

import hashlib
import os.path
import subprocess
import tempfile

cases = [
    (
        # case name
        "no input",
        # input bytes
        b"",
        # bao hash
        "4c21d0993c7daa84190d0212a684a05af6a9be4c294ec84612635938b91b3d9c",
        # BLAKE2b-256 of encoded
        "81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c",
        # BLAKE2b-256 of outboard
        "81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c",
    ),
    (
        "short string",
        b"The quick brown fox jumps over the lazy dog",
        "48bfdfec627a18baaa6f0eaeb3008b8522eb393f3c8c66bc847caeb828253cb0",
        "53feb75c5447c1bed4b7df5da83e7d528085679d2843681aa7e493de8e113e9e",
        "b739cd907e71f72621a37f7c398c1ed6f26c30c32dd53b3cf35ff1514fdc7546",
    ),
    (
        "a million zeros",
        b"\0" * 1_000_000,
        "a6da3f5139c4a277bdfe3718eaef2c00093b8794788722438b15861631c9cf4b",
        "e812974bebf25137ea6cdb775706d3d618f0b05fd1df4e25a111575510d9f333",
        "630af790621065db7e9531f703e9dc98911f0a29139773e642ec3dd71f9c5d7b",
    ),
]

bao_path = os.path.join(os.path.dirname(__file__), "bao.py")


def bao(*args, **kwargs):
    return subprocess.run(
        ["python3", bao_path, *args],
        stdout=subprocess.PIPE,
        **kwargs,
    ).stdout


for (name, input_bytes, bao_hash, encoded_blake2b, outboard_blake2b) in cases:
    print("case:", name)
    input_file = tempfile.NamedTemporaryFile()
    input_file.write(input_bytes)
    input_file.flush()

    # Make sure the hash is what we expect.
    computed_hash = bao("hash", input=input_bytes).decode().strip()
    assert computed_hash == bao_hash

    # Make sure that `bao hash --encoded` gives the same hash.
    encoded = bao("encode", input=input_bytes)
    encoded_file = tempfile.NamedTemporaryFile()
    encoded_file.write(encoded)
    encoded_file.flush()
    bao_hash_from_encoded = bao(
        "hash", "--encoded", input=encoded).decode().strip()
    assert bao_hash_from_encoded == bao_hash

    # Make sure the encoded bytes are what we expect.
    computed_encoded_blake2b = hashlib.blake2b(encoded, digest_size=32)
    assert encoded_blake2b == computed_encoded_blake2b.hexdigest()

    outboard_file = tempfile.NamedTemporaryFile()
    bao("encode", "--outboard", outboard_file.name, input=input_bytes)
    outboard = outboard_file.read()

    # Make sure the outboard encoded bytes are what we expect.
    computed_outboard_blake2b = hashlib.blake2b(outboard, digest_size=32)
    assert outboard_blake2b == computed_outboard_blake2b.hexdigest()

    # Make sure decoding works, and gives back the original input.
    decoded = bao("decode", bao_hash, input=encoded)
    assert decoded == input_bytes

    # Also make sure outboard decoding works.
    outboard_decoded = bao(
        "decode",
        bao_hash,
        "--outboard",
        outboard_file.name,
        input=input_bytes)
    assert outboard_decoded == input_bytes

    # Slicing the entire thing should be exactly the same as the full encoding.
    full_slice = bao(
        "slice", "0", str(len(input_bytes)), stdin=open(encoded_file.name))
    assert encoded == full_slice
    full_slice_from_outboard = bao(
        "slice",
        "0",
        str(len(input_bytes)),
        "--outboard",
        outboard_file.name,
        stdin=open(input_file.name))
    assert full_slice == full_slice_from_outboard
    assert full_slice == encoded
    full_slice_decoded = bao(
        "decode-slice", bao_hash, "0", str(len(input_bytes)), input=full_slice)
    assert input_bytes == full_slice_decoded

    # Test decoding a slice from the middle.
    slice_start = len(input_bytes) // 4
    slice_len = len(input_bytes) // 2
    middle_slice = bao(
        "slice",
        str(slice_start),
        str(slice_len),
        stdin=open(encoded_file.name))
    middle_slice_from_outboard = bao(
        "slice",
        str(slice_start),
        str(slice_len),
        "--outboard",
        outboard_file.name,
        stdin=open(input_file.name))
    assert middle_slice == middle_slice_from_outboard
    middle_slice_decoded = bao(
        "decode-slice",
        bao_hash,
        str(slice_start),
        str(slice_len),
        input=middle_slice)
    assert middle_slice_decoded == input_bytes[slice_start:][:slice_len]
