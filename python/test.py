#! /usr/bin/env python3

import hashlib
import os.path
import subprocess

# (case name, input bytes, bao hash, BLAKE2b256 hash of encoded)
cases = [
    (
        "no input",
        b"",
        "4c21d0993c7daa84190d0212a684a05af6a9be4c294ec84612635938b91b3d9c",
        "81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c",
    ),
    (
        "short string",
        b"The quick brown fox jumps over the lazy dog",
        "48bfdfec627a18baaa6f0eaeb3008b8522eb393f3c8c66bc847caeb828253cb0",
        "53feb75c5447c1bed4b7df5da83e7d528085679d2843681aa7e493de8e113e9e",
    ),
    (
        "a million zeros",
        b"\0" * 1_000_000,
       "a6da3f5139c4a277bdfe3718eaef2c00093b8794788722438b15861631c9cf4b",
       "e812974bebf25137ea6cdb775706d3d618f0b05fd1df4e25a111575510d9f333",
    ),
]

bao_path = os.path.join(os.path.dirname(__file__), "bao.py")


def bao(*args, input_bytes):
    return subprocess.run(
        [bao_path, *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
    ).stdout


for (name, input_bytes, bao_hash, encoded_blake2b) in cases:
    print("case:", name)

    computed_hash = bao("hash", input_bytes=input_bytes).decode().strip()
    assert computed_hash == bao_hash

    encoded = bao("encode", input_bytes=input_bytes)
    bao_hash_from_encoded = bao(
        "hash", "--encoded", input_bytes=encoded).decode().strip()
    assert bao_hash_from_encoded == bao_hash

    computed_encoded_blake2b = hashlib.blake2b(encoded, digest_size=32)
    assert encoded_blake2b == computed_encoded_blake2b.hexdigest()

    decoded = bao("decode", bao_hash, input_bytes=encoded)
    assert decoded == input_bytes
