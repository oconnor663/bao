#! /usr/bin/env python3

import os.path
import subprocess

cases = [
    ("empty", b"",
     "4c21d0993c7daa84190d0212a684a05af6a9be4c294ec84612635938b91b3d9c"),
    ("quick brown fox", b"The quick brown fox jumps over the lazy dog",
     "48bfdfec627a18baaa6f0eaeb3008b8522eb393f3c8c66bc847caeb828253cb0"),
    ("a million zeroes", b"\0" * 1_000_000,
     "a6da3f5139c4a277bdfe3718eaef2c00093b8794788722438b15861631c9cf4b"),
]

bao_path = os.path.join(os.path.dirname(__file__), "bao.py")


def bao(*args, input_):
    return subprocess.run(
        [bao_path, *args],
        input=input_,
        stdout=subprocess.PIPE,
    ).stdout


for (name, input_, hash_) in cases:
    print("case:", name)

    computed_hash = bao("hash", input_=input_).decode().strip()
    assert computed_hash == hash_

    encoded = bao("encode", "--memory", input_=input_)
    computed_hash_encoded = bao(
        "hash", "--encoded", input_=encoded).decode().strip()
    assert computed_hash_encoded == hash_

    decoded = bao("decode", "--hash", hash_, input_=encoded)
    assert decoded == input_

    decoded_any = bao("decode", "--any", input_=encoded)
    assert decoded_any == input_
