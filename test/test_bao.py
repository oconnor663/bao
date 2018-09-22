#! /usr/bin/env python3

# This file is directly runnable, or you can run pytest in this directory.
# Since test_vectors.json is generated from bao.py, it's slightly cheating to
# then test bao.py against its own output. But at least this helps is notice
# changes, since the vectors are checked in rather than generated every time.

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

# Imports from this directory.
import generate_input

HERE = Path(__file__).parent
BAO_PATH = HERE / "bao.py"
VECTORS_PATH = HERE / "test_vectors.json"
VECTORS = json.load(VECTORS_PATH.open())


def bao(*args, input=None, should_fail=False):
    output = subprocess.run(
        ["python3", str(BAO_PATH), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if should_fail else None,
        input=input,
    )
    if output.returncode != 0 and not should_fail:
        raise AssertionError("bao.py returned an error", output.returncode)
    if output.returncode == 0 and should_fail:
        raise AssertionError("bao.py should have failed")
    return output.stdout


def bao_hash(input, encoded=False, outboard=None):
    args = ["hash"]
    if encoded:
        args += ["--encoded"]
    if outboard is not None:
        args += ["--outboard", outboard]
    output = bao(*args, input=input)
    return output.decode("utf8").strip()


def test_hashes():
    for case in VECTORS["hash"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        expected_hash = case["bao_hash"]
        print("hash", input_len)

        computed_hash = bao_hash(input_bytes)
        assert expected_hash == computed_hash


def encoded_file(input_len, *, outboard=False):
    encoded_file = tempfile.NamedTemporaryFile()
    args = ["encode", "-"]
    if outboard:
        args += ["--outboard"]
    args += [encoded_file.name]
    bao(*args, input=generate_input.input_bytes(input_len))
    return encoded_file


def encoded_bytes(input_len, *, outboard=False):
    f = encoded_file(input_len, outboard=outboard)
    return f.read()


def blake2b(b):
    return hashlib.blake2b(b, digest_size=16).hexdigest()


def test_encoded():
    for case in VECTORS["encode"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        output_len = case["output_len"]
        expected_bao_hash = case["bao_hash"]
        encoded_blake2b = case["encoded_blake2b"]
        corruptions = case["corruptions"]
        print("encoded", input_len)

        # First make sure the encoded output is what it's supposed to be.
        encoded = encoded_bytes(input_len)
        assert output_len == len(encoded)
        assert encoded_blake2b == blake2b(encoded)

        # Test `bao hash --encoded`.
        bao_hash_encoded = bao_hash(encoded, encoded=True)
        assert expected_bao_hash == bao_hash_encoded

        # Now test decoding.
        output = bao("decode", expected_bao_hash, input=encoded)
        assert input_bytes == output

        # Finally, make sure each of the corruptions causes decoding to fail.
        for c in corruptions:
            corrupted = bytearray(encoded)
            corrupted[c] ^= 1
            bao("decode", bao_hash_encoded, input=corrupted, should_fail=True)


def test_outboard():
    for case in VECTORS["outboard"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        output_len = case["output_len"]
        expected_bao_hash = case["bao_hash"]
        encoded_blake2b = case["encoded_blake2b"]
        outboard_corruptions = case["outboard_corruptions"]
        input_corruptions = case["input_corruptions"]
        print("outboard", input_len)

        # First make sure the encoded output is what it's supposed to be.
        outboard_file = encoded_file(input_len, outboard=True)
        outboard_bytes = outboard_file.read()
        assert output_len == len(outboard_bytes)
        assert encoded_blake2b == blake2b(outboard_bytes)

        # Test `bao hash --outboard`.
        bao_hash_encoded = bao_hash(input_bytes, outboard=outboard_file.name)
        assert expected_bao_hash == bao_hash_encoded

        # Now test decoding.
        output = bao(
            "decode",
            expected_bao_hash,
            "--outboard",
            outboard_file.name,
            input=input_bytes)
        assert input_bytes == output

        # Make sure each of the outboard corruptions causes decoding to fail.
        for c in outboard_corruptions:
            corrupted = bytearray(outboard_bytes)
            corrupted[c] ^= 1
            corrupted_file = tempfile.NamedTemporaryFile()
            corrupted_file.write(corrupted)
            corrupted_file.flush()
            bao("decode",
                expected_bao_hash,
                "--outboard",
                corrupted_file.name,
                input=input_bytes,
                should_fail=True)

        # Make sure each of the input corruptions causes decoding to fail.
        for c in input_corruptions:
            corrupted = bytearray(input_bytes)
            corrupted[c] ^= 1
            bao("decode",
                expected_bao_hash,
                "--outboard",
                outboard_file.name,
                input=corrupted,
                should_fail=True)


def test_slices():
    for case in VECTORS["slice"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        expected_bao_hash = case["bao_hash"]
        slices = case["slices"]
        print("slice", input_len)

        encoded = encoded_file(input_len)

        for slice_case in slices:
            slice_start = slice_case["start"]
            slice_len = slice_case["len"]
            output_len = slice_case["output_len"]
            output_blake2b = slice_case["output_blake2b"]
            corruptions = slice_case["corruptions"]

            # Make sure the slice output is what it should be.
            slice_bytes = bao("slice", str(slice_start), str(slice_len),
                              encoded.name)
            assert output_len == len(slice_bytes)
            assert output_blake2b == blake2b(slice_bytes)

            # Test decoding the slice, and compare it to the input. Note that
            # slicing a byte array in Python allows indices past the end of the
            # array, and sort of silently caps them.
            input_slice = input_bytes[slice_start:][:slice_len]
            decoded = bao(
                "decode-slice",
                expected_bao_hash,
                str(slice_start),
                str(slice_len),
                input=slice_bytes)
            assert input_slice == decoded

            for c in corruptions:
                corrupted = bytearray(slice_bytes)
                corrupted[c] ^= 1
                bao("decode-slice",
                    expected_bao_hash,
                    str(slice_start),
                    str(slice_len),
                    input=corrupted,
                    should_fail=True)


def main():
    test_hashes()
    test_encoded()
    test_outboard()
    # Note that bao.py doesn't do seeks, so we don't use the seek tests here.
    test_slices()


if __name__ == "__main__":
    main()
