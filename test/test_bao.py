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
    for case in VECTORS["encoded"]:
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
        corruptions = case["corruptions"]
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
        for c in corruptions:
            corrupted = bytearray(outboard_bytes)
            corrupted[c] ^= 1
            corrupted_file = tempfile.NamedTemporaryFile()
            corrupted_file.write(corrupted)
            corrupted_file.flush()
            bao("decode",
                bao_hash_encoded,
                input=input_bytes,
                should_fail=True)


def main():
    test_hashes()
    test_encoded()
    test_outboard()


if __name__ == "__main__":
    main()

# for (name, input_bytes, bao_hash, encoded_blake2b, outboard_blake2b) in cases:
#     print("case:", name)
#     input_file = tempfile.NamedTemporaryFile()
#     input_file.write(input_bytes)
#     input_file.flush()

#     # Make sure the hash is what we expect.
#     computed_hash = bao("hash", input=input_bytes).decode().strip()
#     assert computed_hash == bao_hash

#     # Make sure that `bao hash --encoded` gives the same hash.
#     encoded_file = tempfile.NamedTemporaryFile()
#     bao("encode", "-", encoded_file.name, input=input_bytes)
#     encoded = open(encoded_file.name, "rb").read()
#     bao_hash_from_encoded = bao("hash", "--encoded",
#                                 encoded_file.name).decode().strip()
#     assert bao_hash_from_encoded == bao_hash

#     # Make sure the encoded bytes are what we expect.
#     computed_encoded_blake2b = hashlib.blake2b(encoded, digest_size=32)
#     assert encoded_blake2b == computed_encoded_blake2b.hexdigest()

#     # Make sure that `bao hash --outboard=...` gives the same hash.
#     outboard_file = tempfile.NamedTemporaryFile()
#     bao("encode", "-", "--outboard", outboard_file.name, input=input_bytes)
#     outboard = outboard_file.read()
#     bao_hash_from_outboard = bao("hash", input_file.name, "--outboard",
#                                  outboard_file.name).decode().strip()
#     assert bao_hash_from_outboard == bao_hash

#     # Make sure the outboard encoded bytes are what we expect.
#     computed_outboard_blake2b = hashlib.blake2b(outboard, digest_size=32)
#     assert outboard_blake2b == computed_outboard_blake2b.hexdigest()

#     # Make sure decoding works, and gives back the original input.
#     decoded = bao("decode", bao_hash, encoded_file.name)
#     assert decoded == input_bytes

#     # Also make sure outboard decoding works.
#     outboard_decoded = bao(
#         "decode",
#         bao_hash,
#         "--outboard",
#         outboard_file.name,
#         input=input_bytes)
#     assert outboard_decoded == input_bytes

#     # Slicing the entire thing should be exactly the same as the full encoding.
#     full_slice = bao("slice", "0", str(len(input_bytes)), encoded_file.name)
#     assert encoded == full_slice
#     full_slice_from_outboard = bao(
#         "slice",
#         "0",
#         str(len(input_bytes)),
#         "--outboard",
#         outboard_file.name,
#         input=input_bytes)
#     assert full_slice == full_slice_from_outboard
#     assert full_slice == encoded
#     full_slice_decoded = bao("decode-slice", bao_hash, "0",
#                              str(len(input_bytes)), encoded_file.name)
#     assert input_bytes == full_slice_decoded

#     # Test decoding a slice from the middle.
#     slice_start = len(input_bytes) // 4
#     slice_len = len(input_bytes) // 2
#     middle_slice = bao("slice", str(slice_start), str(slice_len),
#                        encoded_file.name)
#     middle_slice_from_outboard = bao("slice", str(slice_start), str(slice_len),
#                                      input_file.name, "--outboard",
#                                      outboard_file.name)
#     assert middle_slice == middle_slice_from_outboard
#     middle_slice_decoded = bao(
#         "decode-slice",
#         bao_hash,
#         str(slice_start),
#         str(slice_len),
#         input=middle_slice)
#     assert middle_slice_decoded == input_bytes[slice_start:][:slice_len]
