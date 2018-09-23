#! /usr/bin/env python3

# This file is directly runnable, or you can run pytest in this directory.
# Since test_vectors.json is generated from bao.py, it's slightly cheating to
# then test bao.py against its own output. But at least this helps is notice
# changes, since the vectors are checked in rather than generated every time.

from binascii import unhexlify
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile

# Imports from this directory.
import bao
import generate_input

HERE = Path(__file__).parent
BAO_PATH = HERE / "bao.py"
VECTORS_PATH = HERE / "test_vectors.json"
VECTORS = json.load(VECTORS_PATH.open())

# Wrapper functions
# =================
#
# Most of the functions in bao.py (except bao_encode) work with streams. These
# wrappers work with bytes, which makes them easier to test.


def bao_hash(content):
    return bao.bao_hash(io.BytesIO(content)).hex()


def bao_hash_encoded(encoded):
    return bao.bao_hash_encoded(io.BytesIO(encoded)).hex()


def bao_hash_outboard(content, outboard):
    return bao.bao_hash_encoded(io.BytesIO(content),
                                io.BytesIO(outboard)).hex()


def bao_encode(content):
    # Note that unlike the other functions, this one already takes bytes.
    return bao.bao_encode(content, outboard=False)


def bao_encode_outboard(content):
    # Note that unlike the other functions, this one already takes bytes.
    return bao.bao_encode(content, outboard=True)


def bao_decode(hash, encoded):
    hashbytes = unhexlify(hash)
    output = io.BytesIO()
    bao.bao_decode(io.BytesIO(encoded), output, hashbytes)
    return output.getvalue()


def bao_decode_outboard(hash, content, outboard):
    hashbytes = unhexlify(hash)
    output = io.BytesIO()
    bao.bao_decode(
        io.BytesIO(content),
        output,
        hashbytes,
        outboard_stream=io.BytesIO(outboard))
    return output.getvalue()


def bao_slice(encoded, slice_start, slice_len):
    output = io.BytesIO()
    bao.bao_slice(io.BytesIO(encoded), output, slice_start, slice_len)
    return output.getvalue()


def bao_slice_outboard(content, outboard, slice_start, slice_len):
    output = io.BytesIO()
    bao.bao_slice(
        io.BytesIO(content),
        output,
        slice_start,
        slice_len,
        outboard_stream=io.BytesIO(outboard))
    return output.getvalue()


def bao_decode_slice(slice_bytes, hash, slice_start, slice_len):
    hashbytes = unhexlify(hash)
    output = io.BytesIO()
    bao.bao_decode_slice(
        io.BytesIO(slice_bytes), output, hashbytes, slice_start, slice_len)
    return output.getvalue()


# Tests
# =====


def test_hashes():
    for case in VECTORS["hash"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        expected_hash = case["bao_hash"]
        print("hash", input_len)

        computed_hash = bao_hash(input_bytes)
        assert expected_hash == computed_hash


def bao_cli(*args, input=None, should_fail=False):
    output = subprocess.run(
        ["python3", str(BAO_PATH), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if should_fail else None,
        input=input,
    )
    cmd = " ".join(["bao.py"] + list(args))
    if should_fail:
        assert output.returncode != 0, "`{}` should've failed".format(cmd)
    else:
        assert output.returncode == 0, "`{}` failed".format(cmd)
    return output.stdout


def test_hash_cli():
    # CLI tests just use the final (largest) test vector in each set, to avoid
    # shelling out hundreds of times. There's no need to exhaustively test the
    # implementation via the CLI, because it's tested on its own above.
    # Instead, we just need to verify once that it's hooked up properly.
    case = VECTORS["hash"][-1]
    input_len = case["input_len"]
    input_bytes = generate_input.input_bytes(input_len)
    expected_hash = case["bao_hash"]
    print("hash cli", input_len)

    computed_hash = bao_cli("hash", input=input_bytes).decode().strip()
    assert expected_hash == computed_hash


def blake2b(b):
    return hashlib.blake2b(b, digest_size=16).hexdigest()


def assert_decode_failure(f, *args):
    try:
        f(*args)
    except AssertionError:
        pass
    else:
        raise AssertionError("failure expected, but no exception raised")


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
        encoded = bao_encode(input_bytes)
        assert output_len == len(encoded)
        assert encoded_blake2b == blake2b(encoded)

        # Test hashing the encoded bytes.
        encoded_hash = bao_hash_encoded(encoded)
        assert expected_bao_hash == encoded_hash

        # Now test decoding.
        output = bao_decode(expected_bao_hash, encoded)
        assert input_bytes == output

        # Make sure decoding with the wrong hash fails.
        wrong_hash = "0" * len(encoded_hash)
        assert_decode_failure(bao_decode, wrong_hash, encoded)

        # Make sure each of the corruption points causes decoding to fail.
        for c in corruptions:
            corrupted = bytearray(encoded)
            corrupted[c] ^= 1
            assert_decode_failure(bao_decode, encoded_hash, corrupted)


def make_tempfile(b=b""):
    f = tempfile.NamedTemporaryFile()
    f.write(b)
    f.flush()
    f.seek(0)
    return f


def test_encoded_cli():
    case = VECTORS["encode"][-1]
    input_len = case["input_len"]
    input_bytes = generate_input.input_bytes(input_len)
    output_len = case["output_len"]
    expected_bao_hash = case["bao_hash"]
    encoded_blake2b = case["encoded_blake2b"]
    print("encoded cli", input_len)

    # First make sure the encoded output is what it's supposed to be.
    input_file = make_tempfile(input_bytes)
    encoded_file = make_tempfile()
    bao_cli("encode", input_file.name, encoded_file.name)
    encoded = encoded_file.read()
    assert output_len == len(encoded)
    assert encoded_blake2b == blake2b(encoded)

    # Test hashing the encoded bytes.
    encoded_hash = bao_cli("hash", "--encoded",
                           encoded_file.name).decode().strip()
    assert expected_bao_hash == encoded_hash

    # Now test decoding.
    output = bao_cli("decode", expected_bao_hash, encoded_file.name)
    assert input_bytes == output

    # Make sure decoding with the wrong hash fails.
    wrong_hash = "0" * len(encoded_hash)
    bao_cli("decode", wrong_hash, encoded_file.name, should_fail=True)


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
        outboard = bao_encode_outboard(input_bytes)
        assert output_len == len(outboard)
        assert encoded_blake2b == blake2b(outboard)

        # Test `bao hash --outboard`.
        bao_hash_encoded = bao_hash_outboard(input_bytes, outboard)
        assert expected_bao_hash == bao_hash_encoded

        # Now test decoding.
        output = bao_decode_outboard(expected_bao_hash, input_bytes, outboard)
        assert input_bytes == output

        # Make sure decoding with the wrong hash fails.
        wrong_hash = "0" * len(expected_bao_hash)
        assert_decode_failure(bao_decode_outboard, wrong_hash, input_bytes,
                              outboard)

        # Make sure each of the outboard corruption points causes decoding to
        # fail.
        for c in outboard_corruptions:
            corrupted = bytearray(outboard)
            corrupted[c] ^= 1
            assert_decode_failure(bao_decode_outboard, expected_bao_hash,
                                  input_bytes, corrupted)

        # Make sure each of the input corruption points causes decoding to
        # fail.
        for c in input_corruptions:
            corrupted = bytearray(input_bytes)
            corrupted[c] ^= 1
            assert_decode_failure(bao_decode_outboard, expected_bao_hash,
                                  corrupted, outboard)


def test_outboard_cli():
    case = VECTORS["outboard"][-1]
    input_len = case["input_len"]
    input_bytes = generate_input.input_bytes(input_len)
    output_len = case["output_len"]
    expected_bao_hash = case["bao_hash"]
    encoded_blake2b = case["encoded_blake2b"]
    print("outboard cli", input_len)

    # First make sure the encoded output is what it's supposed to be.
    input_file = make_tempfile(input_bytes)
    outboard_file = make_tempfile()
    bao_cli("encode", input_file.name, "--outboard", outboard_file.name)
    outboard = outboard_file.read()
    assert output_len == len(outboard)
    assert encoded_blake2b == blake2b(outboard)

    # Test `bao hash --outboard`.
    outboard_encoded_hash = bao_cli("hash", input_file.name, "--outboard",
                                    outboard_file.name).decode().strip()
    assert expected_bao_hash == outboard_encoded_hash

    # Now test decoding.
    output = bao_cli("decode", expected_bao_hash, input_file.name,
                     "--outboard", outboard_file.name)
    assert input_bytes == output

    # Make sure decoding with the wrong hash fails.
    wrong_hash = "0" * len(expected_bao_hash)
    output = bao_cli(
        "decode",
        wrong_hash,
        input_file.name,
        "--outboard",
        outboard_file.name,
        should_fail=True)


def test_slices():
    for case in VECTORS["slice"]:
        input_len = case["input_len"]
        input_bytes = generate_input.input_bytes(input_len)
        expected_bao_hash = case["bao_hash"]
        slices = case["slices"]
        print("slice", input_len)

        encoded = bao_encode(input_bytes)
        outboard = bao_encode_outboard(input_bytes)

        for slice_case in slices:
            slice_start = slice_case["start"]
            slice_len = slice_case["len"]
            output_len = slice_case["output_len"]
            output_blake2b = slice_case["output_blake2b"]
            corruptions = slice_case["corruptions"]

            # Make sure the slice output is what it should be.
            slice_bytes = bao_slice(encoded, slice_start, slice_len)
            assert output_len == len(slice_bytes)
            assert output_blake2b == blake2b(slice_bytes)

            # Make sure slicing an outboard tree is the same.
            outboard_slice_bytes = bao_slice_outboard(input_bytes, outboard,
                                                      slice_start, slice_len)
            assert slice_bytes == outboard_slice_bytes

            # Test decoding the slice, and compare it to the input. Note that
            # slicing a byte array in Python allows indices past the end of the
            # array, and sort of silently caps them.
            input_slice = input_bytes[slice_start:][:slice_len]
            output = bao_decode_slice(slice_bytes, expected_bao_hash,
                                      slice_start, slice_len)
            assert input_slice == output

            # Make sure decoding with the wrong hash fails.
            wrong_hash = "0" * len(expected_bao_hash)
            assert_decode_failure(bao_decode_slice, slice_bytes, wrong_hash,
                                  slice_start, slice_len)

            # Make sure each of the slice corruption points causes decoding to
            # fail.
            for c in corruptions:
                corrupted = bytearray(slice_bytes)
                corrupted[c] ^= 1
                assert_decode_failure(bao_decode_slice, corrupted,
                                      expected_bao_hash, slice_start,
                                      slice_len)


def test_slices_cli():
    case = VECTORS["slice"][-1]
    input_len = case["input_len"]
    input_bytes = generate_input.input_bytes(input_len)
    expected_bao_hash = case["bao_hash"]
    slices = case["slices"]
    print("slice cli", input_len)

    input_file = make_tempfile(input_bytes)
    encoded_file = make_tempfile()
    bao_cli("encode", input_file.name, encoded_file.name)
    outboard_file = make_tempfile()
    bao_cli("encode", input_file.name, "--outboard", outboard_file.name)

    # Use the first slice in the list. Currently they're all the same length.
    slice_case = slices[0]
    slice_start = slice_case["start"]
    slice_len = slice_case["len"]
    output_len = slice_case["output_len"]
    output_blake2b = slice_case["output_blake2b"]

    # Make sure the slice output is what it should be.
    slice_bytes = bao_cli("slice", str(slice_start), str(slice_len),
                          encoded_file.name)
    assert output_len == len(slice_bytes)
    assert output_blake2b == blake2b(slice_bytes)

    # Make sure slicing an outboard tree is the same.
    outboard_slice_bytes = bao_cli("slice", str(slice_start), str(slice_len),
                                   input_file.name, "--outboard",
                                   outboard_file.name)
    assert slice_bytes == outboard_slice_bytes

    # Test decoding the slice, and compare it to the input. Note that
    # slicing a byte array in Python allows indices past the end of the
    # array, and sort of silently caps them.
    input_slice = input_bytes[slice_start:][:slice_len]
    output = bao_cli(
        "decode-slice",
        expected_bao_hash,
        str(slice_start),
        str(slice_len),
        input=slice_bytes)
    assert input_slice == output

    # Make sure decoding with the wrong hash fails.
    wrong_hash = "0" * len(expected_bao_hash)
    bao_cli(
        "decode-slice",
        wrong_hash,
        str(slice_start),
        str(slice_len),
        input=slice_bytes,
        should_fail=True)


def main():
    test_hashes()
    test_hash_cli()
    test_encoded()
    test_encoded_cli()
    test_outboard()
    test_outboard_cli()
    # Note that bao.py doesn't do seeks, so we don't use the seek tests here.
    test_slices()
    test_slices_cli()


if __name__ == "__main__":
    main()
