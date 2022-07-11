#! /usr/bin/env python3

from binascii import hexlify
from collections import OrderedDict
import io
import json
import sys

# Imports from this directory.
import bao
from bao import CHUNK_SIZE, GROUP_SIZE, HEADER_SIZE, PARENT_SIZE
from generate_input import input_bytes

SIZES = [
    0,
    1,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE,
    3 * CHUNK_SIZE,
    GROUP_SIZE - 1,
    GROUP_SIZE,
    GROUP_SIZE + 1,
    2 * GROUP_SIZE,
    3 * GROUP_SIZE,
    # The first case that has chunk groups at three different depths.
    11 * GROUP_SIZE,
    # The first case that has a depth jump greater than one.
    13 * GROUP_SIZE,
]


def blake3_hash(b):
    return hexlify(bao.bao_hash(io.BytesIO(b))).decode("utf-8")


def hashes():
    ret = []
    for size in SIZES:
        b = input_bytes(size)
        h = bao.bao_hash(io.BytesIO(b))
        fields = [("input_len", size), ("bao_hash", h.hex())]
        ret.append(OrderedDict(fields))
    return ret


# Return the first byte of the header, of each parent, and of each chunk group.
def encode_corruption_points(content_len, outboard=False):
    def recurse(subtree_start, subtree_len, offset, ret):
        if subtree_len <= GROUP_SIZE:
            if subtree_len != 0 and not outboard:
                ret.append(offset)
            return
        ret.append(offset)
        offset += PARENT_SIZE
        llen = bao.left_len(subtree_len)
        recurse(subtree_start, llen, offset, ret)
        offset += bao.encoded_subtree_size(llen, outboard)
        recurse(subtree_start + llen, subtree_len - llen, offset, ret)

    # Start with just the first byte of the header.
    ret = [0]
    recurse(0, content_len, HEADER_SIZE, ret)
    return ret


def encoded():
    ret = []
    for size in SIZES:
        b = input_bytes(size)
        encoded, hash_ = bao.bao_encode(b)
        fields = [
            ("input_len", size),
            ("output_len", len(encoded)),
            ("bao_hash", hash_.hex()),
            ("encoded_blake3", blake3_hash(encoded)),
            ("corruptions", encode_corruption_points(size)),
        ]
        ret.append(OrderedDict(fields))
    return ret


def outboard():
    ret = []
    for size in SIZES:
        b = input_bytes(size)
        encoded, hash_ = bao.bao_encode(b, outboard=True)
        input_corruptions = []
        corruption = 0
        while corruption < size:
            input_corruptions.append(corruption)
            corruption += GROUP_SIZE
        fields = [
            ("input_len", size),
            ("output_len", len(encoded)),
            ("bao_hash", hash_.hex()),
            ("encoded_blake3", blake3_hash(encoded)),
            ("outboard_corruptions", encode_corruption_points(size, outboard=True)),
            ("input_corruptions", input_corruptions),
        ]
        ret.append(OrderedDict(fields))
    return ret


def seeks():
    ret = []
    for size in SIZES:
        offsets = []
        offset = 0
        while offset < size - 2:
            if offset > 0:
                offsets.append(offset - 1)
            offsets.append(offset)
            offset += GROUP_SIZE
        if size > 0:
            offsets.append(size - 1)
        offsets.append(size)
        offsets.append(size + 1)
        fields = [("input_len", size), ("seek_offsets", offsets)]
        ret.append(OrderedDict(fields))
    return ret


# Return the first byte of each parent and of each chunk, as well as the last
# byte of the header. We use the last byte of the header, because header
# corruption isn't guaranteed to break slice decoding. A small change (i.e. in
# the first byte) to the length header generally only breaks the final chunk,
# and a slice might not include the final chunk. Changing the highest-order
# byte in the header breaks all of our cases reliably. This function is very
# similar to bao_decode_slice, but it's not worth complicating the decode
# implementation to avoid this duplication.
def slice_corruption_points(content_len, slice_start, slice_len):
    def recurse(subtree_start, subtree_len, is_root, offset, ret):
        slice_end = slice_start + slice_len
        subtree_end = subtree_start + subtree_len
        if subtree_end <= slice_start and not is_root:
            # This subtree isn't part of the slice. Skip it.
            return 0
        elif slice_end <= subtree_start and not is_root:
            # We've covered all the sliced content. Quit.
            return 0
        elif subtree_len <= GROUP_SIZE:
            # The current subtree is one chunk group. Add its first byte, as
            # long as it's not the empty chunk.
            if subtree_len != 0:
                ret.append(offset)
            return subtree_len
        else:
            # The current subtree is a parent. Add its first byte, and then
            # descend into the left and right subtrees. Note that is_root is
            # always false after this point.
            ret.append(offset)
            offset += PARENT_SIZE
            llen = bao.left_len(subtree_len)
            left_size = recurse(subtree_start, llen, False, offset, ret)
            offset += left_size
            right_size = recurse(
                subtree_start + llen, subtree_len - llen, False, offset, ret
            )
            return PARENT_SIZE + left_size + right_size

    # Start with the last / highest-order byte of the header.
    ret = [HEADER_SIZE - 1]
    recurse(0, content_len, True, HEADER_SIZE, ret)
    return ret


def slices():
    ret = []
    for case in seeks():
        size = case["input_len"]
        offsets = case["seek_offsets"]
        b = input_bytes(size)
        encoded, hash_ = bao.bao_encode(b)
        slices = []
        for offset in offsets:
            for slice_len in [0, GROUP_SIZE]:
                slice_bytes = io.BytesIO()
                bao.bao_slice(io.BytesIO(encoded), slice_bytes, offset, slice_len)
                slice_hash = blake3_hash(slice_bytes.getbuffer())
                fields = [
                    ("start", offset),
                    ("len", slice_len),
                    ("output_len", len(slice_bytes.getbuffer())),
                    ("output_blake3", slice_hash),
                    ("corruptions", slice_corruption_points(size, offset, slice_len)),
                ]
                slices.append(OrderedDict(fields))
        fields = [
            ("input_len", size),
            ("bao_hash", hash_.hex()),
            ("slices", slices),
        ]
        ret.append(OrderedDict(fields))
    return ret


comment = """
Generated by generate_vectors.py. Input bytes, which you can get from
generate_input.py, are generated by incrementing a 4-byte little-endian
integer, starting with 1. For example, an input of length 10 would be the bytes
[1, 0, 0, 0, 2, 0, 0, 0, 3, 0].
""".replace(
    "\n", " "
).strip()


def main():
    output = OrderedDict()
    output["_comment"] = comment
    output["hash"] = hashes()
    output["encode"] = encoded()
    output["outboard"] = outboard()
    output["seek"] = seeks()
    output["slice"] = slices()
    json.dump(output, sys.stdout, indent="    ")
    print()  # a terminating newline


if __name__ == "__main__":
    main()
