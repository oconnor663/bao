#! /usr/bin/env python3

import bao
import io
import json
import sys

CHUNK_SIZE = 4096

SIZES = [
    0,
    1,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE - 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 1,
    3 * CHUNK_SIZE - 1,
    3 * CHUNK_SIZE,
    3 * CHUNK_SIZE + 1,
    # The first case that has chunks at three different depths.
    11 * CHUNK_SIZE,
    # The first case that has a depth jump greater than one.
    13 * CHUNK_SIZE,
]


def inputbytes(size):
    ret = bytearray()
    i = 0
    while len(ret) < size:
        take = min(4, size - len(ret))
        ibytes = i.to_bytes(4, "little")
        ret.extend(ibytes[:take])
    return ret


def hashes():
    ret = []
    for size in SIZES:
        b = inputbytes(size)
        h = bao.bao_hash(io.BytesIO(b))
        ret.append([size, h.hex()])
    return ret


def main():
    output = {}
    output["hash"] = hashes()
    json.dump(output, sys.stdout, indent="    ", sort_keys=True)
    print()  # a terminating newline


if __name__ == "__main__":
    main()
