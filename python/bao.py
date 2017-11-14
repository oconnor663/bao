#! /usr/bin/env python3

__doc__ = """\
Usage: bao.py encode --memory
       bao.py decode (--hash=<hash> | --any)
       bao.py hash
"""

import binascii
import docopt
import hashlib
import sys

CHUNK_SIZE = 4096
DIGEST_SIZE = 32
HEADER_SIZE = 8 + DIGEST_SIZE

def blake2b_256(b):
    return hashlib.blake2b(b, digest_size=32).digest()

def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

def bao_encode(b):
    def encode_tree(b):
        if len(b) <= CHUNK_SIZE:
            return blake2b_256(b), b
        left_len_ = left_len(len(b))
        left_hash, left_encoded = encode_tree(b[:left_len_])
        right_hash, right_encoded = encode_tree(b[left_len_:])
        node = left_hash + right_hash
        return blake2b_256(node), node + left_encoded + right_encoded

    root_hash, encoded = encode_tree(b)
    header = len(b).to_bytes(8, "little") + root_hash
    return blake2b_256(header), header + encoded

def bao_decode(header_hash, b):
    def decode_tree(tree_hash, content_len, offset, b):
        if content_len <= CHUNK_SIZE:
            new_offset = offset + content_len
            chunk = b[offset:new_offset]
            assert tree_hash == blake2b_256(chunk)
            return new_offset, chunk
        new_offset = offset + 2*DIGEST_SIZE
        node = b[offset:new_offset]
        assert tree_hash == blake2b_256(node)
        left_hash, right_hash = node[:DIGEST_SIZE], node[DIGEST_SIZE:]
        left_len_ = left_len(content_len)
        new_offset, left_decoded = decode_tree(left_hash, left_len_, new_offset, b)
        new_offset, right_decoded = decode_tree(right_hash, content_len - left_len_, new_offset, b)
        return new_offset, left_decoded + right_decoded

    header = b[:HEADER_SIZE]
    assert header_hash == blake2b_256(header)
    content_len = int.from_bytes(header[:8], "little")
    tree_hash = header[8:]
    _, decoded = decode_tree(tree_hash, content_len, HEADER_SIZE, b)
    return decoded

def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        _, encoded = bao_encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif args["decode"]:
        input_ = sys.stdin.buffer.read()
        if args["--any"]:
            header_hash = blake2b_256(input_[:HEADER_SIZE])
        else:
            header_hash = binascii.unhexlify(args["--hash"])
        decoded = bao_decode(header_hash, input_)
        sys.stdout.buffer.write(decoded)
    elif args["hash"]:
        bao_hash, _ = bao_encode(sys.stdin.buffer.read())
        print(bao_hash.hex())

if __name__ == "__main__":
    main()
