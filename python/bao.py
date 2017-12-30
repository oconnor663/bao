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

# The root node (whether it's a chunk or a parent) is hashed with the Blake2
# "last node" flag set, and with the content length as a suffix.
def hash_node(node, suffix=None):
    return hashlib.blake2b(
        node + (suffix or b""),
        last_node=bool(suffix),
        digest_size=DIGEST_SIZE
    ).digest()

# Left subtrees contain the largest possible power of two chunks, with at least
# one byte left for the right subtree.
def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

def bao_encode(buf):
    def encode_recurse(buf, hash_suffix):
        if len(buf) <= CHUNK_SIZE:
            return hash_node(buf, suffix=hash_suffix), buf
        llen = left_len(len(buf))
        # Nodes below the root have no hash suffix.
        left_hash, left_encoded = encode_recurse(buf[:llen], None)
        right_hash, right_encoded = encode_recurse(buf[llen:], None)
        node = left_hash + right_hash
        encoded = node + left_encoded + right_encoded
        return hash_node(node, suffix=hash_suffix), encoded

    # The 8-byte little endian content length is used as a hash suffix for the
    # root node, and as a prefix for the final encoding.
    length_bytes = len(buf).to_bytes(8, "little")
    hash, encoded = encode_recurse(buf, length_bytes)
    return hash, length_bytes + encoded

def bao_decode(buf, digest):
    def decode_recurse(buf, digest, encoded_offset, content_len, hash_suffix):
        if content_len <= CHUNK_SIZE:
            new_offset = encoded_offset + content_len
            chunk = buf[encoded_offset:new_offset]
            if digest is not None:
                assert digest == hash_node(chunk, hash_suffix)
            return new_offset, chunk
        new_offset = encoded_offset + 2*DIGEST_SIZE
        node = buf[encoded_offset:new_offset]
        if digest is not None:
            assert digest == hash_node(node, hash_suffix)
        left_hash, right_hash = node[:DIGEST_SIZE], node[DIGEST_SIZE:]
        llen = left_len(content_len)
        new_offset, left_decoded = decode_recurse(
            buf, left_hash, new_offset, llen, None)
        new_offset, right_decoded = decode_recurse(
            buf, right_hash, new_offset, content_len - llen, None)
        return new_offset, left_decoded + right_decoded

    assert len(buf) >= 8, "not enough bytes for header"
    content_len = int.from_bytes(buf[:8], "little")
    _, decoded = decode_recurse(buf, digest, 8, content_len, buf[:8])
    return decoded

def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        _, encoded = bao_encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif args["decode"]:
        buf = sys.stdin.buffer.read()
        if args["--any"]:
            header_hash = None
        else:
            header_hash = binascii.unhexlify(args["--hash"])
        decoded = bao_decode(buf, header_hash)
        sys.stdout.buffer.write(decoded)
    elif args["hash"]:
        bao_hash, _ = bao_encode(sys.stdin.buffer.read())
        print(bao_hash.hex())

if __name__ == "__main__":
    main()
