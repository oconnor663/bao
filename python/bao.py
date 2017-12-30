#! /usr/bin/env python3

__doc__ = """\
Usage: bao.py encode --memory
       bao.py decode (--hash=<hash> | --any)
       bao.py hash [--encoded]
"""

import binascii
import docopt
import hashlib
import sys

CHUNK_SIZE = 4096
DIGEST_SIZE = 32
HEADER_SIZE = 8

# The root node (whether it's a chunk or a parent) is hashed with the Blake2
# "last node" flag set, and with the content length as a suffix.
def hash_node(node, suffix=None):
    return hashlib.blake2b(
        node + (suffix or b""),
        last_node=bool(suffix),
        digest_size=DIGEST_SIZE
    ).digest()

# Python is very permissive with reads and slices, and can silently return
# fewer bytes than requested. Hashing a chunk that's not as long as the header
# said it should be, or parsing a length that's not actually 8 bytes, can
# incorrectly validate malicious input and lead to multiple hashes for the same
# content. Thus the explicit length asserts here.
def verify_bytes(buf, start, length, expected_hash, suffix=None):
    assert start + length <= len(buf), "not enough bytes"
    if suffix is not None:
        assert len(suffix) == HEADER_SIZE, "header is the wrong length"
    verified = buf[start:start+length]
    assert expected_hash == hash_node(verified, suffix), "hash mismatch"
    return verified

# Left subtrees contain the largest possible power of two chunks, with at least
# one byte left for the right subtree.
def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

# This function does double duty as encode and hash.
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
    length_bytes = len(buf).to_bytes(HEADER_SIZE, "little")
    hash, encoded = encode_recurse(buf, length_bytes)
    return hash, length_bytes + encoded

def bao_decode(buf, digest):
    def decode_recurse(buf, digest, encoded_offset, content_len, hash_suffix):
        if content_len <= CHUNK_SIZE:
            verified = verify_bytes(buf, encoded_offset, content_len, digest, hash_suffix)
            new_offset = encoded_offset + content_len
            return new_offset, verified
        verified = verify_bytes(buf, encoded_offset, 2*DIGEST_SIZE, digest, hash_suffix)
        new_offset = encoded_offset + 2*DIGEST_SIZE
        left_hash, right_hash = verified[:DIGEST_SIZE], verified[DIGEST_SIZE:]
        llen = left_len(content_len)
        new_offset, left_decoded = decode_recurse(
            buf, left_hash, new_offset, llen, None)
        new_offset, right_decoded = decode_recurse(
            buf, right_hash, new_offset, content_len - llen, None)
        return new_offset, left_decoded + right_decoded

    content_len = int.from_bytes(buf[:HEADER_SIZE], "little")
    _, decoded = decode_recurse(buf, digest, HEADER_SIZE, content_len, buf[:HEADER_SIZE])
    return decoded

def bao_hash_encoded(buf):
    assert len(buf) >= HEADER_SIZE, "not enough bytes"
    length_bytes = buf[:HEADER_SIZE]
    length = int.from_bytes(length_bytes, "little")
    if length > CHUNK_SIZE:
        root_node = buf[HEADER_SIZE:HEADER_SIZE+2*DIGEST_SIZE]
    else:
        root_node = buf[HEADER_SIZE:HEADER_SIZE+length]
    return hash_node(root_node, suffix=length_bytes)

def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        _, encoded = bao_encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif args["decode"]:
        buf = sys.stdin.buffer.read()
        if args["--any"]:
            bao_hash = bao_hash_encoded(buf)
        else:
            bao_hash = binascii.unhexlify(args["--hash"])
        decoded = bao_decode(buf, bao_hash)
        sys.stdout.buffer.write(decoded)
    elif args["hash"]:
        buf = sys.stdin.buffer.read()
        if args["--encoded"]:
            bao_hash = bao_hash_encoded(buf)
        else:
            bao_hash, _ = bao_encode(buf)
        print(bao_hash.hex())

if __name__ == "__main__":
    main()
