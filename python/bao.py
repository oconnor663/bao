#! /usr/bin/env python3

__doc__ = """\
Usage: bao.py encode --memory
       bao.py decode (--hash=<hash> | --any)
       bao.py hash [--encoded]
"""

import binascii
import docopt
import hashlib
import hmac
import sys

CHUNK_SIZE = 4096
DIGEST_SIZE = 32
HEADER_SIZE = 8

# A sentinel value for when we'll accept any hash.
ANY = object()

def encode_len(root_len):
    return root_len.to_bytes(HEADER_SIZE, "little")

# Python is very permissive with reads and slices, and can silently return
# fewer bytes than requested, so we explicitly check the expected length here.
# Parsing a header that's shorter than 8 bytes could trick us into accepting an
# invalid encoding.
def decode_len(len_bytes):
    assert len(len_bytes) == HEADER_SIZE, "not enough bytes"
    return int.from_bytes(len_bytes, "little")

# The root node (whether it's a chunk or a parent) is hashed with the Blake2
# "last node" flag set, and with the total content length as a suffix. All
# interior nodes set root_len=None.
def hash_node(node, root_len):
    state = hashlib.blake2b(
        last_node=(root_len is not None),
        digest_size=DIGEST_SIZE)
    state.update(node)
    if root_len is not None:
        state.update(encode_len(root_len))
    return state.digest()

# As with decode len, we explicitly assert the expected length here, to avoid
# accepting a chunk that's shorter than the header said it should be.
def verify_node(buf, node_size, root_len, expected_hash):
    assert node_size <= len(buf), "not enough bytes"
    node_bytes = buf[:node_size]
    found_hash = hash_node(node_bytes, root_len)
    if expected_hash is not ANY:
        # Compare digests in constant time. It might matter to some callers.
        assert hmac.compare_digest(expected_hash, found_hash), "hash mismatch"

# Left subtrees contain the largest possible power of two chunks, with at least
# one byte left for the right subtree.
def left_len(parent_len):
    available_chunks = (parent_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

# This function does double duty as encode and hash.
def bao_encode(buf):
    def encode_recurse(buf, root_len):
        if len(buf) <= CHUNK_SIZE:
            return hash_node(buf, root_len), buf
        llen = left_len(len(buf))
        # Interior nodes have no len suffix.
        left_hash, left_encoded = encode_recurse(buf[:llen], None)
        right_hash, right_encoded = encode_recurse(buf[llen:], None)
        node = left_hash + right_hash
        encoded = node + left_encoded + right_encoded
        return hash_node(node, root_len), encoded

    # Only this topmost call sets a non-None root_len.
    root_len = len(buf)
    hash_, encoded = encode_recurse(buf, root_len)
    # The final output prefixes the 8 byte encoded length.
    return hash_, encode_len(root_len) + encoded

def bao_decode(in_stream, out_stream, hash_):
    def decode_recurse(hash_, content_len, root_len):
        if content_len <= CHUNK_SIZE:
            chunk = in_stream.read(content_len)
            verify_node(chunk, content_len, root_len, hash_)
            out_stream.write(chunk)
        else:
            parent = in_stream.read(2*DIGEST_SIZE)
            verify_node(parent, 2*DIGEST_SIZE, root_len, hash_)
            left_hash, right_hash = parent[:DIGEST_SIZE], parent[DIGEST_SIZE:]
            llen = left_len(content_len)
            # Interior nodes have no len suffix.
            decode_recurse(left_hash, llen, None)
            decode_recurse(right_hash, content_len - llen, None)

    # The first 8 bytes are the encoded content len.
    content_len = decode_len(in_stream.read(HEADER_SIZE))
    decode_recurse(hash_, content_len, content_len)

def bao_hash_encoded(buf):
    assert len(buf) >= HEADER_SIZE, "not enough bytes"
    length_bytes = buf[:HEADER_SIZE]
    root_len = decode_len(length_bytes)
    if root_len > CHUNK_SIZE:
        root_node = buf[HEADER_SIZE:HEADER_SIZE+2*DIGEST_SIZE]
    else:
        root_node = buf[HEADER_SIZE:HEADER_SIZE+root_len]
    return hash_node(root_node, root_len)

def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        _, encoded = bao_encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif args["decode"]:
        if args["--any"]:
            bao_hash = ANY
        else:
            bao_hash = binascii.unhexlify(args["--hash"])
        bao_decode(sys.stdin.buffer, sys.stdout.buffer, bao_hash)
    elif args["hash"]:
        buf = sys.stdin.buffer.read()
        if args["--encoded"]:
            bao_hash = bao_hash_encoded(buf)
        else:
            bao_hash, _ = bao_encode(buf)
        print(bao_hash.hex())

if __name__ == "__main__":
    main()
