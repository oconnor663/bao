#! /usr/bin/env python3

import binascii
import sys
import hashlib

CHUNK_SIZE = 4096
DIGEST_SIZE = 32
HEADER_SIZE = 8 + DIGEST_SIZE

def hash_bytes(b):
    return hashlib.blake2b(b, digest_size=32).digest()

def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

def encode(b):
    def encode_tree(b):
        if len(b) <= CHUNK_SIZE:
            return hash_bytes(b), b
        left_len_ = left_len(len(b))
        left_hash, left_encoded = encode_tree(b[:left_len_])
        right_hash, right_encoded = encode_tree(b[left_len_:])
        node = left_hash + right_hash
        return hash_bytes(node), node + left_encoded + right_encoded

    root_hash, encoded = encode_tree(b)
    header = len(b).to_bytes(8, "little") + root_hash
    return hash(header), header + encoded

def decode(header_hash, b):
    def decode_tree(tree_hash, content_len, offset, b):
        if content_len <= CHUNK_SIZE:
            new_offset = offset + content_len
            chunk = b[offset:new_offset]
            assert tree_hash == hash_bytes(chunk)
            return new_offset, chunk
        new_offset = offset + 2*DIGEST_SIZE
        node = b[offset:new_offset]
        assert tree_hash == hash_bytes(node)
        left_hash, right_hash = node[:DIGEST_SIZE], node[DIGEST_SIZE:]
        left_len_ = left_len(content_len)
        new_offset, left_decoded = decode_tree(left_hash, left_len_, new_offset, b)
        new_offset, right_decoded = decode_tree(right_hash, content_len - left_len_, new_offset, b)
        return new_offset, left_decoded + right_decoded

    header = b[:HEADER_SIZE]
    assert header_hash == hash_bytes(header)
    content_len = int.from_bytes(header[:8], "little")
    tree_hash = header[8:]
    _, decoded = decode_tree(tree_hash, content_len, HEADER_SIZE, b)
    return decoded

def main():
    if sys.argv[1] == "encode":
        _, encoded = encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif sys.argv[1] == "decode":
        input_ = sys.stdin.buffer.read()
        if sys.argv[2] == "--any":
            header_hash = hash_bytes(input_[:HEADER_SIZE])
        else:
            header_hash = binascii.unhexlify(sys.argv[2])
        decoded = decode(header_hash, input_)
        sys.stdout.buffer.write(decoded)

if __name__ == "__main__":
    main()
