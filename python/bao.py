#! /usr/bin/env python3

import binascii
import sys
import hashlib

CHUNK_SIZE = 4096
DIGEST_SIZE = 32
HEADER_SIZE = 8 + DIGEST_SIZE

def hash_bytes(buf):
    return hashlib.blake2b(buf, digest_size=32).digest()

def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

def encode(buf):
    def encode_recurse(buf, prefix):
        if len(buf) <= CHUNK_SIZE:
            return hash_bytes(prefix + buf), prefix + buf
        llen = left_len(len(buf))
        left_hash, left_encoded = encode(buf[:llen], b"")
        right_hash, right_encoded = encode(buf[llen:], b"")
        node = prefix + left_hash + right_hash
        return hash_bytes(node), node + left_encoded + right_encoded

    prefix = len(buf).to_bytes(8, "little")
    return encode_recurse(buf, prefix)

def decode(digest, buf):
    def decode_recurse(digest, encoded_offset, content_len, buf, prefix):
        if content_len <= CHUNK_SIZE:
            new_offset = encoded_offset + content_len
            chunk = buf[encoded_offset:new_offset]
            assert digest == hash_bytes(prefix + chunk)
            return new_offset, chunk
        new_offset = encoded_offset + 2*DIGEST_SIZE
        node = buf[encoded_offset:new_offset]
        assert digest == hash_bytes(prefix + node)
        left_hash, right_hash = node[:DIGEST_SIZE], node[DIGEST_SIZE:]
        llen = left_len(content_len)
        new_offset, left_decoded = decode_recurse(left_hash, new_offset, llen, buf, b"")
        new_offset, right_decoded = decode_recurse(right_hash, new_offset, content_len - llen, buf, b"")
        return new_offset, left_decoded + right_decoded

    assert(len(buf) >= 8, "not enough bytes for header")
    content_len = int.from_bytes(buf[:8], "little")
    _, decoded = decode_recurse(digest, 8, content_len, buf, 

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
