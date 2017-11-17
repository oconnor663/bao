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

def blake2b_256(buf):
    return hashlib.blake2b(buf, digest_size=32).digest()

def left_len(total_len):
    available_chunks = (total_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2 ** (available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks

def bao_encode(buf):
    def encode_recurse(buf, prefix):
        if len(buf) <= CHUNK_SIZE:
            return blake2b_256(prefix + buf), prefix + buf
        llen = left_len(len(buf))
        left_hash, left_encoded = encode_recurse(buf[:llen], b"")
        right_hash, right_encoded = encode_recurse(buf[llen:], b"")
        node = prefix + left_hash + right_hash
        return blake2b_256(node), node + left_encoded + right_encoded

    prefix = len(buf).to_bytes(8, "little")
    return encode_recurse(buf, prefix)

def bao_decode(buf, digest):
    def decode_recurse(buf, digest, encoded_offset, content_len, prefix):
        if content_len <= CHUNK_SIZE:
            new_offset = encoded_offset + content_len
            chunk = buf[encoded_offset:new_offset]
            if digest is not None:
                assert digest == blake2b_256(prefix + chunk)
            return new_offset, chunk
        new_offset = encoded_offset + 2*DIGEST_SIZE
        node = buf[encoded_offset:new_offset]
        if digest is not None:
            assert digest == blake2b_256(prefix + node)
        left_hash, right_hash = node[:DIGEST_SIZE], node[DIGEST_SIZE:]
        llen = left_len(content_len)
        new_offset, left_decoded = decode_recurse(buf, left_hash, new_offset, llen, b"")
        new_offset, right_decoded = decode_recurse(buf, right_hash, new_offset, content_len - llen, b"")
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
