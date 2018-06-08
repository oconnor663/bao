#! /usr/bin/env python3

# This is an example implementation of bao, with the goal of being as readable
# as possible and a reference for tests. Some comments on how the three main
# operations are implemented:
#
# *bao_decode* is a recursive streaming implementation. Recursion is easy here
# because the length header at the start of the encoding tells us how deep the
# tree is, and we can build up the callstack to match. The pre-order layout of
# the tree means that no seeking is required, just regular reads.
#
# *bao_hash* is an iterative streaming implementation. Recursion doesn't work
# well here, because we don't know the length of the input file in advance.
# Instead, we keep a stack of subtrees filled so far, merging them as we go
# along. There is a very cute trick, where the number of trees that should
# remain in the stack is the same as the number of 1's in the binary
# representation of the count of chunks so far. (E.g. If you've read 255 chunks
# so far, then you have 8 partial subtrees. One of 128 chunks, one of 64
# chunks, and so on. After you read the 256th chunk, you can merge all of those
# into a single subtree.) That, plus the fact that merging is always done
# smallest-to-largest / right-to-left, means that we don't need to track the
# size of each subtree at all; just the hashes and the size of the stack is
# enough.
#
# *bao_encode* is a recursive implementation, but it's not streaming. Instead
# it buffers the entire input in memory. The Rust implementation use a more
# complicated strategy to avoid hogging memory like this. It writes the output
# tree first in post-order, and then it does a second pass back-to-front to
# flip it in place. (A pre-order-first approach suffers from not knowing how
# much space to leave for parent nodes before the first chunk, until you find
# out the final length of the input.) That two-pass-tree-flipping strategy is
# pretty complicated, and this example doesn't try to reproduce it. Note that
# in any implementation, if the ouput doesn't support seeking (like a Unix
# pipe), the only options are to either use a temporary file or to buffer the
# whole input.

__doc__ = """\
Usage: bao.py encode
       bao.py decode <hash>
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
        last_node=(root_len is not None), digest_size=DIGEST_SIZE)
    state.update(node)
    if root_len is not None:
        state.update(encode_len(root_len))
    return state.digest()


# As with decode len, we explicitly assert the expected length here, to avoid
# accepting a chunk that's shorter than the header said it should be.
def verify_node(buf, node_size, root_len, expected_hash):
    # As in decode_len, it's crucial to be strict with lengths.
    assert node_size <= len(buf), "not enough bytes"
    node_bytes = buf[:node_size]
    found_hash = hash_node(node_bytes, root_len)
    # Compare digests in constant time. It might matter to some callers.
    assert hmac.compare_digest(expected_hash, found_hash), "hash mismatch"


# Left subtrees contain the largest possible power of two chunks, with at least
# one byte left for the right subtree.
def left_len(parent_len):
    available_chunks = (parent_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2**(available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks


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
    return encode_len(root_len) + encoded


def bao_decode(in_stream, out_stream, hash_):
    def decode_recurse(hash_, content_len, root_len):
        if content_len <= CHUNK_SIZE:
            chunk = in_stream.read(content_len)
            verify_node(chunk, content_len, root_len, hash_)
            out_stream.write(chunk)
        else:
            parent = in_stream.read(2 * DIGEST_SIZE)
            verify_node(parent, 2 * DIGEST_SIZE, root_len, hash_)
            left_hash, right_hash = parent[:DIGEST_SIZE], parent[DIGEST_SIZE:]
            llen = left_len(content_len)
            # Interior nodes have no len suffix.
            decode_recurse(left_hash, llen, None)
            decode_recurse(right_hash, content_len - llen, None)

    # The first 8 bytes are the encoded content len.
    root_len = decode_len(in_stream.read(HEADER_SIZE))
    decode_recurse(hash_, root_len, root_len)


def bao_hash(in_stream):
    buf = b""
    chunks = 0
    subtrees = []
    while True:
        # We ask for CHUNK_SIZE bytes, but be careful, we can always get fewer.
        read = in_stream.read(CHUNK_SIZE)
        # If the read is EOF, do a final rollup merge of all the subtrees we
        # have, and pass the root_len flag for hashing the root node.
        if not read:
            if chunks == 0:
                return hash_node(buf, len(buf))
            new_subtree = hash_node(buf, None)
            while len(subtrees) > 1:
                new_subtree = hash_node(subtrees.pop() + new_subtree, None)
            root_len = chunks * CHUNK_SIZE + len(buf)
            return hash_node(subtrees[0] + new_subtree, root_len)
        # Hash a chunk and merge subtrees before adding in bytes from the last
        # read. That way we know we haven't hit EOF, and these nodes definitely
        # aren't the root.
        if len(buf) >= CHUNK_SIZE:
            chunks += 1
            new_subtree = hash_node(buf[:CHUNK_SIZE], None)
            # This is the very cute trick described at the top.
            total_after_merging = bin(chunks).count('1')
            while len(subtrees) + 1 > total_after_merging:
                new_subtree = hash_node(subtrees.pop() + new_subtree, None)
            subtrees.append(new_subtree)
            buf = buf[CHUNK_SIZE:]
        buf = buf + read


def bao_hash_encoded(in_stream):
    root_len = decode_len(in_stream.read(HEADER_SIZE))
    if root_len > CHUNK_SIZE:
        root_node = in_stream.read(2 * DIGEST_SIZE)
        assert len(root_node) == 2 * DIGEST_SIZE
    else:
        root_node = in_stream.read(root_len)
        assert len(root_node) == root_len
    return hash_node(root_node, root_len)


def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        encoded = bao_encode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(encoded)
    elif args["decode"]:
        hash_ = binascii.unhexlify(args["<hash>"])
        bao_decode(sys.stdin.buffer, sys.stdout.buffer, hash_)
    elif args["hash"]:
        if args["--encoded"]:
            hash_ = bao_hash_encoded(sys.stdin.buffer)
        else:
            hash_ = bao_hash(sys.stdin.buffer)
        print(hash_.hex())


if __name__ == "__main__":
    main()
