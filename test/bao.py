#! /usr/bin/env python3

# This is an example implementation of bao, with the goal of being as readable
# as possible and generating test vectors. There are a few differences that
# make this code much simpler than the Rust version:
#
# 1. This version's encode implementation buffers all input and output in
#    memory. The Rust version uses a more complicated tree-flipping strategy to
#    avoid using extra storage.
# 2. This version isn't incremental. The Rust version provides incremental
#    encoders and decoders, which accept small reads and writes from the
#    caller, and that require more bookkeeping.
# 3. This version doesn't support arbitrary seeking. The most complicated bit
#    of bookkeeping in the Rust version is seeking in the incremental decoder.
#
# Some more specific details about how each part of this implementation works:
#
# *bao_decode*, *bao_slice*, and *bao_decode_slice* are recursive streaming
# implementations. Recursion is easy here because the length header at the
# start of the encoding tells us all we need to know about the layout of the
# tree. The pre-order layout means that neither of the decode functions needs
# to seek (though bao_slice does, to skip the parts that aren't in the slice).
#
# *bao_hash* is an iterative streaming implementation, which is closer to an
# incremental implementation than the recursive functions are. Recursion
# doesn't work well here, because we don't know the length of the input in
# advance. Instead, we keep a stack of subtrees filled so far, merging them as
# we go along. There is a very cute trick, where the number of subtree hashes
# that should remain in the stack is the same as the number of 1's in the
# binary representation of the count of chunks so far. (E.g. If you've read 255
# chunks so far, then you have 8 partial subtrees. One of 128 chunks, one of 64
# chunks, and so on. After you read the 256th chunk, you can merge all of those
# into a single subtree.) That, plus the fact that merging is always done
# smallest-to-largest / at the top of the stack, means that we don't need to
# remember the size of each subtree; just the hash is enough.
#
# *bao_encode* is a recursive implementation, but as noted above, it's not
# streaming. Instead, it buffers the entire input and output in memory. The
# Rust implementation uses either memory mapped files or a more complicated
# tree-flipping strategy to avoid hogging memory like this. The tree-flipping
# approach is to write the output tree first in a post-order layout, and then
# to do a second pass back-to-front to flip it in place to pre-order. Without
# knowing the total length of the input, a one-pass design wouldn't know how
# much space to leave for pre-order parent nodes.

__doc__ = """\
Usage: bao.py encode [--outboard=<file>]
       bao.py decode <hash> [--outboard=<file>]
       bao.py hash [--encoded]
       bao.py slice <start> <len> [--outboard=<file>]
       bao.py decode-slice <hash> <start> <len>
"""

import binascii
import docopt
import hashlib
import hmac
import sys

CHUNK_SIZE = 4096
HASH_SIZE = 32
PARENT_SIZE = 2 * HASH_SIZE
HEADER_SIZE = 8


def encode_len(content_len):
    return content_len.to_bytes(HEADER_SIZE, "little")


# Python is very permissive with reads and slices, and can silently return
# fewer bytes than requested, so we explicitly check the expected length here.
# Parsing a header that's shorter than 8 bytes could trick us into accepting an
# invalid encoding, which would lead to a "reverse collision" (two different
# hashes that decode to the same input).
def decode_len(len_bytes):
    assert len(len_bytes) == HEADER_SIZE, "not enough bytes"
    return int.from_bytes(len_bytes, "little")


# The root node (whether it's a chunk or a parent) is hashed with the Blake2
# "last node" flag set, and with the total content length as a suffix. In that
# case, the finalization parameter is the content length as an integer. All
# interior nodes set finalization=None.
def hash_node(node, finalization):
    state = hashlib.blake2b(
        last_node=(finalization is not None), digest_size=HASH_SIZE)
    state.update(node)
    if finalization is not None:
        state.update(encode_len(finalization))
    return state.digest()


def verify_node(buf, node_size, finalization, expected_hash):
    # As in decode_len, it's crucial to be strict with lengths, to prevent a
    # "reverse collision".
    assert node_size <= len(buf), "not enough bytes"
    node_bytes = buf[:node_size]
    found_hash = hash_node(node_bytes, finalization)
    # Compare digests in constant time. It might matter to some callers.
    assert hmac.compare_digest(expected_hash, found_hash), "hash mismatch"


# Left subtrees contain the largest possible power of two chunks, with at least
# one byte left for the right subtree.
def left_len(parent_len):
    available_chunks = (parent_len - 1) // CHUNK_SIZE
    power_of_two_chunks = 2**(available_chunks.bit_length() - 1)
    return CHUNK_SIZE * power_of_two_chunks


def bao_encode(buf, *, outboard=False):
    def encode_recurse(buf, finalization):
        if len(buf) <= CHUNK_SIZE:
            return hash_node(buf, finalization), b"" if outboard else buf
        llen = left_len(len(buf))
        # Interior nodes have no len suffix.
        left_hash, left_encoded = encode_recurse(buf[:llen], None)
        right_hash, right_encoded = encode_recurse(buf[llen:], None)
        node = left_hash + right_hash
        encoded = node + left_encoded + right_encoded
        return hash_node(node, finalization), encoded

    # Only this topmost call sets a non-None finalization.
    finalization = len(buf)
    hash_, encoded = encode_recurse(buf, finalization)
    # The final output prefixes the 8 byte encoded length.
    return encode_len(finalization) + encoded


def bao_decode(input_stream, output_stream, hash_, *, outboard_stream=None):
    tree_stream = outboard_stream or input_stream

    def decode_recurse(hash_, content_len, finalization):
        if content_len <= CHUNK_SIZE:
            chunk = input_stream.read(content_len)
            verify_node(chunk, content_len, finalization, hash_)
            output_stream.write(chunk)
        else:
            parent = tree_stream.read(PARENT_SIZE)
            verify_node(parent, PARENT_SIZE, finalization, hash_)
            left_hash, right_hash = parent[:HASH_SIZE], parent[HASH_SIZE:]
            llen = left_len(content_len)
            # Interior nodes have no len suffix.
            decode_recurse(left_hash, llen, None)
            decode_recurse(right_hash, content_len - llen, None)

    # The first 8 bytes are the encoded content len.
    content_len = decode_len(tree_stream.read(HEADER_SIZE))
    decode_recurse(hash_, content_len, content_len)


def bao_hash(input_stream):
    buf = b""
    chunks = 0
    subtrees = []
    while True:
        # We ask for CHUNK_SIZE bytes, but be careful, we can always get fewer.
        read = input_stream.read(CHUNK_SIZE)
        # If the read is EOF, do a final rollup merge of all the subtrees we
        # have, and pass the finalization flag for hashing the root node.
        if not read:
            if chunks == 0:
                return hash_node(buf, len(buf))
            new_subtree = hash_node(buf, None)
            while len(subtrees) > 1:
                new_subtree = hash_node(subtrees.pop() + new_subtree, None)
            content_len = chunks * CHUNK_SIZE + len(buf)
            return hash_node(subtrees[0] + new_subtree, content_len)
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


def bao_hash_encoded(input_stream):
    content_len = decode_len(input_stream.read(HEADER_SIZE))
    if content_len > CHUNK_SIZE:
        root_node = input_stream.read(PARENT_SIZE)
        assert len(root_node) == PARENT_SIZE
    else:
        root_node = input_stream.read(content_len)
        assert len(root_node) == content_len
    return hash_node(root_node, content_len)


# Round up to the next full chunk, and remember that the empty tree still
# counts as one chunk.
def count_chunks(content_len):
    if content_len == 0:
        return 1
    return (content_len + CHUNK_SIZE - 1) // CHUNK_SIZE


def bao_slice(input_stream,
              output_stream,
              slice_start,
              slice_len,
              outboard_stream=None):
    tree_stream = outboard_stream or input_stream

    # Note that the root node is always included, regardless of whether the
    # start is after EOF or the len is zero. This means the recipient always
    # verifies the root hash.
    def slice_recurse(subtree_start, subtree_len, is_root):
        slice_end = slice_start + slice_len
        subtree_end = subtree_start + subtree_len
        if subtree_end <= slice_start and not is_root:
            # Seek past the current subtree. Note that if there are N chunks in
            # a subtree, there are always N-1 parent nodes.
            parent_nodes_size = PARENT_SIZE * (count_chunks(subtree_len) - 1)
            # `1` here means seek from the current position.
            tree_stream.seek(parent_nodes_size, 1)
            input_stream.seek(subtree_len, 1)
        elif slice_end <= subtree_start and not is_root:
            # We've sliced all the requested content, and we're done.
            pass
        elif subtree_len <= CHUNK_SIZE:
            # The current subtree is just a chunk. Read the whole thing. The
            # recipient will need the whole thing to verify its hash,
            # regardless of whether it overlaps slice_end.
            chunk = input_stream.read(subtree_len)
            output_stream.write(chunk)
        else:
            # We need to read a parent node and recurse into the current
            # subtree. Note that is_root is always False after this point.
            parent = tree_stream.read(PARENT_SIZE)
            output_stream.write(parent)
            llen = left_len(subtree_len)
            slice_recurse(subtree_start, llen, False)
            slice_recurse(subtree_start + llen, subtree_len - llen, False)

    content_len_bytes = tree_stream.read(HEADER_SIZE)
    output_stream.write(content_len_bytes)
    content_len = decode_len(content_len_bytes)
    slice_recurse(0, content_len, True)


# Note that unlike bao_slice, there is no optional outboard parameter. Slices
# can be created from either a combined our outboard tree, but the resulting
# slice itself is always combined.
def bao_decode_slice(input_stream, output_stream, hash_, slice_start,
                     slice_len):
    # As above, note that the root node is always included, regardless of
    # whether the start is after EOF or the len is zero. This means the
    # recipient always verifies the root hash.
    def decode_slice_recurse(subtree_start, subtree_len, subtree_hash,
                             finalization):
        slice_end = slice_start + slice_len
        subtree_end = subtree_start + subtree_len
        if subtree_end <= slice_start and finalization is None:
            # This subtree isn't part of the slice. Keep going.
            pass
        elif slice_end <= subtree_start and finalization is None:
            # We've verified all the requested content, and we're done.
            pass
        elif subtree_len <= CHUNK_SIZE:
            # The current subtree is just a chunk. Verify the whole thing, and
            # then output however many bytes we need.
            chunk = input_stream.read(subtree_len)
            verify_node(chunk, subtree_len, finalization, subtree_hash)
            chunk_start = max(0, min(subtree_len, slice_start - subtree_start))
            chunk_end = max(0, min(subtree_len, slice_end - subtree_start))
            output_stream.write(chunk[chunk_start:chunk_end])
        else:
            # We need to read a parent node and recurse into the current
            # subtree. Note that the finalization is always None after this
            # point.
            parent = input_stream.read(PARENT_SIZE)
            verify_node(parent, PARENT_SIZE, finalization, subtree_hash)
            left_hash, right_hash = parent[:HASH_SIZE], parent[HASH_SIZE:]
            llen = left_len(subtree_len)
            decode_slice_recurse(subtree_start, llen, left_hash, None)
            decode_slice_recurse(subtree_start + llen, subtree_len - llen,
                                 right_hash, None)

    content_len_bytes = input_stream.read(HEADER_SIZE)
    content_len = decode_len(content_len_bytes)
    decode_slice_recurse(0, content_len, hash_, content_len)


def main():
    args = docopt.docopt(__doc__)
    if args["encode"]:
        outboard = False
        output_file = sys.stdout.buffer
        if args["--outboard"] is not None:
            outboard = True
            output_file = open(args["--outboard"], "wb")
        encoded = bao_encode(sys.stdin.buffer.read(), outboard=outboard)
        output_file.write(encoded)
    elif args["decode"]:
        hash_ = binascii.unhexlify(args["<hash>"])
        outboard_stream = None
        if args["--outboard"] is not None:
            outboard_stream = open(args["--outboard"], "rb")
        bao_decode(
            sys.stdin.buffer,
            sys.stdout.buffer,
            hash_,
            outboard_stream=outboard_stream)
    elif args["hash"]:
        if args["--encoded"]:
            hash_ = bao_hash_encoded(sys.stdin.buffer)
        else:
            hash_ = bao_hash(sys.stdin.buffer)
        print(hash_.hex())
    elif args["slice"]:
        outboard_stream = None
        if args["--outboard"] is not None:
            outboard_stream = open(args["--outboard"], "rb")
        bao_slice(sys.stdin.buffer, sys.stdout.buffer, int(args["<start>"]),
                  int(args["<len>"]), outboard_stream)
    elif args["decode-slice"]:
        hash_ = binascii.unhexlify(args["<hash>"])
        bao_decode_slice(sys.stdin.buffer, sys.stdout.buffer, hash_,
                         int(args["<start>"]), int(args["<len>"]))


if __name__ == "__main__":
    main()
