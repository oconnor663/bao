#! /usr/bin/python3

# ./swap_content.py <encoded_file>
#
# Reads input from stdin and replaces the content (but not the hashes!) of the
# encoded file with the stdin bytes. If stdin is shorter than the content, the
# remaining content bytes are unmodified. If stdin is longer, only the input up
# to the length of the encoded content is used. Either way, the encoded file
# length is unchanged.
#
# This tool is used to construct corrupted Bao encodings, for testing and
# demos. Normally any difference between two inputs would result in a different
# root node, so a decoder reading the wrong file will abort immediately with no
# output. However, it's possible that corruption in the tree only shows up
# halfway through, and in that case the decoder can emit valid output before
# encountering the corruption and aborting.

import bao
import sys


def swap_recurse(encoded_stream, input_stream, content_len):
    if content_len <= bao.CHUNK_SIZE:
        # We might get fewer input bytes than requested, if the input stream is
        # finished. That's fine. All the writes after that point will be empty,
        # and the rest of the tree will be left as is.
        input_bytes = input_stream.read(content_len)
        encoded_stream.write(input_bytes)
    else:
        # Read past the parent node and then recurse to the children.
        encoded_stream.read(bao.PARENT_SIZE)
        left_len = bao.left_len(content_len)
        swap_recurse(encoded_stream, input_stream, left_len)
        swap_recurse(encoded_stream, input_stream, content_len - left_len)


def main():
    encoded_stream = open(sys.argv[1], "rb+")
    content_len = bao.decode_len(encoded_stream.read(bao.HEADER_SIZE))
    swap_recurse(encoded_stream, sys.stdin.buffer, content_len)


if __name__ == "__main__":
    main()
