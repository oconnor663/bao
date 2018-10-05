# The Tree

Bao divides the input up into 4096* byte chunks. The final chunk may be
shorter, but it's never empty unless the input itself is empty. When there is
more than one chunk, pairs of chunks are joined with a parent node in the level
above. The contents of a parent node are the concatenated 256-bit BLAKE2b
hashes of its left and right children, using all default parameters besides the
length. Those children can be either chunks or, in higher levels of the tree,
other parent nodes. When there's an odd number of chunks or parent nodes at any
level of the tree, the rightmost node is raised to the level above unmodified.
The process of pairing off nodes at each level repeats until there's one root
node at the topmost level, which is either a parent node or, in the single
chunk case, that chunk. To hash the root node, there are two extra steps: first
the total input length as a 64-bit little-endian integer is appended to its
contents, and also the BLAKE2 final node flag is set to true. Those steps
prevent collisions between inputs of different lengths.

The definition above is in an iterative style, but we can also define the
structure recursively:

- If a subtree contains 4096 input bytes or less, the subtree is just a chunk.
- Otherwise, the subtree is rooted at a parent node, with the input bytes
  divided between its left and right child subtrees. The number of bytes on the
  left is largest power of 2 times 4096 that's strictly less than the total.
  The remainder, always at least 1 byte, goes in the right subtree.

The recursive rule relies on an important invariant, that every left subtree is
a perfect binary tree. That is, every left subtree contains a power of 2 number
of chunks, all on the bottom level.

Here's an example tree, with 8193 bytes of input that are all zero:

```
                                    [0x49e4b8...0x03170a...](root hash=6254a3...)
                                                        /   \
                                                       /     \
                 [0x686ede...0x686ede...](hash=49e4b8...)   [0x00](hash=03170a...)
                                   /   \
                                  /     \
       [0x00 * 4096](hash=686ede...)   [0x00 * 4096](hash=686ede...)
```

We can verify those values on the command line using the `b2sum` utility from
https://github.com/oconnor663/blake2b_simd, which supports the necessary flags:

```bash
# Define a short alias for parsing hex.
$ alias unhex='python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))"'
# Compute the hash of the first and second chunks, which are the same.
$ head -c 4096 /dev/zero | b2sum -l256
686ede9288c391e7e05026e56f2f91bfd879987a040ea98445dabc76f55b8e5f  -
$ big_chunk_hash=686ede9288c391e7e05026e56f2f91bfd879987a040ea98445dabc76f55b8e5f
# Compute the hash of the third chunk, which is different.
$ head -c 1 /dev/zero | b2sum -l256
03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314  -
$ small_chunk_hash=03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314
# Compute the hash of the first two chunks' parent node.
$ unhex $big_chunk_hash$big_chunk_hash | b2sum -l256
49e4b80d5b7d8d93224825f26c45987e107bbf2f871d4e5636ac550ff125e082  -
$ parent_hash=49e4b80d5b7d8d93224825f26c45987e107bbf2f871d4e5636ac550ff125e082
# Define another alias converting the input length to 8-byte little-endian hex.
$ alias hexint='python3 -c "import sys; print(int(sys.argv[1]).to_bytes(8, \"little\").hex())"'
# Compute the hash of the root node, with the length suffix and last node flag.
$ unhex $parent_hash$small_chunk_hash$(hexint 8193) | b2sum -l256 --last-node
6254a3e86396e4ce264ab45915a7ba5e0aa116d22c7deab04a4e29d3f81492da  -
# Verify that this matches the bao hash of the same input.
$ head -c 8193 /dev/zero | bao hash
6254a3e86396e4ce264ab45915a7ba5e0aa116d22c7deab04a4e29d3f81492da
```

* The 4096-byte chunk size is an arbitrary design parameter, and it's possible
  we could choose a different value. See discussion at
  https://github.com/oconnor663/bao/issues/17.
