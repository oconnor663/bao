# The Bao Spec

## Tree Structure

Bao divides the input up into 4096-byte chunks. The final chunk may be shorter,
but it's never empty unless the input itself is empty. When there's more than
one chunk, pairs of chunks are joined with a parent node in the level above.
The contents of a parent node are the concatenated 256-bit BLAKE2b hashes of
its left and right children, using all default parameters besides the length.
Those children can be either chunks or, in higher levels of the tree, other
parent nodes. When there's an odd number of chunks or parent nodes at any level
of the tree, the rightmost node is raised to the level above unmodified. The
process of pairing off nodes at each level repeats until there's one root node
at the topmost level, which is either a parent node or, in the single chunk
case, that chunk. To hash the root node, there are two extra steps: first the
total input length as a 64-bit little-endian integer is appended to its
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

## Security

[TODO]

Hopefully we can use the framework from [Bertoni et al, *Sufficient conditions
for sound tree and sequential hashing modes*
(2009)](https://eprint.iacr.org/2009/210.pdf).

## Design Alternatives

### Use a chunk size other than 4096 bytes.

See [Issue #17](https://github.com/oconnor663/bao/issues/17).

### Use more of the associated data features from BLAKE2.

BLAKE2 defines several parameters intended for tree hashing. The Bao design
above uses only one of them, the last node flag. That flag is the only
piece of associated data in the BLAKE2 standard that can be set after some
input has already been hashed, which makes it well suited for hashing chunks
incrementally. (If the root node had to be flagged before hashing any of its
bytes, an incremental hasher would need extra space to buffer the first chunk,
in case it turned out to be the root.) As per the Security section above, we
believe that the last node flag coupled with the length suffix is
sufficient to prevent collisions and length extension.

There are two benefits to avoiding the rest of the tree parameters:

1. It's nice not to excessively couple Bao's design to BLAKE2. Bao could
   potentially be generalized over other hash functions, perhaps if future
   research weakens BLAKE2 or offers faster alternatives. For functions like
   SHA-512/256 that don't provide an equivalent of the last node flag (but
   which do prevent length extension), it could be simulated reasonably cheaply
   by appending a 1 byte to the root node and a 0 byte to all others. But if
   Bao depended on several tree parameters, generalizing it to other hash
   functions would be more involved.
2. The **node offset** parameter in particular might be an anti-feature. In the
   Bao design, two subtrees with exactly the same contents will produce the
   same inner hash, regardless of their location in the larger tree. The node
   offset parameter would break that symmetry, by tagging each node with its
   horizontal position within its tree level. Losing that symmetry could
   prevent us from optimizing certain specialized cases. For example, it's
   possible to compute the Bao hash of astronomically large inputs, as long as
   most of the input consists of repeating subtrees. To hash 2^N identical
   chunks, you can first compute the hash of 2^(N-1) chunks, and then
   concatenate that hash twice to construct the root node of the 2^N chunk
   tree. Repeating that shortcut all the way down lets you hash the whole input
   in a logarithmic number of steps. This approach could be useful for hashing
   sparse files or disk images.

If we don't want to use the full set of tree parameters available from BLAKE2
(particularly not the node offset), it seems natural not to use any of them
apart from the minimum necessary for security (namely the last node flag). That
said, some of the others might be helpful for generalizing Bao. The **leaf
maximal byte length** parameter could distinguish a tree that used a customized
chunk size. The **maximal depth** parameter could distinguish a tree that used
something other than 8 bytes to represent its length. And the **fanout**
parameter could could distinguish a tree that allowed more than two child nodes
per parent (see below). If we decide to bless any of these variations in the
official definition of Bao, we might consider setting the relevant parameters,
either in all cases or perhaps, for backwards compatibility, only in the
non-default cases. Note that a variant using a different digest length is
distinguishable in any case, because BLAKE2 always includes the digest length
as associated data.

### Use an arity larger than 2.

Allowing parents to have more than 2 children would complicate things in a few
ways. Parents would have to figure out how to represent empty children. (Should
the parent of a partial subtree have a variable length, or should it add extra
empty chunks onto the end?) Also, the logic in the incremental hasher that
figures out when to merge subtrees would get more difficult. (Currently we rely
on a cute trick where we count the binary 1's in the chunk index, but the
higher-arity version of that trick is more complicated and more expensive.)

That said, there's an efficiency argument for allowing parent nodes to have 4
children. Note that the BLAKE2b block size is 128 bytes. If we're using hashes
that are 32 bytes long, hashing a parent with 2 children takes just as much
time as hashing a parent with 4 children. That would cut the total number of
parent nodes down by a factor of 3 (because 1/4 + 1/16 + ... = 1/3), with
potentially no additional cost per parent.

Two counterpoints to that idea:

1. It relies on the exact choice of 32-byte BLAKE2b hashes, which is the sort
   of design coupling we talked about avoiding in the section above.
2. The gain here applies only to the overhead of hashing parent nodes, which is
   already fairly small.

As an aside, it might seem like using a higher arity would allow the
incremental hasher to keep a shorter stack of subtree hashes. It's true that a
4-ary tree would be half as tall as a binary tree over the same number of
chunks. However, that overlooks an important detail: The 4-ary tree's stack
would need to store up to 3 subtree hashes per level, while the binary tree's
stack only needs to store 1. The binary tree actually wins in this respect.

## Related Work

- Tiger
- https://www.cryptolux.org/mediawiki-esc2013/images/c/ca/SL_tree_hashing_esc.pdf
- Bertoni et al, *Sufficient conditions for sound tree and sequential hashing
  modes*, https://eprint.iacr.org/2009/210.pdf
