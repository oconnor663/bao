# The Bao Spec

**Caution:** Bao is intended to be a cryptographic hash function, but it hasn't
yet been reviewed. The output may change prior to the 1.0 release.

## Contents

* [The Tree Structure](#the-tree-structure)
* [Security](#security)
* [Combined Encoding Format](#combined-encoding-format)
* [Outboard Encoding Format](#outboard-encoding-format)
* [Slicing Format](#slicing-format)
* [Storage Requirements](#storage-requirements)
* [Design Rationales and Open Questions](#design-rationales-and-open-questions)
* [Other Related Work](#other-related-work)


## The Tree Structure

Bao divides the input up into 4096-byte chunks. The final chunk may be shorter,
but it's never empty unless the input itself is empty. The chunks are arranged
as the leaves of a binary tree. All parent nodes have exactly two children, and
the content of each parent node is the hash of its left child concatenated with
the hash of its right child. When there's an odd number of nodes in a given
level of the tree, the rightmost node is raised to the level above. Here's what
the tree looks like as it grows from 1 to 4 chunks.

```
                                     <parent>                   <parent>
                                      /    \                   /       \
              <parent>          <parent>  [CHUNK]      <parent>         <parent>
               /   \             /   \                  /   \            /   \
[CHUNK]   [CHUNK] [CHUNK]   [CHUNK] [CHUNK]        [CHUNK] [CHUNK]  [CHUNK] [CHUNK]
```

We can also define the tree recursively:

- If a tree/subtree contains 4096 input bytes or less, the tree/subtree is just
  a chunk.
- Otherwise, the tree/subtree is rooted at a parent node, with the input bytes
  divided between its left and right child subtrees. The number of input bytes
  on the left is largest power of 2 times 4096 that's strictly less than the
  total. The remainder, always at least 1 byte, goes on the right.

Hashing nodes is done with BLAKE2b, using the following parameters:

- **Hash length** is 32.
- **Fanout** is 2.
- **Max depth** is 128.
- **Max leaf length** is 4096.
- **Node offset** is 0, unchanged from the default. See the discussion in
  Design Rationales.
- **Node depth** is 0 for chunks and 1 for parent nodes. See the [Security
  section](#security) and also the same discussion as above.
- **Inner hash length** is equal to hash length.

In addition, the root node -- whether it's a chunk or a parent -- is hashed
with two tweaks:

- The input byte length, encoded as a 16-byte little endian integer, is
  appended to the bytes of the node.
- The **last node** BLAKE2 finalization flag is set to true. Note that BLAKE2
  supports setting the last node flag at any time, so hashing the first chunk
  can begin without knowing whether it's the root.

That root node hash is the output of Bao. Here's an example tree, with 8193
bytes of input that are all zero:

```
                            [49e4b8...03170a...](root hash=6254a3...)
                                                /   \
                                               /     \
             [686ede...686ede...](hash=49e4b8...)   [\x00](hash=03170a...)
                            /   \
                           /     \
[\x00 * 4096](hash=686ede...)   [\x00 * 4096](hash=686ede...)
```

We can verify those values on the command line using the `b2sum` utility from
https://github.com/oconnor663/blake2b_simd, which supports the necessary flags
(the coreutils `b2sum` doesn't support `--last-node`):

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
$ left_parent_hash=49e4b80d5b7d8d93224825f26c45987e107bbf2f871d4e5636ac550ff125e082

# Define another alias converting the input length to 8-byte little-endian hex.
$ alias hexint='python3 -c "import sys; print(int(sys.argv[1]).to_bytes(8, \"little\").hex())"'

# Compute the hash of the root node, with the length suffix and last node flag.
$ unhex $left_parent_hash$small_chunk_hash$(hexint 8193) | b2sum -l256 --last-node
6254a3e86396e4ce264ab45915a7ba5e0aa116d22c7deab04a4e29d3f81492da  -

# Verify that this matches the Bao hash of the same input.
$ head -c 8193 /dev/zero | bao hash
6254a3e86396e4ce264ab45915a7ba5e0aa116d22c7deab04a4e29d3f81492da
```

## Security

TODO: I need help fleshing this part out. Perhaps we can use the framework from
[Bertoni et al, *Sufficient conditions for sound tree and sequential hashing
modes* (2009)](https://eprint.iacr.org/2009/210.pdf) to construct a proper
proof. Bao doesn't currently domain-separate the inner parent nodes from the
input chunks though (only the root is domain-separated), and that might be a
precondition of the framework. See Design Rationales below.

The most important security requirement for a tree mode is that it doesn't
create any "new" collisions, that is, collisions in the tree hash that don't
follow from a collision in the underlying hash function. Here's the sketch of a
proof that Bao doesn't create any new collisions:

1. No two inputs can produce a new collision in Bao if they are a different
   length. The last 8 bytes of input to the final hashing step are the input
   length. If the resulting root hashes are the same, that must be a collision
   in the underlying hash. (Note that this assumes the length doesn't overflow.
   See Design Rationales for more discussion.)
2. If two inputs are the same length, their Bao trees have an identical
   structure. This follows from the defintion of Bao, which determines the tree
   structure entirely from the input length.
3. If two different inputs are mapped to identical tree structures, and they
   have a colliding root hash, then some pair of corresponding nodes between
   the two trees must form a collision in the underlying hash.

Another security requirement is that length extension shouldn't be possible. An
attacker has two options for attempting an extension: they can try to append
bytes onto the root node itself, or they can build a larger tree that
incorporates the root hash as a subtree. The first attack is prevented by
assuming that the underlying hash doesn't allow length extension. The second
attack is prevented by using the last node flag to finalize root nodes, which
means they cannot collide with any subtree hash in a valid Bao tree.

## Combined Encoding Format

The combined encoding file format is the contents of the the chunks and parent
nodes of the tree concatenated together in pre-order (that is a parent,
followed by its left subtree, followed by its right subtree), with the 64-bit
little-endian unsigned input length prepended to the very front. This makes the
order of nodes on disk the same as the order in which a depth-first traversal
would encounter them, so a reader decoding the tree from beginning to end
doesn't need to do any seeking. Here's the same example tree above, formatted
as an encoded file and shown as hex:

```
input length    |root parent node  |left parent node  |first chunk|second chunk|last chunk
0120000000000000|49e4b8...03170a...|686ede...686ede...|\x00 * 4096|\x00 * 4096 |\x00
```

Note carefully that this is the mirror of how the root node is hashed. Hashing
the root node *appends* the length as associated data, which makes it possible
to digest parts of the first chunk before knowing whether its the root.
Encoding *prepends* the length, because it's the first thing that the decoder
needs to know. In both cases it's a 64-bit little-endian unsigned integer.

The decoder first reads the 8-byte length from the front. The length indicates
whether the first node is a chunk (<=4096) or a parent (>4096), and it verifies
the hash of root node with the length as associated data. The rest of the tree
structure is completely determined by the length, and the decoder can stream
the whole tree or seek around as needed by the caller. But note that all
decoding operations *must* verify the root. In particular, if the caller asks
to seek to byte 5000 of a 4096-byte encoding, the decoder *must not* skip
verifying the first (only) chunk, because its the root. This ensures that a
decoder will always return an error when the encoded length doesn't match the
root hash

Because of the prepended length, the encoding format is self-delimiting. Most
decoders won't read an encoded file all the way to EOF, and so it's generally
allowed to append extra garbage bytes to a valid encoding. Trailing garbage has
no effect on the content, but it's worth clarifying what is and isn't
guaranteed by the encoding format:

- If the Bao hash of a given input is used in decoding, it will never
  successfully decode anything other than exactly that input. Corruptions in
  the encoding might lead to a partial decoding followed by an error, but any
  partially decoded bytes will always be a prefix of the original input.
- Further, there are no "alternative" hashes for a given input or a given
  encoding. There is at most one hash that can decode any content, even partial
  content followed by an error, from a given encoding. If the decoding is
  complete, that hash is always the Bao hash of the decoded content. If two
  decoding hashes are different, then any content they successfully and
  completely decode is always different.
- However, multiple "different" encoded files can decode using the same hash,
  if they differ only in their trailing garbage. So while there's a unique hash
  for any given input, there's not a unique valid encoded file, and comparing
  encoded files with each other is probably a mistake.

## Outboard Encoding Format

The outboard encoding format is the same as the combined encoding format,
except that all the chunks are omitted. Whenever the decoder would read a
chunk, it instead reads the corresponding offset from the original input file.
This is intended for situations where the benefit of retaining the unmodified
input file is worth the complexity of reading two separate files.

## Slicing Format

The slicing format is very similar to the combined enconding format above. The
only difference is that chunks and parent nodes that wouldn't be encountered in
a given traversal are omitted. For example, if we slice the tree above starting
at input byte 4096 (the beginning of the second chunk), and request any count
of bytes less than or equal to 4096 (up to the end of that chunk), the
resulting slice will be this:

```
input length    |root parent node  |left parent node  |second chunk
0120000000000000|49e4b8...03170a...|686ede...686ede...|\x00 * 4096
```

Although slices can be extracted from either a combined encoding or an outboard
encoding, there is no such thing as an "outboard slice". Slices always include
chunks inline, as the combined encoding does.

Decoding a slice works just like decoding a full encoding. The only difference
is that in cases where the full decoder would normally seek forward, the slice
decoder continues reading in series, all the seeking having been taken care of
by the slice extractor.

Note that requesting a count of 0 bytes is a degenerate case. Only two things
are specified about this case:

- If decoding is successful, the decoded output must be empty.
- The slice must include the root node, and the decoder must verify it.

Current implementations use an approach like "seek forward unconditionally,
extracting all parent nodes encountered in the seek, and then read further as
long as input is needed." In practice that means that parents below the root
are sometimes included in the empty slice and sometimes not. These details may
change, respecting the two guarantees above.

## Storage Requirements

Computing the tree hash requires storing at minimum one hash (32 bytes) for
every level of the tree, in addition to the 336 bytes [required by
BLAKE2b](https://blake2.net/blake2.pdf). Given the 128-bit length counter at
the root and the 4096-byte chunk size (2^12), the largest possible well-defined
Bao tree requires 116 hashes or 3712 bytes of storage overhead.

However, Bao uses a 128-bit counter precisely because filling it is impossible;
that security assumption is baked into all 256-bit hash functions.
Implementations that are concerned about storage space can make much more
practical assumptions about their largets possible input. For example, the
largest supported input for SHA-256 is 2^61 bytes, and a Bao input of that size
requires 49 hashes or 1568 bytes of storage overhead. Implementations can
safely assume that even if they encounter an input that large, they'll never be
able to finish hashing it.

Extremely space-constrained implementations that want to use Bao will need to
define a more aggressive limit for the maximum input size and report failure if
they exceed that size. In some cases, such a limit is already provided by the
protocol they're implementing. For example, the largest possible IPv6
"jumbogram" is 4GiB, and limited to that maximum input size Bao's storage
overhead would be 20 hashes or 640 bytes.

## Design Rationales and Open Questions

### Can we expose the BLAKE2 general parameters through the Bao API?

**Yes, though there are some design choices we need to make.** The general
parameters are the variable output length, secret key, salt, and
personalization string. A future version of this spec will almost certainly
settle on a way to expose them. The salt and personalization will probably be
simple; just apply them to all nodes in the tree.

The right approach for the secret key is less clear. The BLAKE2 spec says:
"Note that tree hashing may be keyed, in which case leaf instances hash the key
followed by a number of bytes equal to (at most) the maximal leaf length." That
remark actually leaves the trickiest detail unsaid, which is that while only
the leaf nodes hash the key bytes, _all_ nodes include the key length as
associated data. This is behavior is visible in the BLAKE2bp [reference
implementation](https://github.com/BLAKE2/BLAKE2/blob/a90684ab3fe788b2ca45076cf9b38335de289f58/ref/blake2bp-ref.c#L65)
and confirmed by its test vectors. Unfortunately, this behavior is actually
impossible to implement with Python's `hashlib.blake2b` API, which ties the key
length and key bytes together. An approach that applied the key bytes to every
node would fit into Python's API, but it would both depart from the spec
conventions and add extra overhead. Implementing Bao in pure Python isn't
necessarily a requirement, but it's useful for generating test vectors, and the
majority of BLAKE2 implementations in the wild have similar limitations.

The variable output length has a similar issue. In BLAKE2bp, the root node's
output length is the hash length parameter, and the leaf nodes' output length
is the inner hash length parameter, with those two parameters set the same way
for all nodes. That's again impossible in the Python API, where the output
length and the hash length parameter are always set together. Bao has the same
problem, because the interior hashes are always 32 bytes (discussed immediately
below). Also for the same reason, a 64-byte Bao output would only have 32
effective bytes of security, so it might be misleading to even offer the longer
digest.

### Why not use the full 64-byte BLAKE2b hash as the inner subtree hash size?

**Storage overhead.** Note that in the [Storage
Requirements](#storage-requirements), the storage overhead is proportional to
the size of a subtree hash. Storing 64-byte hashes would double the overhead.

It's worth noting that BLAKE2b's block size is 128 bytes, so hashing a parent
node takes the same amount of time whether the child hashes are 32 bytes or 64.
However, the 32-byte size does leave room in the block for the root length
suffix, and it's possible that future extensions could implement the general
parameters (discussed above) as additional suffixes.

### Should we stick closer to the BLAKE2 spec when setting node offset and node depth?

**Probaby not.** In the [BLAKE2 spec](https://blake2.net/blake2.pdf), it was
originally intended that each node would use its unique depth/offset pair as
parameters to the hash function. The Security section above made the case that
that approach isn't necessary to prevent collisions, but there could still be
some value in sticking to the letter of the spec. There are a few reasons Bao
doesn't.

One reason is that, by allowing identical subtrees to produce the same hash,
Bao makes it possible to do interesting things with sparse files. For example,
imagine you need to compute the hash of an entire disk, but you know that most
of the disk contains all zeros. You can skip most of the work of hashing it, by
memoizing the hashes of all-zero subtrees. That approach works with any pattern
of bytes that repeats on a subtree boundary. But if we set the node offset
parameter differently in every subtree, memoizing no longer helps.

We're also considering departing from the BLAKE2 spec to implement keying
(above), so there might not be much value in sticking closely to it here.
Computing these values would also require yet another tricky bit twiddling
algorithm over the chunk index.

### Could we use a simpler tree mode, like KangarooTwelve does?

**No, the encoding format requires a full tree.**
[KangarooTwelve](https://keccak.team/kangarootwelve.html) is a modern hash
function based on Keccak/SHA3, and it includes a ["leaves stapled to a
pole"](https://www.cryptologie.net/article/393/kangarootwelve) tree internally
to allow for parallelism in the implementation. This is much simpler to
implement than a full binary tree, and it adds less storage overhead.

However, a shallow tree would limit the usefulness of Bao's encoding and
slicing features. The root node becomes linear in the size of the input, with a
growth factor of 1/8192 in the case of KangarooTwelve. Encoding a video file
several gigabytes in size, for example, would produce a root node approaching a
megabyte. The recipient would need to fetch and buffer the entire root before
verifying any content bytes, and decoding would require heap allocation. The
usefulness of the encoding format would be limited to the space of files big
enough that streaming is valuable, but small enough that the root node is
manageable, and it would preclude most embedded applications. Incremental
update schemes would suffer too, because every update would need to rehash the
large root node.

A two-level tree would also limit parallelism. As noted in the [KangarooTwelve
paper](https://eprint.iacr.org/2016/770.pdf), given enough worker threads
hashing input chunks and adding their hashes to the root, the thread
responsible for hashing the root eventually reaches its own throughput limit.
This happens at a parallelism degree equal to the ratio of the chunk size and
the hash length, 256 in the case of KangarooTwelve. That sounds like an
extraordinary number of threads, but consider that one of Bao's benchmarks is
running on a 96-core AWS machine, and that Bao uses an AVX2 implementation of
BLAKE2b that hashes 4 chunks in parallel per thread. That benchmark is hitting
parallelism degree 384 today. Also consider that Intel's upcoming Cannon Lake
generation of processors will probably support the AVX-512 instruction set
(8-way SIMD) on 16 logical cores, for a parallelism degree of 128 on a
mainstream desktop processor. Now to be fair, this arithmetic is cheating
badly, because logical cores aren't physical cores, and because hashing 4
inputs with SIMD isn't 4x as fast as hashing 1 input. But it's flirting in the
general direction of the truth.

### Should we fall back to serial hashing for messages above some maximum size?

**No.** Many tree modes, including some described in the [BLAKE2
spec](https://blake2.net/blake2.pdf), fall back to a serial mode after the
input reaches some threshold size. The main benefit is that this allows them to
specify a small maximum tree height for reduced memory requirements. However,
one of Bao's main benefits is parallelism over huge files, and falling back to
serial hashing would conflict with that. It would also complicate encoding and
decoding.

### What's the best way to choose the chunk size?

**Open question.** I chose 4096 somewhat arbitrarily, because it seems to be a
common page size, and because the performance overhead seems subjectively small
in testing. But there are many efficiency tradeoffs at the margins, and we
might not be able to settle this question without more real world
implementation experience. See [issue #17](https://github.com/oconnor663/bao/issues/17).

While Bao is intended to be a "one size fits all" hash function, the chunk size
is the parameter that different implementations are most likely to need to
tweak. For example, an embedded implementation that implements decoding (will
there ever be such a thing?) needs to allocate buffer space for an entire
chunk. It's possible that a tiny chunk size would be a hard requirement, and
that cutting the overall throughput by a large factor might not matter.

If an implementation needs to customize the chunk size, it will of course break
compatibility with standard Bao. Such an implementation _must_ set the **max
leaf length** parameter accordingly to avoid any chance of causing collisions.
But note that these variants shouldn't change the max depth; that parameter
only represents the size of the input byte count.

### Would it be more efficient to use an arity larger than 2?

**Maybe, but it would add storage overhead.** There's an efficiency argument
for allowing parent nodes to have 4 children. As noted above, the BLAKE2b block
size is 128 bytes. If we're using hashes that are 32 bytes long, hashing a
parent with 2 children takes just as much time as hashing a parent with 4
children, assuming there are no extra suffixes. That would cut the total number
of parent nodes down by a factor of 3 (because 1/4 + 1/16 + ... = 1/3), with
potentially no additional cost per parent.

However, the storage overhead of this design is actually more than with the
binary tree. While a 4-ary tree is half as tall as a binary tree over the same
number of chunks, its stack needs space for 3 subtree hashes per level, making
total overhead 3/2 times as large. Also, a 4-ary tree would substantially
complicate several algorithms involved in managing the state, like the "cute
trick" we use to figure out how many subtree hashes to merge after each
completed chunk. Overall, the cost of hashing parent nodes is already designed
to be small, and shrinking it further isn't worth these tradeoffs.

## Other Related Work

- the [Tree Hash Exchange (THEX)](https://adc.sourceforge.io/draft-jchapweske-thex-02.html) format
- [Tree Hashing](https://www.cryptolux.org/mediawiki-esc2013/images/c/ca/SL_tree_hashing_esc.pdf),
  2013, a presentation by Stefan Lucks
