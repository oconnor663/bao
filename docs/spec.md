# The Bao Spec

**Caution:** Bao is intended to be a cryptographic hash function, but it hasn't
yet been reviewed. The output may change prior to the 1.0 release.

## The Tree Structure

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
total input length as a 64-bit little-endian unsigned integer is appended to
its contents, and also the BLAKE2 final node flag is set to true. Those steps
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
precondition of the framework. See Design Alternatives below.

The most important security requirement for a tree mode is that it doesn't
create any "new" collisions, that is, collisions in the tree hash that don't
follow from a collision in the underlying hash function. Here's the sketch of a
proof that Bao doesn't create any new collisions:

1. No two inputs can produce a new collision in Bao if they are a different
   length. The last 8 bytes of input to the final hashing step are the input
   length. If the resulting root hashes are the same, that must be a collision
   in the underlying hash. (Note that this assumes the length doesn't overflow.
   See Design Alternatives for more discussion.)
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

## The Encoding format

The encoding file format is the contents of the the chunks and parent nodes of
the tree concatenated together in pre-order (that is a parent, followed by its
left subtree, followed by its right subtree), with the 64-bit little-endian
unsigned input length prepended to the very front. This makes the order of
nodes on disk the same as the order in which a depth-first traversal would
encounter them, so a reader decoding the tree from beginning to end doesn't
need to do any seeking. Here's the same example tree above, formatted as an
encoded file and shown as hex:

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
verifying the first chunk, because its the root. This ensures that a decoder
will always return an error when the encoded length doesn't match the root hash

Because of the prepended length, the encoding format is self-delimiting. Most
decoders won't read an encoded file all the way to EOF, and so it's generally
allowed to append extra garbage bytes to a valid encoding. It's worth
clarifying what is and isn't guaranteed by the encoded format:

- There is never more than one *hash* that can decode a given encoding. (Though
  there might not be any, if it's corrupt.) If decoding succeeds, then the
  decoding hash is always identical to the Bao hash of the decoded content.
- However, many encoded *files* can successfully decode under the same hash, if
  they differ only in their trailing garbage. In general, callers should avoid
  reading or comparing the bytes of encoded files, other than to decode them.

### The Outboard Encoding Format

The outboard encoding format is the same as above (the "combined" encoding
format), except that all the chunks are omitted. Whenever the decoder would
read a chunk, it instead reads the corresponding offset from the original input
file. This is intended for situations where the benefit of retaining the input
file is worth managing two separate files.

## The Slicing Format

The slicing format is very similar to the enconding format above. The only
difference is that chunks and parent nodes that wouldn't be encountered in a
given traversal are omitted. For example, if we slice the tree above starting
at input byte 4096 (the beginning of the second chunk), and request any count
of bytes less than or equal to 4096 (up to the end of that chunk), the
resulting slice will be this:

```
input length    |root parent node  |left parent node  |second chunk
0120000000000000|49e4b8...03170a...|686ede...686ede...|\x00 * 4096
```

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

## Design Alternatives

### Use a chunk size other than 4096 bytes.

There's an efficiency argument for using a larger chunk size, with several
tradeoffs involved. See [issue #17](https://github.com/oconnor663/bao/issues/17).
Probably other implementors need to weigh in on this question before it can be
settled.

### Domain-separate the chunks from non-root parent nodes.

As discussed in Security above, adding chunk-parent domain separation might
make it possible to prove the soundness of the tree using Bertoni et al's
framework. It would also make it harder to generate collisions by overflowing
the input length counter, discussed immediately below. Thoses are theoretical
benefits, though, and it's not clear whether complicating the definition of Bao
would be worth it. See [issue #19](https://github.com/oconnor663/bao/issues/19).

It might be tempting to drop the length bytes from the root hash entirely, if
we domain-separate the parent nodes instead. It's possible that that could be
proven to also prevent collisions, with (very slightly) less overhead. However,
verifying the length as part of the root hash is important for the decoder. Say
an encoding has a real length of 7 chunks, but an attacker tweaks it to say
it's only 5 chunks. If the victim then starts decoding and tries to seek to the
6th chunk, what happens? The decoder would probably report a successful EOF
from the following read, even though the real file is supposed to have bytes at
that point. That's an unacceptable mutation of the encoding. The current
approach verifies the reported length as associated data for the root, and
always verifies the root regardless of the seek target. If want to drop our
ability to verify the length, we would need some other way to detect truncation
when seeking.

### Use something larger than 64 bits for the length counter.

2<sup>64</sup> bytes, or about 16 exbibytes, is large enough that it would be
completely impractical to hash that much input. Given that my laptop can hash
roughly 1 GB/sec per core, hashing 16 EiB would take 585 core-years. 16 EiB is
also the maximum supported file size for most modern filesystems. It's possible
that some trickery with sparse files might let you effectively hash more than
16 EiB (see the discussion below about the node offset parameter and
efficiently hashing sparse files), but at that point there's no practical limit
to your input size and no particular reason to assume that 2<sup>128</sup> or
2<sup>256</sup> bytes would be enough.

If the length counter was allowed to overflow, that could be used by an
attacker to generate collisions. For example, if X is the contents of the root
node (that is, two subtree hashes concatenated) of a file that's
2<sup>64</sup>+64 bytes long, then the hash of that giant file would collide
with the hash of the 64-byte file whose contents are exactly X. Some thoughts
about this scenario:

- SHA-256 use a similar mechanism, with a 64-bit counter appended to the end of
  the input. (Though SHA-256 counts input bits rather than input bytes.) An
  overflow in the SHA-256 counter probably wouldn't immediately lead to a
  collision, but it's nevertheless undefined in the standard.
- The above collision relies on conflating an input chunk with a parent node.
  That could be prevented by domain-separating the two, as noted above.
- A correct implementation of Bao should arguably refuse to hash this much
  input, instead failing with a panic or an abort. However, in practice, most
  hash function implementations don't actually check for length overflow. And
  it's not clear that panicking is acceptable in a hash implementation, if it's
  used in a critical system and expected to be infallible.
- Exploiting this kind of collision would be very difficult in practice. The
  attacker would need the victim to repeat the enormous computation. Though
  perhaps some sort of sparse file protocol could manage it.

### Use more of the associated data features from BLAKE2.

BLAKE2 defines several parameters intended for tree hashing. The Bao design
above uses only one of them, the last node flag. That flag is the only piece of
associated data in the BLAKE2 standard that can be set after some input has
already been hashed, which makes it well suited for hashing chunks
incrementally. (If the root node had to be flagged before hashing any of its
bytes, an incremental hasher would need to buffer the whole first chunk) As per
the Security section above, we believe that the last node flag coupled with the
length suffix is sufficient to prevent collisions and length extension.

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

### Use some kind of Rabin fingerprinting scheme.

The idea of Rabin fingerprinting is that you use some window function over the
input to determine chunk boundaries psuedorandomly. The advantage is that
insertions in the middle of the file only affect block boundaries in their
neighborhood. So perhaps insertions in an encoded file could avoid rehashing
the entire file.

A longer discussion of this idea is at [issue #8](https://github.com/oconnor663/bao/issues/8).
The high points are:

1. This is much more complicated than it sounds. Chunk boundaries aren't the
   only thing that matters. Shifting subtree boundaries would also be
   expensive, so a hierarchy of fingerprints would be needed. And a scheme that
   supported top-down parallelism would be more complicated still.
2. Decoders are responsible for rejecting "non-standard" encodings of an input,
   to maintain the invariant that only the unique Bao hash of an input can
   successfully decode it. A fingerprinting scheme would make it dramatically
   more difficult to verify that an encoding was canonical, and Bao is very
   interested in minimizing the number of rules an implementer could possibly
   forget to check.
3. As it says in the intro, Bao is intended "for files". Standard filesystems
   don't support efficient insertion in the middle of a file anyway.
   Applications that need to do this sort of thing usually have to implement
   something like a B-tree on disk, at which point they probably aren't
   interested in the Bao hash of the file itself.

### Include the content length in the hash itself, rather than in the encoding.

Prepending the encoding with the input length means that the decoder state
machine needs extra states to parse it, and it might have been nice to simplify
it by making sure the caller always tells the decoder the length in advance,
perhaps by concatenating the length to the hash. But that would be problematic
for a couple reasons:

- Most callers don't care about the input length, and extending the length of
  the hash to store it would waste space.
- There are situations where the input length is supposed to be secret,
  particularly when a cryptographic hash is used as a MAC. Publishing it might
  not be acceptable.

## Related Work

- the [Tree Hash Exchange (THEX)](https://adc.sourceforge.io/draft-jchapweske-thex-02.html) format
- [Tree Hashing](https://www.cryptolux.org/mediawiki-esc2013/images/c/ca/SL_tree_hashing_esc.pdf),
  2013, a presentation by Stefan Lucks
