# The Bao Spec

> **Caution!** Not yet suitable for production use. The output of Bao isn't
stable. Hashes in v0.6 (next) will differ from v0.5 (current), and there might
be more changes before 1.0.

## Contents

* [Tree Structure](#tree-structure)
* [Combined Encoding Format](#combined-encoding-format)
* [Outboard Encoding Format](#outboard-encoding-format)
* [Slice Format](#slice-format)
* [Security](#security)
* [Storage Requirements](#storage-requirements)
* [Performance Notes](#performance-notes)
* [Design Rationales and Open Questions](#design-rationales-and-open-questions)
* [Other Related Work](#other-related-work)


## Tree Structure

Bao divides the input up into 4096-byte chunks. The final chunk may be shorter,
but it's never empty unless the input itself is empty. The chunks are arranged
as the leaves of a binary tree. All parent nodes have exactly two children, and
the content of each parent node is the hash of its left child concatenated with
the hash of its right child. When there's an odd number of nodes in a given
level of the tree, the rightmost node is raised to the level above. Here's what
the tree looks like as it grows from 1 to 4 chunks.

```
                                         <parent>                       <parent>
                                          /    \                      /          \
                <parent>            <parent>  [CHUNK3]         <parent>           <parent>
                 /   \               /   \                     /   \              /   \
[CHUNK1]   [CHUNK1] [CHUNK2]   [CHUNK1] [CHUNK2]         [CHUNK1] [CHUNK2]  [CHUNK3] [CHUNK4]
```

We can also describe the tree recursively:

- If a tree/subtree contains 4096 input bytes or less, the tree/subtree is just
  a chunk.
- Otherwise, the tree/subtree is rooted at a parent node, and its input bytes
  are divided between its left and right child subtrees. The number of input
  bytes on the left is largest power of 2 times 4096 that's strictly less than
  the total. The remainder, always at least 1 byte, goes on the right.

Hashing nodes is done with BLAKE2s, using the following parameters:

- **Hash length** is 32.
- **Fanout** is 2.
- **Max depth** is 64.
- **Max leaf length** is 4096.
- **Node offset** is always 0 (the default).
- **Node depth** is 0 for all chunks and 1 for all parent nodes.
- **Inner hash length** is 32.

In addition, the root node -- whether it's a chunk or a parent -- has the
**last node** finalization flag set to true. Note that BLAKE2 supports setting
the last node flag at any time, so hashing the first chunk can begin without
knowing whether it's the root.

That root node hash is the output of Bao. Here's an example tree, with 8193
bytes of input that are all zero:

```
                        root parent hash=bed2e4...
                        <1926c3...f330e9...>
                                /   \
                               /     \
            parent hash=1926c3...   chunk hash=f330e9...
            <7fbd4a...7fbd4a...>    [\x00]
                    /   \
                   /     \
chunk hash: 7fbd4a...   chunk hash: 7fbd4a...
[\x00 * 4096]           [\x00 * 4096]
```

We can verify those values on the command line using the `b2sum` utility from
[blake2_simd](https://github.com/oconnor663/blake2_simd), which supports the
necessary flags (the coreutils `b2sum` doesn't expose all the BLAKE2
parameters):

```bash
# Define some aliases for hashing nodes. Note that --length and
# --inner-hash-length are in bits, not bytes, for compatibility with coreutils.
$ alias hash_node='b2sum --length=256 --fanout=2 --max-depth=64 --max-leaf-length=4096 --inner-hash-length=256'
$ alias hash_chunk='hash_node --node-depth=0'
$ alias hash_parent='hash_node --node-depth=1'

# Compute the hash of the first and second chunks, which are the same.
$ head -c 4096 /dev/zero | hash_chunk
7fbd4a4dce97d0ed509a76448227aac527cb31e20d03096ea360f974b53d8808  -
$ big_chunk_hash=7fbd4a4dce97d0ed509a76448227aac527cb31e20d03096ea360f974b53d8808

# Compute the hash of the third chunk, which is different.
$ head -c 1 /dev/zero | hash_chunk
f330e9ad408a5f3ff2842b45948730c91a3f4d81f98526400ea7e9ba877dcdb3  -
$ small_chunk_hash=f330e9ad408a5f3ff2842b45948730c91a3f4d81f98526400ea7e9ba877dcdb3

# Define an alias for parsing hex.
$ alias unhex='python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))"'

# Compute the hash of the first two chunks' parent node.
$ unhex $big_chunk_hash$big_chunk_hash | hash_parent
1926c3048e0391cdac5a0b116bd63e03a307e2c10d745b25d24c558e8be2bec9  -
$ left_parent_hash=1926c3048e0391cdac5a0b116bd63e03a307e2c10d745b25d24c558e8be2bec9

# Define another alias converting the input length to 8-byte little-endian hex.
$ alias hexint='python3 -c "import sys; print(int(sys.argv[1]).to_bytes(8, \"little\").hex())"'

# Compute the hash of the root node, with the length suffix and last node flag.
$ unhex $left_parent_hash$small_chunk_hash$(hexint 8193) | hash_parent --last-node
bed2e488d2644ce514036824dd5486c0ad16bd1d4b9ee8e9940f810d8c40284e  -

# Verify that this matches the Bao hash of the same input.
$ head -c 8193 /dev/zero | bao hash
bed2e488d2644ce514036824dd5486c0ad16bd1d4b9ee8e9940f810d8c40284e
```

## Combined Encoding Format

The combined encoding file format is the contents of the chunks and parent
nodes of the tree concatenated together in pre-order (that is a parent,
followed by its left subtree, followed by its right subtree), with the 8-byte
little-endian unsigned input length prepended to the very front. This makes the
order of nodes on disk the same as the order in which a depth-first traversal
would encounter them, so a reader decoding the tree from beginning to end
doesn't need to do any seeking. Here's the same example tree above, formatted
as an encoded file:

```
input length    |root parent node  |left parent node  |first chunk|second chunk|last chunk
0120000000000000|1926c3...f330e9...|7fbd4a...7fbd4a...|000000...  |000000...   |00
```

## Decoder

After parsing the length from the first eight bytes of an encoding, the decoder
traverses the tree by reading parent nodes and chunk nodes. The decoder
verifies the hash of each node as it's read, and it may return the contents of
each valid chunk to the caller immediately. The length itself is considered
validated _when and only when_ the decoder validates the final chunk, either by
validating the entire encoding or by seeking to the end and validating only the
right edge of the tree. The decoder _must not_ expose the length to the caller
in any way before the final chunk is validated. There are a number of ways the
decoder might expose the length, some of which are less obvious than others:

- An explicit `.length()` method. The reference implementation doesn't include
  one, because it would be required to seek internally. Callers who need the
  length in advance will usually do better to store it separately along with
  the hash.
- Reading the empty encoding. Any read of the empty encoding reports EOF,
  thereby exposing the length (zero). The decoder must verify that the final
  chunk (that is, the empty chunk) matches the root hash. Most implementations
  will naturally satisfy this requirement for non-empty encodings as part of
  reading chunk bytes, but it's easy to forget it in the empty case if you
  write code like "current position equals content length therefore EOF."
- Seeking past the end. If I seek to an offset greater than or equal to the
  content length, the next read will return EOF, exposing the length. That
  means either the seek itself or the following read must have validated the
  final chunk.
- Seeking relative to the end. Most seek implementations support something akin to
  [`SeekFrom::End`](https://doc.rust-lang.org/std/io/enum.SeekFrom.html#variant.End).
  That exposes the length through the absolute offset returned by the seek,
  which means the seek itself must validate the final chunk.

For decoders that don't expose a `.length()` method and don't support seeking,
the security requirements can be simplified to "verify the hash of every node
you read, and don't skip the empty chunk." But decoders that do support seeking
need to consider the final chunk requirement very carefully. The decoder is
expected to maintain these guarantees:

- Any byte returned to the caller matches the corresponding byte of the
  original input.
- If EOF is indicated to the caller in any way, either through a read or
  through a seek, it matches the length of the original input.
- If the decoder returns a complete input, the decoding hash must be the unique
  hash of that input.

Note one non-guarantee in particular: The encoding itself may be mutable.
Multiple "different" encodings may decode to the same input, under the same
hash. For example, appending extra bytes to a valid encoding may have no effect
on decoding.

## Outboard Encoding Format

The outboard encoding format is the same as the combined encoding format,
except that all the chunks are omitted. Whenever the decoder would read a
chunk, it instead reads the corresponding offset from the original input file.
This is intended for situations where the benefit of retaining the unmodified
input file is worth the complexity of reading two separate files to decode.

## Slice Format

The slice format is very similar to the combined encoding format above. The
only difference is that chunks and parent nodes that wouldn't be encountered in
a given traversal are omitted. For example, if we slice the tree above starting
at input byte 4096 (the beginning of the second chunk), and request any count
of bytes less than or equal to 4096 (up to the end of that chunk), the
resulting slice will be this:

```
input length    |root parent node  |left parent node  |second chunk
0120000000000000|1926c3...f330e9...|7fbd4a...7fbd4a...|000000...
```

Although slices can be extracted from either a combined encoding or an outboard
encoding, there is no such thing as an "outboard slice". Slices always include
chunks inline, as the combined encoding does. A slice that includes the entire
input is exactly the same as the combined encoding of that input.

Decoding a slice works just like decoding a combined encoding. The only
difference is that in cases where the decoder would normally seek forward, the
slice decoder continues reading in series, since all the seeking has been taken
care of by the slice extractor.

There are some unspecified edge cases in the slice parameters:

- A starting point past the end of the input.
- A byte count larger than the available input after the starting point.
- A byte count of zero.

A future version of the spec will settle on the behavior in these cases.

## Security

When designing a tree mode, there are pitfalls that can compromise the security
of the underlying hash. For example, if one input produces a tree with bytes X
at the root node, and we choose another input to be those same bytes X, do
those two inputs result in the same root hash? If so, that's a hash collision,
regardless of the security of the underlying hash function. Or if one input
results in a root hash Y, could Y be incorporated as a subtree hash in another
tree without knowing the input that produced it? If so, that's a length
extension, again regardless of the properties of the underlying hash. There are
many possible variants of these problems.

[*Sufficient conditions for sound tree and sequential hashing
modes*](https://eprint.iacr.org/2009/210.pdf) (2009), authored by the
Keccak/SHA-3 team, lays out a minimal set of requirements for a tree mode, to
prevent attacks like the above. This section describes how Bao satisfies those
requirements. They are:

1. **Tree decodability.** The exact definition of this property is fairly
   technical, but the gist of it is that it needs to be impossible to take a
   valid tree, add more child nodes to it somewhere, and wind up with another
   valid tree.
2. **Message completeness.** It needs to be possible to reconstruct the
   original message from the tree.
3. **Final-node separability.** Again the exact definition is fairly technical,
   but the gist is that it needs to be impossible for any root node and any
   non-root node to have the same hash.

We ensure **tree decodability** by domain-separating parent nodes from leaf
nodes (chunks) with the **node depth** parameter. BLAKE2's parameters are
functionally similar to the frame bits used in the paper, in that two inputs
with different parameters always produce a different hash, though the
parameters are implemented as tweaks to the IV rather than by concatenating
them with the input. Because chunks are domain-separated from parent nodes,
adding children to a chunk is always invalid. That, coupled with the fact that
parent nodes are always full and never have room for more children, means that
adding nodes to a valid tree is always invalid.

**Message completeness** is of course a basic design requirement of the
encoding format, and all the bits of the format are included in the tree.

We ensure **final-node separability** by domain-separating the root node from
the rest of the tree with the **final node flag**. BLAKE2's final node flag is
similar to its other parameters, except that it's an input to the last call to
the compression function rather than a tweak to the IVs. In practice, that
allows an implementation to start hashing the first chunk immediately rather
than buffering it, and to set the final node flag at the end if the first chunk
turns out to be the only chunk and therefore the root.

## Storage Requirements

A Bao implementation needs to store one hash (32 bytes) for every level of the
tree. The largest supported input is 2<sup>64</sup> - 1 bytes. Given the
4096-byte chunk size (2<sup>12</sup>), that's 2<sup>52</sup> leaf nodes, or a
maximum tree height of 52. Storing 52 hashes, 32 bytes each, requires 1664
bytes, in addition to the [168 bytes](https://blake2.net/blake2.pdf) required
by BLAKE2s. For comparison, the TLS record buffer is 16384 bytes.

Extremely space-constrained implementations that want to use Bao have to define
a more aggressive limit for their maximum input size. In some cases, such a
limit is already provided by the protocol they're implementing. For example,
the largest possible IPv6 "jumbogram" is 4 GiB. Limited to that maximum input
size, Bao's storage overhead would be 20 hashes or 640 bytes.

## Performance Notes

To get the highest possible throughput, the Bao implementation uses both
threads and SIMD. Threads let the computation take advantage of multiple CPU
cores, and SIMD gives each thread a higher overall throughput by hashing
multiple chunks at once.

Multithreading in the current implementation is done with the
[`join`](https://docs.rs/rayon/latest/rayon/fn.join.html) function from the
[Rayon](https://github.com/rayon-rs/rayon) library. It splits up its input
recursively -- an excellent fit for traversing a tree -- and allows worker
threads to "steal" the right half of the split, if they happen to be free. Once
the global thread pool is initialized, this approach doesn't require any heap
allocations.

There are two different approaches to using SIMD to speed up BLAKE2. The more
common way is to optimize a single instance, and that's the approach that eeks
past SHA-1 in the [BLAKE2b benchmarks](https://blake2.net/). But the more
efficient way, when you have multiple inputs, is to run multiple instances in
parallel on a single thread. Samuel Neves discussed the second approach in [a
2012 paper](https://eprint.iacr.org/2012/275.pdf) and implemented it in the
[reference AVX2 implementation of
BLAKE2s](https://github.com/sneves/blake2-avx2/blob/master/blake2sp.c). The
overall throughput is about quadruple that of a single BLAKE2s instance. The
[`blake2s_simd`](https://github.com/oconnor663/blake2_simd) implementation
includes a
[`hash_many`](https://docs.rs/blake2s_simd/0.5.1/blake2s_simd/many/fn.hash_many.html)
interface, which provides the same speedup for multiple instances of BLAKE2s,
and Bao uses that interface to make each worker thread hash multiple chunks in
parallel. Note that the main downside of BLAKE2sp is that it hardcodes 8-way
parallelism, such that moving to a higher degree of parallelism would change
the output. But `hash_many` doesn't have that limitation, and when AVX-512
becomes more widespread, it will execute 16-way parallelism without changing
the output or the API.

## Design Rationales and Open Questions

### Why BLAKE2s instead of BLAKE2b?

**It's faster, both on small 32-bit embedded systems and on modern 64-bit
systems with SIMD.** There are two important differences between BLAKE2s and
BLAKE2b:

- BLAKE2s operates on 32-bit words, while BLAKE2b operates on 64-bit words.
- BLAKE2s does 10 rounds of compression, while BLAKE2b does 12. This is related
  to their 128-bit vs 256-bit security levels and the larger state size of
  BLAKE2b, which needs more rounds to get good diffusion.

This is similar to the difference between SHA-256 and SHA-512. With both BLAKE2
and SHA-2, many sources note that the 64-bit variants have better performance
on 64-bit systems. This is true for hashing a single input, because 64-bit
instructions handle twice as much input without being twice as slow. On modern
SIMD hardware, a single instance of BLAKE2b can also take advantage of 256-bit
vector arithmetic, while BLAKE2s can only make use of 128-bit vectors.

However, when the implementation is designed to hash multiple inputs in
parallel, the effect of SIMD is different. In the parallel mode, both BLAKE2b
and BLAKE2s can use vectors of any size, by accumulating words from a
corresponding number of different inputs. Besides being more flexible, this
approach is also substantially more efficient, because the diagonalization step
in the BLAKE2 compression function disappears. With 32-bit words and 64-bit
words on a level playing field in terms of SIMD throughput, the remaining
performance difference between the two functions is that BLAKE2s does fewer
rounds, which makes it faster.

That's the story for long inputs, but for short inputs there are more factors
to consider. With just a few bytes of input, both BLAKE2s and BLAKE2b will
compress a single block, and most of that block will be padded with zeros. In
that case it's not average throughput that matters, but the time it takes to
hash a single block. Here BLAKE2s wins again, both because of its smaller round
count and because of its smaller block size.

On the other hand, there's a regime in the middle where BLAKE2b scores some
points. For inputs that are one chunk long, there's nothing to parallelize, and
the higher single-instance throughput of BLAKE2b wins on 64-bit machines. Also
for inputs that are a few chunks long, the lower parallelism degree of BLAKE2b
helps make earlier use of SIMD. For example, a parallel implementation of
BLAKE2b using 256-bit vectors executes 4 hashes at once, so an 8-chunk input
can be efficiently split between 2 threads. But a parallel implementation of
BLAKE2s using 256-bit vectors executes 8 hashes at once, so the 8-chunk input
has no room for a second thread, and a 4-chunk input would be stuck using
128-bit vectors. In general it takes twice as many chunks for BLAKE2s to make
use of any given SIMD vector width. However, this advantage for BLAKE2b comes
with several caveats:

- It assumes a constant chunk size, but the chunk size is a free parameter in
  the Bao design. Bao could make up the difference by halving the chunk size,
  probably with only a few percentage points of overall throughput sacrificed
  to parent node overhead. See the next section.
- Performance differences matter more at the extremes. For extremely large
  inputs, BLAKE2s wins because its lower round count leads to higher overall
  throughput. For extremely limited hardware without 64-bit arithmetic or SIMD,
  BLAKE2s wins because of its 32-bit words.
- It's possible to parallelize Bao across multiple inputs just like we
  parallelize BLAKE2s across multiple inputs. In fact, inputs up to one chunk
  long are just a single BLAKE2s hash, and the parallel BLAKE2s implementation
  could be reused as-is to parallelize the Bao hashes of those short inputs.
  It's unlikely that anyone will go through the trouble of implementing this in
  practice, but an application with a critical bottleneck hashing
  moderate-length inputs has this option.

### What's the best way to choose the chunk size?

**Open question.** There are many efficiency tradeoffs at the margins. As noted
above, the main advantage of a small chunk size is that it allows the
implementation to parallelize more work for inputs that are only a few chunks
long. The advantage of a large chunk size is that it reduces the number of
parent nodes in the tree and the overhead of hashing them. I chose 4096
somewhat arbitrarily, because it seems to be a common page size, and because
the performance overhead is subjectively small in testing. But different
applications are likely to have different priorities around this tradeoff, and
we won't be able to settle this question without more experiments. See [issue
17](https://github.com/oconnor663/bao/issues/17).

Another consideration might be how much buffer space a streaming implementation
needs to allocate to take full advantage of SIMD. The widest SIMD instruction
set available on x86 today is AVX-512, which can run 16 BLAKE2s hashes in
parallel. With a chunk size of 4096 bytes, a 16-chunk buffer is 64 KiB, which
is already e.g. the [default maximum stack buffer size under musl
libc](https://wiki.musl-libc.org/functional-differences-from-glibc.html#Thread_stack_size).
That's a small motivation not to use chunks larger than 4096 bytes.

### Does Bao have a "high security" variant?

**No.** A 256-bit digest with its 128-bit security level is enough for
practically any cryptographic application, which is why everyone uses SHA-256
for TLS certificates and why the Intel SHA Extensions don't include SHA-512.
Higher security levels waste cycles, and longer digests waste bandwidth. Also
having multiple variants of the same algorithm complicates implementations and
confuses people.

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
associated data. This is behavior is visible in the BLAKE2sp [reference
implementation](https://github.com/BLAKE2/BLAKE2/blob/a90684ab3fe788b2ca45076cf9b38335de289f58/ref/blake2sp-ref.c#L64)
and confirmed by its test vectors. Unfortunately, this behavior is actually
impossible to implement with Python's `hashlib.blake2s` API, which ties the key
length and key bytes together. An approach that applied the key bytes to every
node would fit into Python's API, but it would both depart from the spec
conventions and add extra overhead. Implementing Bao in pure Python isn't
necessarily a requirement, but the majority of BLAKE2 implementations in the
wild have similar limitations.

The variable output length has a similar issue. In BLAKE2sp, the root node's
output length is the hash length parameter, and the leaf nodes' output length
is the inner hash length parameter, with those two parameters set the same way
for all nodes. That's again impossible in the Python API, where the output
length and the hash length parameter are always set together. Bao has the same
problem, because the interior subtree hashes are always 32 bytes.

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

Also, we're already departing from the BLAKE2 spec in our use of the last node
flag. The spec intended it to be set for all nodes on the right edge of the
tree, but we only set it for the root node. It doesn't seem worth it to make
implementations do more bookkeeping to be slightly-more-but-still-not-entirely
compliant with the spec.

### Could we use a simpler tree mode, like KangarooTwelve does?

**No, the encoding format requires a full tree.**
[KangarooTwelve](https://keccak.team/kangarootwelve.html) is a modern hash
function based on Keccak/SHA3, and it includes a ["leaves stapled to a
pole"](https://www.cryptologie.net/article/393/kangarootwelve) tree internally
to allow for parallelism in the implementation. This is much simpler to
implement than a full binary tree, and it adds less storage overhead.

However, a shallow tree would limit the usefulness of Bao's encoding and
slicing features. The root node becomes linear in the size of the input.
Encoding a gigabyte file, for example, would produce a root node that's several
megabytes. The recipient would need to fetch and buffer the entire root before
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
If the root hash has the same throughput as the leaves, this happens at a
parallelism degree equal to the ratio of the chunk size and the hash length,
256 in the case of KangarooTwelve. In practice, devoting an entire core to a
single instance roughly doubles that one instance's throughput, bringing the
max degree to 512.

That sounds like an impossibly high number, but consider that one of Bao's
benchmarks runs on a 48-physical-core AWS "m5.24xlarge" machine, and that the
AVX-512 version of BLAKE2s ([preliminary
benchmarks](https://github.com/oconnor663/blake2s_simd/issues/1#issuecomment-484572123))
will hash 16 chunks in parallel per thread. That machine supports parallelism
degree 768 today.

### Should we fall back to serial hashing for messages above some maximum size?

**No.** Many tree modes, including some described in the [BLAKE2
spec](https://blake2.net/blake2.pdf), fall back to a serial mode after some
threshold. That allows them to specify a small maximum tree height for reduced
memory requirements. However, one of Bao's main benefits is parallelism over
huge files, and falling back to serial hashing would conflict with that. It
would also complicate encoding and decoding.

### Is 64 bits large enough for the length counter?

**Yes.** Every filesystem in use today has a maximum file size of
2<sup>64</sup> bytes or less. It's possible that some trickery with sparse
files (more discussion above) might let you effectively hash something that
large, but at that point there's no practical limit to your input size and no
particular reason to assume that 2<sup>128</sup> or 2<sup>256</sup> bytes would
be enough.

Bao's decoding features are designed to work with the IO interfaces of
mainstream programming languages, particularly around streaming and seeking.
These interfaces are [usually
restricted](https://doc.rust-lang.org/std/io/enum.SeekFrom.html) to 64-bit
sizes and offsets. If Bao supported longer streams in theory, implementations
would need to handle more unrepresentable edge cases. (Though even with a
64-bit counter, the maximum _encoded_ file size can exceed 64 bits, and a
perfect decoder implementation needs to seek twice to reach bytes near the end
of max-size encodings. In practice the decoder returns an overflow error.)

Implementations also need to decide how much storage overhead is reasonable. If
the counter was 128 bits, it would still make almost no sense to allocate space
for a 128-level tree. The recommended default would probably be to assume a
maximum of 52 levels like today, but it would put the burden of choice on each
implementation.

### Could a similar design be based on a different underlying hash function?

**Yes, as long as the underlying hash prevents length extension.** SHA-256 and
SHA-512 aren't suitable, but SHA-512/256 and SHA-3 could be.

Domain separation between the root and non-root nodes, and between chunks and
parent nodes, is a security requirement. For hash functions without associated
data parameters, you can achieve domain separation with a small amount of
overhead by appending some bits to every node. See for example the [Sakura
coding](https://keccak.team/files/Sakura.pdf), also designed by the
Keccak/SHA-3 team. Note that the chunk/parent distinguisher may be an
initialization parameter (as `node_depth` is), but the root/non-root
distinguisher needs to be a finalization parameter (as `last_node` is) or an
input suffix. Making the root/non-root distinguisher part of initialization
would force the implementation to either buffer the first chunk or to hash it
both ways.

As noted above, there's no "high security" variant of Bao. However, in some
future world with large quantum computers, it could theoretically make sense to
define a new hash function targetting a 256-bit security level. We could
achieve that by replacing BLAKE2s with BLAKE2b with very few other changes.

### Would hashing the length as associated data improve the security of the decoder?

**No, not for a correct decoder.** An attacker modifying the length bytes can't
produce any observable result, other than the errors that are also possible by
modifying or truncating the rest of the encoding. The story is more complicated
if we consider "sloppy" implementations that accept some invalid encodings, in
which case hashing the length could mitigate some attacks but would also create
some new ones. An earlier version of the Bao design did hash the length bytes,
but the current design doesn't.

Let's start by considering a correct decoder. What happens if a
man-in-the-middle attacker tweaks the length header in between encoding and
decoding? Small tweaks change the expected length of the final chunk. For
example, if you subtract one from the length, the final chunk might go from
4096 bytes to 4095 bytes. Assuming the collision resistance of BLAKE2, the 4095
byte chunk will necessarily have a different hash, and validating it will lead
to a hash mismatch error. Adding one to the length would be similar. Either no
additional bytes are available at the end to supply the read, leading or an IO
error, or an extra byte is available somehow, leading to a hash mismatch.
Larger tweaks have a bigger effect on the expected structure of the tree.
Growing the tree leads to chunk hashes being reinterpreted as parent hashes,
and shrinking the tree leads to parent hashes being reinterpreted as chunk
hashes. Since chunks and parents are domain separated from each other, this
also leads to hash mismatch errors in the tree, in particular always including
some node along the right edge.

Those observations are the reason behind the "final chunk requirement" for
decoders. That is, a decoder must always validate the final chunk before
exposing the length to the caller in any way. Because an attacker tweaking the
length will always invalidate the final chunk, this guarantees that the
modified length value will never be observed outside of the decoder. Length
tweaks might or might not invalidate earlier chunks before the final one, and
decoding some chunks might succeed before the caller eventually hits an error,
but that's indistinguishable from simple corruption or truncation at the same
point in the tree.

So, what happens if the decoder gets sloppy? Of course the implementation could
neglect to check any hashes at all, providing no security. Assuming the
implementation does check hashes, there are couple other subtle mistakes that
can still come up in practice (insofar as I made them myself in early versions
of the reference implementation).

The first one, we just mentioned: failure to uphold the "final chunk
requirement". As a special case, recall that the empty tree consists of a
single empty chunk; if the decoder neglects to validate that empty chunk and
skips right to its EOF state, then the empty encoding wouldn't actually
validate anything at all, making it appear valid under _any_ root hash. More
generally, if the decoder seeks past EOF or relative to EOF without validating
the final chunk first, an attacker could effectively truncate encodings without
detection by shortening the length, or change the target offset of EOF-relative
seeks.

The other likely mistake is "short reads". The IO interfaces in most languages
are based on a `read` function which _usually_ returns as many bytes as you ask
it to but which _may_ return fewer for any reason. Implementations need to
either call such functions in a loop until they get the bytes they need, or use
some higher level wrapper that does the same. Implementations that neglect to
call `read` in a loop will often appear to work in tests, but will be prone to
spurious failures in less common IO settings like reading from a pipe or a
socket. This mistake also opens up a class of attacks. An attacker might modify
the length header of an encoding, for example creating an encoding with 9
content bytes but a length header of 10. In this case, a correct decoder would
fail with an unexpected-end-of-file error, but an incorrect decoder might
"short read" just the 9 bytes without noticing the discrepancy and then
successfully validate them. That exposes the caller to inconsistencies that the
attacker can control: The length of all the bytes read (9) doesn't match the
offset returned by seeking to EOF (10), and like the "final chunk requirement"
issue above, an attacker can again change the target offset of EOF-relative
seeks.

With those two classes of attacks in mind, we can come back to the original
question: Would hashing the length as associated data (probably as a suffix to
the root node) mitigate any of the attacks above for sloppy implementations?
The answer is some yes and some no.

The most egregious "final chunk requirement" vulnerability above -- validating
nothing at all in the case of an empty encoding -- remains a pitfall regardless
of associated data. Seek-past-EOF also remains a pitfall but in a slightly
modified form: the implementation might detect the modified length if it
validates the root node before seeking, but forgetting to validate the root
node would be the same class of mistake as forgetting to validate the final
chunk. However, the decoder would do better in any scenario where you actually
tried to read chunk data; getting to a chunk means validating the root node on
your way down the tree, and bad associated data would fail validation at that
point.

The "short reads" vulnerabilities above would also be partially mitigated. In a
scenario where the attacker corrupts a "legitimate" encoding by changing its
length header after the fact, hashing the length as associated data would
detect the corruption and prevent the attack. But in a scenario where the
attacker constructs both the encoding and the hash used to decode it, the
attacker may craft an "illegitimate" root hash that _expects_ an inconsistent
length header. (A typical encoder doesn't expose any way for the caller to put
an arbitrary value in the length header, but there's nothing stopping an
attacker from doing it.) In this case the inconsistent length pitfall would
remain: the root node would validate with the bad length as associated data,
the final chunk would validate with a short read, and once again the length of
all the bytes read wouldn't match the offset returned by seeking to EOF.

If that were the whole story -- that hashing the length as associated data
mitigated some attacks on sloppy implementations -- that would be some
motivation to do it. However, that last scenario above actually leads to a new
class of attacks, by violating Bao's "no decoding collisions" guarantee. That
is, no input should ever decode (successfully, to completion) under more than
one hash. (And naturally the one hash an input does decode under must be the
hash of itself.) The illegitimate encoding above and its exotic root hash
constitute a "decoding collision" with the legitimate encoding they're derived
from. To put yourself in the shoes of a caller who might care about this
property, imagine you have a dictionary containing Bao encodings indexed by the
hashes that decode them. If you find that a given string's hash isn't present
as a key in your dictionary, is it safe for you to assume that no encoding in
your dictionary will decode to that string? Bao says yes, you may assume that.
And maybe equally importantly, callers in that scenario _will_ assume that
without bothering to read the spec. In this sense, including the length as
associated data would actually make sloppy implementations _less_ secure, by
giving attackers a way to create decoding collisions.

Earlier versions of Bao did append the length to the root node, instead of
using a chunk/parent distinguisher. A proper distinguisher (the `node_depth`
initialization parameter) was added later, both to better fit the [*Sufficient
conditions*](https://eprint.iacr.org/2009/210.pdf) framework and to avoid
issues around integer overflow. At that point the length suffix was redundant,
and it also incurred some performance overhead in the short message case, where
a one-block message would require two blocks of compression. It was dropped
mainly for that performance reason, since the sloppy implementation concerns
above aren't decisive either way.

### Would it be more efficient to use an arity larger than 2?

[Open question, there are memory footprint concerns, but also a workaround with
state words is possible.]

### Should Bao use the node offset parameter to prevent caching?

[Open question.]

## Other Related Work

- The [Tree Hash
  Exchange](https://adc.sourceforge.io/draft-jchapweske-thex-02.html) format
  (2003). THEX and Bao have similar tree structures, and both specify a binary
  format for encoding the tree to enable incremental decoding. THEX uses a
  breadth-first rather than depth-first encoding layout, however, which makes
  the decoder's storage requirements much larger. Also, as noted by the
  Keccak/SHA-3 team in [*Sufficient
  conditions*](https://eprint.iacr.org/2009/210.pdf), THEX doesn't
  domain-separate its root node, so it's vulnerable to length extension
  regardless of the security of the underlying hash function.
- [Tree
  Hashing](https://www.cryptolux.org/mediawiki-esc2013/images/c/ca/SL_tree_hashing_esc.pdf)
  (2013), a presentation by Stefan Lucks, discussing the requirements for
  standardizing a tree hashing mode.
- [RFC 6962](https://tools.ietf.org/html/rfc6962) uses a similar tree layout
  and growth strategy.
