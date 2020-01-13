> Bao is based on the BLAKE3 standard. An [earlier version of
> Bao](spec_0.9.1.md) specified its own custom tree mode, which eventually grew
> into BLAKE3.

# The Bao Spec

## Contents

* [Combined Encoding Format](#combined-encoding-format)
* [Outboard Encoding Format](#outboard-encoding-format)
* [Slice Format](#slice-format)
* [Decoder](#decoder)
* [Discussion](#discussion)
  + [Would hashing the length as associated data improve the security of the decoder?](#would-hashing-the-length-as-associated-data-improve-the-security-of-the-decoder)
  + [Why is the encoding format malleable?](#why-is-the-encoding-format-malleable)


## Combined Encoding Format

The combined encoding file format is the contents of the chunks and parent nodes of the
[BLAKE3 tree](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
concatenated together in pre-order (that is a parent, followed by its left
subtree, followed by its right subtree), with the 8-byte little-endian unsigned
input length prepended to the very front. This makes the order of nodes on disk
the same as the order in which a depth-first traversal would encounter them, so
a decoder reading the tree from beginning to end doesn't need to do any
seeking. Here's the example input of 2049 zero bytes (two full chunks and a
third chunk with just one byte), formatted as an encoded file:

```
input length    |root parent node  |left parent node  |first chunk|second chunk|last chunk
0120000000000000|a04fc7...c37466...|91715a...f0eef3...|000000...  |000000...   |00
```

## Outboard Encoding Format

The outboard encoding format is the same as the combined encoding format,
except that all the chunks are omitted. In outboard mode, whenever the decoder
would read a chunk, it instead reads it from the original input file. This
makes the encoding much smaller than the input, with the downside that the
decoder needs to read from two streams.

## Slice Format

The slice format is very similar to the combined encoding format above. The
difference is that the caller requests a specific start point and byte count,
and chunks and parent nodes that wouldn't be encountered when seeking to that
start point and reading that many bytes are omitted. For example, if we slice
the tree above starting at input byte 1024 (the beginning of the second chunk),
and request any count of bytes less than or equal to 1024 (up to the end of
that chunk), the resulting slice will be this:

```
input length    |root parent node  |left parent node  |second chunk
0120000000000000|a04fc7...c37466...|91715a...f0eef3...|000000...
```

Although slices can be extracted from both combined and outboard encodings,
there is no such thing as an "outboard slice". Slices always include chunks
inline, as the combined encoding does. A slice that includes the entire input
is exactly the same as the combined encoding of that input.

Decoding a slice works just like decoding a combined encoding. The only
difference is that in cases where the decoder would normally seek forward to
skip over a subtree, the slice decoder keeps reading without a seek, since the
subtree was already skipped by the slice extractor.

A slice always includes at least one chunk, though in the empty encoding case
that chunk is empty. If the requested byte count is zero, that's equivalent to
a byte count of one, such that the chunk containing the start point is included
in the slice. If the requested start point is at or past the end of the
content, the final chunk is included. (See also the "final chunk requirement"
below.) Apart from that, no parents or chunks after the end of the requested
bytes are included. Either the slice extractor or the slice decoder may return
an error if the requested bytes exceed the end of the content (strict bounds
checking), or they may cap the requested bytes (permissive bounds checking).
The reference implementation is permissive.

## Decoder

After parsing the length from the first eight bytes of an encoding, the decoder
traverses the tree by reading parent nodes and chunk nodes. The decoder
verifies the chaining value (CV) of each node as it's read, and it may return
the contents of each valid chunk to the caller immediately. CVs are computed as per the
[BLAKE3 spec](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
The length itself is considered validated _when and only when_ the decoder
validates the final chunk, either by validating the entire encoding or by
seeking to the end and validating only the right edge of the tree. The decoder
_must not_ expose the length to the caller in any way before the final chunk is
validated. There are a number of ways the decoder might expose the length, some
of which are less obvious than others:

- An explicit `.length()` method. The reference implementation doesn't include
  one, because it would be required to seek internally. Callers who need the
  length in advance will usually do better to store it separately along with
  the hash.
- Reading the empty encoding. Any read of the empty encoding reports EOF,
  thereby exposing the length (zero). The decoder must verify that the final
  chunk (that is, the empty chunk) matches the root hash. Most implementations
  will naturally satisfy this requirement for non-empty encodings as part of
  reading chunk bytes, but it's easy to forget it in the empty case by assuming
  that you're finished whenever the current position equals the content length.
- Seeking past the end. If I seek to an offset greater than or equal to the
  content length, the next read will return EOF, exposing the length. That
  means either the seek itself or the following read must have validated the
  final chunk.
- Seeking relative to the end. Most seek implementations support something akin to
  [`SeekFrom::End`](https://doc.rust-lang.org/std/io/enum.SeekFrom.html#variant.End).
  That exposes the length through the absolute offset returned by the seek,
  which means the seek itself must validate the final chunk.

For decoders that don't expose a `.length()` method and don't support seeking,
the security requirements can be simplified to "verify the CV of every node you
read, and don't skip the empty chunk." But decoders that do support seeking
need to consider the final chunk requirement very carefully. The decoder is
expected to maintain these guarantees, even in the face of a man-in-the-middle
attacker who modifies the encoded bytes:

- Any output byte returned by the decoder matches the corresponding input byte
  from the original input.
- If EOF is indicated to the caller in any way, either through a read or
  through a seek, it matches the length of the original input.
- If the decoder reads a complete output to EOF, the decoding hash must be the
  BLAKE3 hash of that output. There are no "decoding collisions" where two
  different hashes decode the same output to EOF. Two different hashes may
  decode the same output, however, if at least one of them terminates with an
  error before EOF.

Note one non-guarantee in particular: The encoding itself may be malleable.
Multiple "different" encodings may decode to the same input, under the same
hash. See the [discussion below](#why-is-the-encoding-format-malleable) for
more on this.

## Discussion

### Would hashing the length as associated data improve the security of the decoder?

**No, not for a correct implementation.** An attacker modifying the length
bytes can't produce any observable result, other than the errors that are also
possible by modifying or truncating the rest of the encoding. The story is more
complicated if we consider "sloppy" implementations that accept some invalid
encodings, in which case hashing the length could mitigate some attacks but
would also create some new ones. An earlier version of the Bao design did hash
the length bytes, but the current design doesn't. This has the nice property
that the `bao hash` of a file is the same as the regular BLAKE3 hash.

Let's start by considering a correct decoder. What happens if a
man-in-the-middle attacker tweaks the length header in between encoding and
decoding? Small tweaks change the expected length of the final chunk. For
example, if you subtract one from the length, the final chunk might go from 10
bytes to 9 bytes. Assuming the collision resistance of BLAKE3, the 9-byte chunk
will necessarily have a different CV, and validating it will lead to a hash
mismatch error. Adding one to the length would be similar. Either no additional
bytes are available at the end to supply the read, leading to an IO error, or
an extra byte is available somehow, leading to a hash mismatch. Larger tweaks
have a bigger effect on the expected structure of the tree. Growing the tree
leads to chunk CVs being reinterpreted as parent CVs, and shrinking the tree
leads to parent CVs being reinterpreted as chunk CVs. Since chunks and parents
are domain separated from each other, this also leads to hash mismatch errors
in the tree, in particular always including some node along the right edge.

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
neglect to check any CVs at all, providing no security. Assuming the
implementation does check CVs, there are couple other subtle mistakes that can
still come up in practice (insofar as I made them myself in early versions of
Bao).

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
one hash. (And the one hash an input does decode under must be the BLAKE3 hash
of itself.) The illegitimate encoding above and its exotic root hash constitute
a "decoding collision" with the legitimate encoding they're derived from. To
put yourself in the shoes of a caller who might care about this property,
imagine you have a dictionary containing Bao encodings indexed by the BLAKE3
hashes that decode them. If you find that a given string's hash isn't present
as a key in your dictionary, is it safe for you to assume that no encoding in
your dictionary will decode to that string? Bao says yes, you may assume that.
And maybe equally importantly, callers in that scenario _will_ assume that
without bothering to read the spec. In this sense, including the length as
associated data would actually make sloppy implementations _less_ secure, by
giving attackers a way to create decoding collisions.

Earlier versions of Bao did append the length to the root node, instead of
using a chunk/parent distinguisher. A proper distinguisher was added later (the
`node_depth` initialization parameter, as Bao was based on BLAKE2 at that time),
both to better fit the [*Sufficient conditions*](https://eprint.iacr.org/2009/210.pdf)
framework and to avoid issues around integer overflow. At that point the length
suffix was redundant, and it also incurred some performance overhead in the
short message case, where a one-block message would require two blocks of
compression. It was dropped mainly for that performance reason, since the
sloppy implementation concerns above aren't decisive either way.

### Why is the encoding format malleable?

**Because the decoder doesn't read EOF from the encoding.** For example, if the
decoder reads the 8-byte length header and parses a length of 10 bytes, its
next read will be exactly 10 bytes. Since that's the final and only chunk,
decoding is finished, and the decoder won't do any more reads. Typically the
encoded file would have EOF after 18 bytes, so that another read would have
returned zero bytes anyway. However, the encoded file may also have "trailing
garbage" after byte 18. Since the decoder never looks at those bytes, they have
no effect on decoding. That means that two "different looking" encoded files,
which differ in their trailing garbage, can successfully decode to the same
output.

Note that this only concerns decoding, not hashing. There's no such thing as
trailing garbage in the context of hashing, because hashing operates on raw
input bytes rather than on the encoding format, and because hashing necessarily
reads its input to EOF. Rather, this concerns applications that might want to
compare two encoded files byte-for-byte, maybe as a shortcut to predict whether
decoding them would give the same result. That logic would be broken in the
presence of trailing garbage added by a bug or by an attacker. The only valid
way to learn anything about the contents of an encoded file is to decode it.

Another scenario that might lead to malleability is that a decoder might not
verify all parent nodes. For example, if the decoder sees that an encoding is 8
chunks long, and it has buffer space for all 8 chunks, it might skip over the
encoded parent nodes and just reconstruct the whole tree from its chunks. The
reference decoder doesn't do this, in part because it could hide encoder bugs
that lead to incorrect parent nodes. But if an implementation is careful not to
emit any chunk bytes to the caller until all of them have been verified against
the root hash, it can skip reading parent nodes like this without violating the
security requirements. In this case, those parent nodes would be malleable.

As discussed above, a "sloppy" decoder might also ignore some mutations in the
length header, without failing decoding. That's strictly incorrect, and it
violates security requirements related to the original input length, but the
possibility that a buggy implementation might do that is yet another reason to
assume that encoded bytes are malleable. To be clear though, none of the
scenarios discussed in this section violate the guarantee that decoded bytes
match the original input.
