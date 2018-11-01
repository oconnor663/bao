# Bao [![Build Status](https://travis-ci.org/oconnor663/bao.svg?branch=master)](https://travis-ci.org/oconnor663/bao) [![docs.rs](https://docs.rs/bao/badge.svg)](https://docs.rs/bao)

[Spec](docs/spec.md) —
[Rust Crate](https://crates.io/crates/bao) —
[Rust Docs](https://docs.rs/bao)

**Caution:** Bao is intended to be a cryptographic hash function, but it
hasn't yet been reviewed. The output may change prior to the 1.0
release.

Bao (rhymes with bough 🌳) is a general purpose tree hash for files.
Here's the [full specification](docs/spec.md). What makes a tree hash
different from a regular hash? Depending on how many cores you've got in
your machine, the first thing you might notice is that it's ten times
faster than SHA-2:

![snazzy gif](docs/bao_hash.gif)

Why is `bao hash` so fast? It's mostly parallelism, multiple threads
working on different subtrees at the same time. The demo above is from
the 4-core i5-8250U processor in my laptop, but Bao can scale much
higher. In-memory benchmarks on a 48-core AWS m5.24xlarge instance hit
[91 GB/s of throughput](docs/bao_htop.png). Bao is also based on
BLAKE2b, which was [designed to outperform SHA-1](https://blake2.net/),
and it uses the [fastest SIMD implementation
available](https://github.com/oconnor663/blake2b_simd).

## Encoded files

Apart from parallelism, tree hashes make it possible to verify a file
piece-by-piece rather than all-at-once. This is done by storing both the
input and the entire hash tree together in an encoded file.

Use case: A cryptographic messaging app might want to add support for
attachments, like large video files. If the message metadata includes
the Bao hash of its attachment, the client can stream stream an attached
video without compromising its immutability. (This problem was in fact
the original inspiration for the Bao project.)

```sh
# Create an input file that's a megabyte of random data.
> head -c 1000000 /dev/urandom > f

# Convert it into a Bao encoded file.
> bao encode f f.bao

# Compare the size of the two files. The encoding overhead is small.
> stat -c "%n %s" f f.bao | column -t
f       1000000
f.bao   1015624

# Note that the `bao hash` of the input file is the same as the
# `bao hash --encoded` of the encoded file, but the latter is faster.
> bao hash f
[some hash...]
> bao hash --encoded f.bao
[the same hash...]
> hash=`bao hash --encoded f.bao`

# Stream decoded bytes from the encoded file, using the hash above.
> cmp f <(bao decode $hash f.bao)

# Observe that using the wrong hash to decode results in an error. This
# is also what will happen if we use the right hash but corrupt some
# bytes in the encoded file.
> bad_hash=`echo $hash | sed s/a/b/`
> cmp f <(bao decode $bad_hash f.bao)
Error: Custom { kind: InvalidData, error: StringError("hash mismatch") }
cmp: EOF on /proc/self/fd/11 which is empty
```

## Encoded slices

For situations where you need to serve some verifiable bytes from the
middle of a file, without forcing the recipient to stream whole thing
from the front, you can extract an encoded slice.

Use case: A BitTorrent-like application could fetch different slices of
a file from different peers. Or, a distributed file storage application
could request random slices of an archived file from its storage
providers, to prove that they're honestly storing the file.

```sh
# Using the encoded file from above, extract a 100 KB from somewhere in
# the middle. We'll use start=500000 (500 KB) and count=100000 (100 KB).
> bao slice 500000 100000 f.bao f.slice

# Look at the size of the slice. It contains the 100 KB of content plus
# some overhead. Again, the overhead is small.
> stat -c "%n %s" f.slice
f.slice 104584

# Using the same parameters we used to create the slice, plus the same
# hash we got above from the full encoding, decode the slice.
> bao decode-slice $hash 500000 100000 f.slice > f.slice.out

# Confirm that the decoded output matches the corresponding section from
# the input file. (Note that `tail` numbers bytes starting with 1.)
> tail --bytes=+500001 f | head -c 100000 > expected.out
> cmp f.slice.out expected.out

# Now try decoding the slice with the wrong hash. Again, this will fail,
# as it would if we corrupted some bytes in the slice.
> bao decode-slice $bad_hash 500000 100000 f.slice
Error: Custom { kind: InvalidData, error: StringError("hash mismatch") }
```

## Outboard mode

By default, all of the operations above work with a "combined" encoded
file, that is, one that contains both the content bytes and the tree
hash bytes interleaved. However, sometimes you want to keep them
separate, like to avoid copying the contents of a very large input file.
In these cases, you can use the "outboard" encoded format, via the
`--outboard` flag:

```sh
# Re-encode the input file from above in the outboard mode.
> bao encode f --outboard f.obao

# Compare the size of all these files. The size of the outboard file is
# equal to the overhead of the original combined file.
> stat -c "%n %s" f f.bao f.obao | column -t
f       1000000
f.bao   1015624
f.obao  15624

# Decode the whole file in outboard mode. Note that both the original
# input file and the outboard encoding are passed in as arguments.
> cmp f <(bao decode $hash f --outboard f.obao)
```

## Installing and building from source

The `bao` command line utility is published on
[crates.io](https://crates.io) as the
[`bao_bin`](https://crates.io/crates/bao_bin) crate. To install it, add
`~/.cargo/bin` to your `PATH` and then run:

```sh
cargo install bao_bin
```

To build the binary directly from this repo:

```sh
git clone https://github.com/oconnor663/bao
cd bao/bao_bin
cargo build --release
./target/release/bao --help
```

[`tests/bao.py`](tests/bao.py) is a fully functional second
implementation in Python, designed to be as short and readable as
possible. It's a good starting point for understanding the algorithms
involved, before diving into the Rust code.

The `bao` library crate includes `no_std` support if you set
`default-features = false` in your `Cargo.toml`. Most of the standalone
functions that don't obviously depend on `std` are available. For
example, `bao::encode::encode` is available with a single threaded
implementation, but `bao::encode::encode_to_vec` isn't available. Of the
streaming implementations, only `hash::Writer` is available, because the
encoding and decoding implementations rely more on the `std::io::{Read,
Write, Seek}` interfaces. If there are any callers that want to do
streaming encoding or decoding under `no_std`, please let me know, and
we can figure out which libcore-compatible traits it makes sense to
implement.
