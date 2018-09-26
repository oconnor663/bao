# bao [![Build Status](https://travis-ci.org/oconnor663/bao.svg?branch=master)](https://travis-ci.org/oconnor663/bao) [![Build status](https://ci.appveyor.com/api/projects/status/yt1vchury2xtqphk/branch/master?svg=true)](https://ci.appveyor.com/project/oconnor663/bao/branch/master) [![docs.rs](https://docs.rs/bao/badge.svg)](https://docs.rs/bao)

[Repo](https://github.com/oconnor663/bao) —
[Docs](https://docs.rs/bao) —
[Crate](https://crates.io/crates/bao)

`bao` (rhymes with bough 🌳) is a general purpose tree hash for files.
Tree hashes have two big benefits over regular serial hashes:

- **Parallelism.** Regular hashes are single threaded, but a tree hash
  with enough input can split the work over any number of threads. That
  makes `bao hash` many times faster than similar commands like
  `md5sum`.
- **Streaming.** To verify a regular hash, you need to hash the whole
  input over again, but a tree hash can verify small sections of input
  by themselves. Given the input hash, `bao decode` can stream verified
  bytes from an encoded version of the input file. `bao slice` can
  extract sections of that encoded file, which can be verified
  independently using the same hash.

`bao hash` is quite fast. The underlying hash function is BLAKE2b, with
an AVX2 implementation provided by
[`blake2b_simd`](https://github.com/oconnor663/blake2b_simd). The input
gets memory mapped and then split among worker threads with
[`rayon`](https://github.com/rayon-rs/rayon). On the i5-8250U processor
in my laptop, it hashes a 1 gigabyte file in 0.25 seconds, or 4 GB/s
including startup and IO. By comparison the fastest Coreutils hash,
`sha1sum`, takes 1.32 seconds. Large input in-memory benchmarks on an
AWS m5.24xlarge instance (96 cores) measure 60 GB/s throughput. (That's
61% of the per-core throughput of BLAKE2b, mostly due to [CPU frequency
scaling](https://blog.cloudflare.com/on-the-dangers-of-intels-frequency-scaling).)
When input is piped and memory mapping isn't possible, `bao hash` falls
back to a single-threaded streaming implementation.

`bao encode` copies its input and produces an encoded file with a small
header and subtree hashes interspersed throughout, currently 1.5% larger
than the original. `bao hash --encoded` can quickly extract the root
hash from the encoded file, the same result as running `bao hash` on the
original content. Given that hash, `bao decode` will **stream verified
content bytes** from the encoded file, with an optional `--start`
offset. `decode` can read from a pipe or a socket, unless `--start` is
used, in which case it needs to be able to seek.

`bao slice` takes a start offset and a byte count and extracts the parts
of an encoded file needed to read just those bytes. `bao decode-slice`
takes the same offset and count plus the **same hash that `decode`
uses**, reads in the output of `slice`, and outputs the specified range
of content bytes. While `slice` and `decode --start=...` require
seeking, and so generally require a full encoded file on disk,
`decode-slice` doesn't need to seek and can stream from a pipe or a
socket like a regular `decode`. Note that `bao hash --encoded` can hash
an extracted slice just like a full encoded file.

The `encode`, `decode`, `slice`, and `hash` commands all support an
`--outboard` flag. This mode reads or writes tree data in a separate
file apart from the input bytes, so that you can keep the unmodified
input file without taking up twice as much disk space. The total size of
an input file plus an outboard tree file is the same as the size of an
encoded file in the default combined mode. Note that if you `slice` the
entire input (using the slice parameters start=0 and len=size), the
result is exactly the same as an entire combined-mode encoding, so
`slice` can be an efficient way of converting from outboard to combined
without re-hashing or writing to disk.

You can build the `bao` binary from the `bao_bin` sub-crate, like this:

```bash
git clone https://github.com/oconnor663/bao
cd bao/bao_bin
cargo build --release
./target/release/bao --help
```

[`tests/bao.py`](tests/bao.py) includes a Python implementation designed
to be as short and readable as possible.

There is `no_std` support if you set `default-features = false` in your
`Cargo.toml`. Most of the standalone functions that don't obviously
depend on `std` are available. For example, `encode::encode` is
available with a single threaded implementation, but
`encode::encode_to_vec` isn't avialable. Of the streaming
implementations, only `hash::Writer` is available, because the encoding
and decoding implementations rely more on the `std::io` traits. If there
are any callers that want to do streaming encoding or decoding under
`no_std`, please let me know, and we can figure out which
libcore-compatible IO interfaces it makes sense to use.
