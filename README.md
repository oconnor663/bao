# bao

`bao` (pronounced "bough") is a general purpose tree hash for files.
Tree hashes have two big benefits over regular serial hashes:

- **Parallelism.** A regular hash can only occupy one CPU core, but a
  tree hash with enough input can spread the work over any number of
  cores.
- **Streaming verification.** The only way to verify that a regular file
  matches a hash is to download the entire file. A tree hash makes it
  efficient to stream verified bytes out of a file, or to consume
  arbitrary pieces of a file BitTorrent-style.

`bao hash` is quite fast. The underlying hash function is BLAKE2b, with
an AVX2 implementation provided by
[`blake2b_simd`](https://github.com/oconnor663/blake2b_simd). The input
gets memory mapped and then split among worker threads with
[`rayon`](https://github.com/rayon-rs/rayon). On the i5-8250U processor
in my laptop, it hashes a 1 gigabyte file in 0.25 seconds. By comparison
the fastest Coreutils hash, `sha1sum`, takes 1.32 seconds. If the input
is piped and memory mapping isn't possible, `bao hash` falls back to a
single-threaded streaming implementation.

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

The `encode`, `decode`, and `slice` commands all support an `--outboard`
flag. This mode stores tree data in a separate file apart from the input
bytes, so that you can keep the unmodified input file without taking up
twice as much disk space. The total size of an input file plus an
outboard tree file is the same as the size of an encoded file in the
usual combined mode. Note that if you `slice` the entire input (using
the slice parameters start=0 and len=size), the result is exactly the
same as an entire combined-mode encoding, so `slice` can be an efficient
way of converting from outboard to combined without re-hashing or
writing to disk.

You can build the `bao` binary from the `bao_bin` sub-crate, like this:

```bash
git clone https://github.com/oconnor663/bao
cd bao/bao_bin
cargo build --release
./target/release/bao --help
```

[`python/bao.py`](python/bao.py) includes a Python implementation in
about 100 lines of code, designed to be as readable as possible.
