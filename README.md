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
original content. Given that hash, `bao decode` will stream verified
content bytes from the encoded file, with an optional seek offset.

`bao slice` takes a start offset and a length of content bytes to read
and extracts the parts of an encoded file needed to read just those
bytes. `bao decode-slice` takes those arguments plus the same hash that
`bao decode` uses, and verifies and outputs the specified content bytes.
Note that `bao hash --encoded` can read an extracted slice just like a
full encoded file.

You can build the `bao` binary from the `bao_bin` sub-crate, like this:

```bash
git clone https://github.com/oconnor663/bao
cd bao/bao_bin
cargo build --release
./target/release/bao --help
```

[`python/bao.py`](python/bao.py) includes a Python implementation in
about 100 lines of code, designed to be as readable as possible.
