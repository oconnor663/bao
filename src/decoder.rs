use simple::{from_header_bytes, left_subregion_len};
use unverified::Unverified;

#[derive(Debug, Clone, Copy)]
enum State {
    NoHeader,
    Eof,
    Chunk(Region),
    Node(Region),
}

#[derive(Debug, Clone)]
pub struct Decoder {
    header_hash: ::Digest,
    header: Option<Region>,
    position: u64,
    stack: Vec<Node>,
}

impl Decoder {
    pub fn new(header_hash: &::Digest) -> Self {
        Self {
            header_hash: *header_hash,
            header: None,
            position: 0,
            stack: Vec::new(),
        }
    }

    pub fn len(&self) -> Option<u64> {
        self.header.map(|h| h.len())
    }

    fn state(&self) -> State {
        let header = if let Some(region) = self.header {
            region
        } else {
            return State::NoHeader;
        };
        if self.position >= header.end {
            return State::Eof;
        }
        let current_region = if let Some(node) = self.stack.last() {
            // invariant here: the current position is inside the last node
            if node.left.contains(self.position) {
                node.left
            } else {
                node.right
            }
        } else {
            header
        };
        if current_region.len() <= ::CHUNK_SIZE as u64 {
            State::Chunk(current_region)
        } else {
            State::Node(current_region)
        }
    }

    pub fn seek(&mut self, position: u64) {
        // Setting the position breaks state()'s invariant, since now we might
        // be outside the bounds of the last node in the stack. We have to fix
        // it before we return.
        self.position = position;

        // If we don't have the header yet, or if we're EOF, short circuit.
        let header_end = self.header.map(|r| r.end).unwrap_or(0);
        if self.position >= header_end {
            return;
        }

        // Otherwise, pop off all nodes that don't contain the current
        // position. Note that the first node (if any) will never be popped.
        while let Some(&node) = self.stack.last() {
            if node.contains(position) {
                break;
            }
            self.stack.pop();
        }
    }

    // Give the (encoded_offset, size) needed in the next call to feed(). A
    // size of zero means EOF.
    pub fn needed(&self) -> (u64, usize) {
        match self.state() {
            State::NoHeader => (0, ::HEADER_SIZE),
            State::Eof => (0, 0),
            State::Chunk(r) => (r.encoded_offset, r.len() as usize),
            State::Node(r) => (r.encoded_offset, ::NODE_SIZE),
        }
    }

    // Returns (consumed, output), where output is Some() when a chunk was
    // consumed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> ::Result<(usize, &'a [u8])> {
        // Immediately shadow input with a wrapper type that only gives us
        // bytes when the hash is correct.
        let mut input = Unverified::wrap(input);

        match self.state() {
            State::NoHeader => self.feed_header(&mut input),
            State::Eof => Ok((0, &[])),
            State::Chunk(r) => self.feed_chunk(&mut input, r),
            State::Node(r) => self.feed_node(&mut input, r),
        }
    }

    fn feed_header<'a>(&mut self, input: &mut Unverified<'a>) -> ::Result<(usize, &'a [u8])> {
        let header_bytes = input.read_verify(::HEADER_SIZE, &self.header_hash)?;
        let header_array = array_ref!(header_bytes, 0, ::HEADER_SIZE);
        self.header = Some(Region::from_header_bytes(header_array));
        Ok((::HEADER_SIZE, &[]))
    }

    fn feed_chunk<'a>(
        &mut self,
        input: &mut Unverified<'a>,
        region: Region,
    ) -> ::Result<(usize, &'a [u8])> {
        let chunk_bytes = input.read_verify(region.len() as usize, &region.hash)?;
        // We pay attention to the `chunk_offset` for cases where a previous
        // seek() put us in the middle of the chunk. In that case, we still
        // have to verify the whole thing, but we only return the bytes after
        // the seek position. In regular reading without seeks, the chunk
        // offset will always end up being zero.
        let chunk_offset = (self.position - region.start) as usize;
        let ret = &chunk_bytes[chunk_offset..];
        // Successfully feeding a chunk moves the position foward, and pops any
        // finished nodes off the node stack. Subsequent feeds will be for the
        // following chunk.
        self.seek(region.end);
        // Note that the length of the entire chunk is returned as "consumed",
        // even in offset cases where only part of it is returned, because the
        // caller still fed the whole chunk in and still needs to advance the
        // entire chunk length forward in the encoded input.
        Ok((chunk_bytes.len() as usize, ret))
    }

    fn feed_node<'a>(
        &mut self,
        input: &mut Unverified<'a>,
        region: Region,
    ) -> ::Result<(usize, &'a [u8])> {
        let node_bytes = input.read_verify(::NODE_SIZE, &region.hash)?;
        let node = region.parse_node(node_bytes)?;
        self.stack.push(node);
        Ok((::NODE_SIZE, &[]))
    }
}

/// A `Region` represents some part of the content (or all of it, if it's the
/// "root region") with a given hash. If the length of the region is less than
/// or equal to the chunk size, the region's hash is simply the hash of that
/// chunk. If it's longer than a chunk, then the region is encoded as a tree,
/// and it's hash is the hash of the node at the top of that tree.
///
/// Regions also track their "encoded offset", the position in the encoding
/// where the region's chunk or node begins. Note how this is different from
/// "start" and "end", which are offsets in the *content*, not the encoding.
#[derive(Debug, Copy, Clone)]
struct Region {
    start: u64,
    end: u64,
    encoded_offset: u64,
    hash: ::Digest,
}

impl Region {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    fn contains(&self, position: u64) -> bool {
        self.start <= position && position < self.end
    }

    fn from_header_bytes(bytes: &[u8]) -> Region {
        let (len, hash) = from_header_bytes(bytes);
        Region {
            start: 0,
            end: len,
            encoded_offset: ::HEADER_SIZE as u64,
            hash: hash,
        }
    }

    /// Splits the current region into two subregions, with the key logic
    /// happening in `left_subregion_len`. If calculating the new
    /// `encoded_offset` overflows, return `None`.
    fn parse_node(&self, bytes: &[u8]) -> ::Result<Node> {
        let left = Region {
            start: self.start,
            end: self.start + left_subregion_len(self.len()),
            encoded_offset: checked_add(self.encoded_offset, ::NODE_SIZE as u64)?,
            hash: *array_ref!(bytes, 0, ::DIGEST_SIZE),
        };
        let right = Region {
            start: left.end,
            end: self.end,
            encoded_offset: checked_add(left.encoded_offset, encoded_len(left.len())?)?,
            hash: *array_ref!(bytes, ::DIGEST_SIZE, ::DIGEST_SIZE),
        };
        Ok(Node { left, right })
    }
}

#[derive(Debug, Copy, Clone)]
struct Node {
    left: Region,
    right: Region,
}

impl Node {
    fn contains(&self, position: u64) -> bool {
        self.left.start <= position && position < self.right.end
    }
}

/// Computing the encoded length of a region is surprisingly cheap. All binary
/// trees have a useful property: as long as all interior nodes have exactly two
/// children (ours do), the number of nodes is always equal to the
/// number of leaves minus one. Because we require all the leaves in our tree
/// to be full chunks (except the last one), we only need to divide by the
/// chunk size, which in practice is just a bitshift.
///
/// Note that a complete encoded file is both the encoded "root region", and
/// the bytes of the header itself, which aren't accounted for here.
///
/// Because the encoded len is longer than the input length, it can overflow
/// for very large inputs. In that case, we return `Err(Overflow)`.
fn encoded_len(region_len: u64) -> ::Result<u64> {
    // Divide rounding up to get the number of chunks.
    let num_chunks = (region_len / ::CHUNK_SIZE as u64) +
        (region_len % ::CHUNK_SIZE as u64 > 0) as u64;
    // The number of nodes is one less, but not less than zero.
    let num_nodes = num_chunks.saturating_sub(1);
    // `all_nodes` can't overflow by itself unless the node size is larger
    // than the chunk size, which would be pathological, but whatever :p
    checked_add(checked_mul(num_nodes, ::NODE_SIZE as u64)?, region_len)
}

fn checked_add(a: u64, b: u64) -> ::Result<u64> {
    a.checked_add(b).ok_or(::Error::Overflow)
}

fn checked_mul(a: u64, b: u64) -> ::Result<u64> {
    a.checked_mul(b).ok_or(::Error::Overflow)
}

#[cfg(test)]
mod test {
    extern crate rand;
    use self::rand::Rng;

    use super::*;
    use simple::encode;

    #[test]
    fn test_encoded_len() {
        for &case in ::TEST_CASES {
            let found_len = encode(&vec![0; case]).0.len() as u64;
            let computed_len = encoded_len(case as u64).unwrap() + ::HEADER_SIZE as u64;
            assert_eq!(found_len, computed_len, "wrong length in case {}", case);
        }
    }

    #[test]
    fn test_decoder() {
        // This simulates a writer who supplies exactly what's asked for by
        // needed(), until EOF.
        for &case in ::TEST_CASES {
            println!("\n>>>>> starting case {}", case);
            let input = vec![0x72; case];
            let (encoded, hash) = encode(&input);
            println!("encoded.len() {}", encoded.len());
            let mut decoder = Decoder::new(&hash);
            let mut output = Vec::new();
            loop {
                let (offset, len) = decoder.needed();
                println!("needed: {}, {}", offset, len);
                if len == 0 {
                    break;
                }
                let encoded_input = &encoded[offset as usize..offset as usize + len];
                let (consumed, out_slice) = decoder.feed(encoded_input).unwrap();
                println!("consumed: {} (gave output: {})", consumed, output.len());
                assert_eq!(consumed, len);
                output.extend_from_slice(out_slice);
            }
            assert_eq!(input, output);
        }
    }

    fn decode_all(mut encoded: &[u8], hash: &::Digest) -> ::Result<Vec<u8>> {
        let mut decoder = Decoder::new(&hash);
        let mut output = Vec::new();
        loop {
            let (_, len) = decoder.needed();
            if len == 0 {
                return Ok(output);
            }
            let (consumed, out_slice) = decoder.feed(encoded)?;
            output.extend_from_slice(out_slice);
            encoded = &encoded[consumed..];
        }
    }

    #[test]
    fn test_decoder_corrupted() {
        // Similar to test_simple_corrupted. We flip bits and make things stop
        // working.
        for &case in ::TEST_CASES {
            println!("\n>>>>> starting case {}", case);
            let input = vec![0x72; case];
            let (encoded, hash) = encode(&input);
            println!("encoded lenth {}", encoded.len());
            for &tweak_case in ::TEST_CASES {
                if tweak_case >= encoded.len() {
                    continue;
                }
                println!("tweak case {}", tweak_case);
                let mut corrupted = encoded.clone();
                corrupted[tweak_case] ^= 1;
                assert_eq!(
                    decode_all(&corrupted, &hash).unwrap_err(),
                    ::Error::HashMismatch
                );
                // But make sure it does work without the tweak.
                decode_all(&encoded, &hash).unwrap();
            }
        }
    }

    #[test]
    fn test_decoder_overfeed() {
        // This simulates a writer who doesn't even call needed(), and instead
        // just feeds everything into every call to seek(), bumping the start
        // forward as bytes are consumed.
        for &case in ::TEST_CASES {
            let input = vec![0x72; case];
            let (encoded, hash) = encode(&input);
            let mut decoder = Decoder::new(&hash);
            let mut output = Vec::new();
            let mut encoded_input = &encoded[..];
            loop {
                let (consumed, out_slice) = decoder.feed(encoded_input).unwrap();
                if consumed == 0 {
                    break;
                }
                output.extend_from_slice(out_slice);
                encoded_input = &encoded_input[consumed..]
            }
            assert_eq!(input, output);
        }
    }

    #[test]
    fn test_decoder_feed_by_ones() {
        // This simulates a writer who tries to feed small amounts, making the
        // amount larger with each failure until things succeed.
        let input = vec![0; 4 * ::CHUNK_SIZE + 1];
        let (encoded, hash) = encode(&input);
        let mut decoder = Decoder::new(&hash);
        let mut encoded_slice = &encoded[..];
        let mut output = Vec::new();
        let mut feed_len = 0;
        loop {
            match decoder.feed(&encoded_slice[..feed_len]) {
                Ok((consumed, out_slice)) => {
                    if consumed == 0 {
                        // Note that this EOF will happen after the last
                        // successful feed, when we attempt to feed 0 bytes
                        // again. If we reset feed_len to anything other than
                        // zero, we'd end up slicing out of bounds.
                        break;
                    }
                    output.extend_from_slice(out_slice);
                    encoded_slice = &encoded_slice[consumed..];
                    feed_len = 0;
                }
                Err(::Error::ShortInput) => {
                    // Keep bumping the feed length until we succeed.
                    feed_len += 1;
                }
                e => panic!("unexpected error: {:?}", e),
            }
        }
    }

    #[test]
    fn test_decoder_seek() {
        for &case in ::TEST_CASES {
            println!("\n>>>>> case {}", case);
            // Use pseudorandom input, so that slices from different places are
            // very likely not to match.
            let input: Vec<u8> = rand::ChaChaRng::new_unseeded()
                .gen_iter()
                .take(case)
                .collect();
            let (encoded, hash) = encode(&input);
            for &seek_case in ::TEST_CASES {
                if seek_case > case {
                    continue;
                }
                println!(">>> seek case {}", seek_case);
                let mut decoder = Decoder::new(&hash);
                decoder.seek(seek_case as u64);
                // Read the rest of the output and confirm it matches the input
                // slice at the same offset.
                let mut output = Vec::new();
                loop {
                    let (offset, len) = decoder.needed();
                    if len == 0 {
                        break;
                    }
                    let encoded_input = &encoded[offset as usize..offset as usize + len];
                    let (_, out_slice) = decoder.feed(encoded_input).unwrap();
                    output.extend_from_slice(out_slice);
                }
                let expected = &input[seek_case..];
                assert_eq!(expected, &output[..]);
            }
        }
    }
}
