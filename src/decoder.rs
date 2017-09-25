use byteorder::{ByteOrder, BigEndian};

#[derive(Debug, Clone, Copy)]
struct Region {
    hash: ::Digest,
    start: u64,
    end: u64,
    encoded_offset: u64,
}

impl Region {
    fn contains(&self, position: u64) -> bool {
        self.start <= position && position < self.end
    }

    fn len(&self) -> u64 {
        self.end - self.start
    }

    fn encoded_len(&self) -> ::Result<u64> {
        // Divide rounding up.
        let num_chunks = (self.len() / ::CHUNK_SIZE as u64) +
            (self.len() % ::CHUNK_SIZE as u64 > 0) as u64;
        // Note that the empty input results in zero nodes, not "-1" nodes.
        checked_add(
            self.len(),
            checked_mul(num_chunks.saturating_sub(1), ::NODE_SIZE as u64)?,
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct Node {
    left: Region,
    right: Region,
}

impl Node {
    fn contains(&self, position: u64) -> bool {
        self.left.contains(position) || self.right.contains(position)
    }

    fn region_for(&self, position: u64) -> Option<Region> {
        if self.left.contains(position) {
            Some(self.left)
        } else if self.right.contains(position) {
            Some(self.right)
        } else {
            None
        }
    }
}

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
            node.region_for(self.position).expect(
                "position must be within the last node",
            )
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
        // be outside the bounds of the last node in the stack. We can't call
        // state() until we finish popping nodes below.
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
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> ::Result<(usize, Option<&'a [u8]>)> {
        // Immediately shadow input with a wrapper type that only gives us
        // bytes when the hash is correct.
        let input = ::evil::EvilBytes::wrap(input);

        match self.state() {
            State::NoHeader => self.feed_header(input),
            State::Eof => Ok((0, None)),
            State::Chunk(r) => self.feed_chunk(input, r),
            State::Node(r) => self.feed_node(input, r),
        }
    }

    fn feed_header<'a>(
        &mut self,
        input: ::evil::EvilBytes<'a>,
    ) -> ::Result<(usize, Option<&'a [u8]>)> {
        let header_bytes = input.verify(::HEADER_SIZE, &self.header_hash)?;
        let decoded_len = BigEndian::read_u64(&header_bytes[..8]);
        let root_hash = array_ref!(header_bytes, 8, ::DIGEST_SIZE);
        self.header = Some(Region {
            hash: *root_hash,
            start: 0,
            end: decoded_len,
            encoded_offset: ::HEADER_SIZE as u64,
        });
        Ok((::HEADER_SIZE, None))
    }

    fn feed_chunk<'a>(
        &mut self,
        input: ::evil::EvilBytes<'a>,
        region: Region,
    ) -> ::Result<(usize, Option<&'a [u8]>)> {
        let chunk_bytes = input.verify(region.len() as usize, &region.hash)?;
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
        Ok((chunk_bytes.len() as usize, Some(ret)))
    }

    fn feed_node<'a>(
        &mut self,
        input: ::evil::EvilBytes<'a>,
        region: Region,
    ) -> ::Result<(usize, Option<&'a [u8]>)> {
        let node_bytes = input.verify(::NODE_SIZE, &region.hash)?;
        let left_hash = array_ref!(node_bytes, 0, ::DIGEST_SIZE);
        let right_hash = array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE);
        let left_region = Region {
            hash: *left_hash,
            start: region.start,
            end: region.start + ::left_len(region.len()),
            encoded_offset: checked_add(region.encoded_offset, ::NODE_SIZE as u64)?,
        };
        let right_region = Region {
            hash: *right_hash,
            start: left_region.end,
            end: region.end,
            encoded_offset: checked_add(left_region.encoded_offset, left_region.encoded_len()?)?,
        };
        self.stack.push(Node {
            left: left_region,
            right: right_region,
        });
        Ok((::NODE_SIZE, None))
    }
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

    #[test]
    fn test_encoded_len() {
        for &case in ::TEST_CASES {
            // All dummy values except for end.
            let region = Region {
                hash: [0; ::DIGEST_SIZE],
                start: 0,
                end: case as u64,
                encoded_offset: 0,
            };
            let found_len = ::simple::encode(&vec![0; case]).0.len() as u64;
            let computed_len = region.encoded_len().unwrap() + ::HEADER_SIZE as u64;
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
            let (encoded, hash) = ::simple::encode(&input);
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
                let (consumed, maybe_output) = decoder.feed(encoded_input).unwrap();
                println!(
                    "consumed: {} (gave output: {})",
                    consumed,
                    maybe_output.is_some()
                );
                assert_eq!(consumed, len);
                if let Some(slice) = maybe_output {
                    output.extend_from_slice(slice);
                }
            }
            assert_eq!(input, output);
        }
    }

    #[test]
    fn test_decoder_overfeed() {
        // This simulates a writer who doesn't even call needed(), and instead
        // just feeds everything into every call to seek(), bumping the start
        // forward as bytes are consumed.
        for &case in ::TEST_CASES {
            let input = vec![0x72; case];
            let (encoded, hash) = ::simple::encode(&input);
            let mut decoder = Decoder::new(&hash);
            let mut output = Vec::new();
            let mut encoded_input = &encoded[..];
            loop {
                let (consumed, maybe_output) = decoder.feed(encoded_input).unwrap();
                if consumed == 0 {
                    break;
                }
                if let Some(slice) = maybe_output {
                    output.extend_from_slice(slice);
                }
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
        let (encoded, hash) = ::simple::encode(&input);
        let mut decoder = Decoder::new(&hash);
        let mut encoded_slice = &encoded[..];
        let mut output = Vec::new();
        let mut feed_len = 0;
        loop {
            match decoder.feed(&encoded_slice[..feed_len]) {
                Ok((consumed, maybe_output)) => {
                    if consumed == 0 {
                        // Note that this EOF will happen after the last
                        // successful feed, when we attempt to feed 0 bytes
                        // again. If we reset feed_len to anything other than
                        // zero, we'd end up slicing out of bounds.
                        break;
                    }
                    if let Some(bytes) = maybe_output {
                        output.extend_from_slice(bytes);
                    }
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
            let (encoded, hash) = ::simple::encode(&input);
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
                    let (_, maybe_output) = decoder.feed(encoded_input).unwrap();
                    if let Some(bytes) = maybe_output {
                        output.extend_from_slice(bytes);
                    }
                }
                let expected = &input[seek_case..];
                assert_eq!(expected, &output[..]);
            }
        }
    }
}
