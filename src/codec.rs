use byteorder::{ByteOrder, BigEndian};

#[derive(Debug, Clone, Copy)]
struct Region {
    hash: ::Digest,
    start: u64,
    len: u64,
    encoded_offset: u64,
}

impl Region {
    fn contains(&self, offset: u64) -> bool {
        // Note that start+len cannot overflow, because the start+len of the
        // rightmost region(s) is equal to the overall len.
        self.start <= offset && offset < (self.start + self.len)
    }

    fn encoded_len(&self) -> ::Result<u64> {
        // Divide rounding up.
        let num_chunks = checked_add(self.len, (::CHUNK_SIZE - 1) as u64)? / (::CHUNK_SIZE as u64);
        // Note that the empty input results in zero nodes, not "-1" nodes.
        checked_add(
            self.len,
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
    fn contains(&self, offset: u64) -> bool {
        self.left.contains(offset) || self.right.contains(offset)
    }

    fn region_for(&self, offset: u64) -> Region {
        if self.left.contains(offset) {
            self.left
        } else if self.right.contains(offset) {
            self.right
        } else {
            panic!("offset outside of the current node")
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    header_hash: ::Digest,
    header: Option<Region>,
    offset: u64,
    stack: Vec<Node>,
}

impl Decoder {
    pub fn new(header_hash: &::Digest) -> Self {
        Self {
            header_hash: *header_hash,
            header: None,
            offset: 0,
            stack: Vec::new(),
        }
    }

    pub fn len(&self) -> Option<u64> {
        self.header.map(|h| h.len)
    }

    pub fn seek(&mut self, offset: u64) {
        self.offset = offset;
        while let Some(&node) = self.stack.last() {
            if node.contains(offset) {
                break;
            }
            self.stack.pop();
        }
    }

    // Give the (offset, size) needed in the next call to feed(). A size of
    // zero means EOF.
    pub fn needed(&self) -> (u64, usize) {
        // Have we even read the header yet?
        let header_region = if let Some(region) = self.header {
            region
        } else {
            return (0, ::HEADER_SIZE);
        };
        // Are we at EOF?
        if self.offset >= header_region.len {
            return (0, 0);
        }
        // How far down the tree are we right now?
        let current_region = if let Some(node) = self.stack.last() {
            node.region_for(self.offset)
        } else {
            header_region
        };
        // If we're down to chunk size, ask for a chunk. Otherwise more nodes.
        if current_region.len <= ::CHUNK_SIZE as u64 {
            (current_region.encoded_offset, current_region.len as usize)
        } else {
            (current_region.encoded_offset, ::NODE_SIZE)
        }
    }

    // Returns (consumed, output), where output is Some() when a chunk was
    // consumed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> ::Result<(usize, Option<&'a [u8]>)> {
        // Immediately shadow input with a wrapper type that only gives us
        // bytes when the hash is correct.
        let input = ::evil::EvilBytes::wrap(input);
        let header_region = if let Some(region) = self.header {
            region
        } else {
            let header_bytes = input.verify(0..::HEADER_SIZE, &self.header_hash)?;
            let decoded_len = BigEndian::read_u64(&header_bytes[..8]);
            let root_hash = array_ref!(header_bytes, 8, ::DIGEST_SIZE);
            self.header = Some(Region {
                hash: *root_hash,
                start: 0,
                len: decoded_len,
                encoded_offset: ::HEADER_SIZE as u64,
            });
            return Ok((::HEADER_SIZE, None));
        };
        // Are we at EOF?
        if self.offset >= header_region.len {
            return Ok((0, None));
        }
        // How far down the tree are we right now?
        let current_region = if let Some(node) = self.stack.last() {
            node.region_for(self.offset)
        } else {
            header_region
        };
        // If we're down to chunk size, parse a chunk. Otherwise parse a node.
        if current_region.len <= ::CHUNK_SIZE as u64 {
            let chunk_bytes = input.verify(
                0..current_region.len as usize,
                &current_region.hash,
            )?;
            let chunk_offset = (self.offset - current_region.start) as usize;
            let ret = &chunk_bytes[chunk_offset..current_region.len as usize];
            self.seek(current_region.start + current_region.len);
            Ok((ret.len(), Some(ret)))
        } else {
            let node_bytes = input.verify(0..::NODE_SIZE, &current_region.hash)?;
            let left_hash = array_ref!(node_bytes, 0, ::DIGEST_SIZE);
            let right_hash = array_ref!(node_bytes, ::DIGEST_SIZE, ::DIGEST_SIZE);
            let left_region = Region {
                hash: *left_hash,
                start: current_region.start,
                len: ::left_len(current_region.len),
                encoded_offset: checked_add(current_region.encoded_offset, ::NODE_SIZE as u64)?,
            };
            let right_region = Region {
                hash: *right_hash,
                start: left_region.start + left_region.len,
                len: current_region.len - left_region.len,
                encoded_offset: checked_add(
                    left_region.encoded_offset,
                    left_region.encoded_len()?,
                )?,
            };
            self.stack.push(Node {
                left: left_region,
                right: right_region,
            });
            Ok((::NODE_SIZE, None))
        }
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
            // All dummy values except for len.
            let region = Region {
                hash: [0; ::DIGEST_SIZE],
                start: 0,
                len: case as u64,
                encoded_offset: 0,
            };
            let found_len = ::simple::encode(&vec![0; case]).0.len() as u64;
            let computed_len = region.encoded_len().unwrap() + ::HEADER_SIZE as u64;
            assert_eq!(found_len, computed_len, "wrong length in case {}", case);
        }
    }

    #[test]
    fn test_codec() {
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
    fn test_codec_overfeed() {
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
    fn test_codec_feed_by_ones() {
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
    fn test_codec_seek() {
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
