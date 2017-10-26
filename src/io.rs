use std::io::prelude::*;
use std::io;
use std::cmp::min;

use encoder::{PostOrderEncoder, PostToPreFlipper, BackBuffer};
use decoder::Decoder;

/// We have an output buffer that needs to get written to the sink. It might
/// take multiple writes, and any one of them might fail, so we need to keep
/// track of how much we've written.
fn write_out<W: Write>(
    output: &mut Vec<u8>,
    position: &mut usize,
    writer: &mut W,
) -> io::Result<()> {
    while *position < output.len() {
        let n = writer.write(&output[*position..])?;
        *position += n;
    }
    output.clear();
    *position = 0;
    Ok(())
}

pub struct Writer<T: Read + Write + Seek> {
    inner: T,
    out_buffer: Vec<u8>,
    out_position: usize,
    finished: bool,
    encoder: PostOrderEncoder,
}

impl<T: Read + Write + Seek> Writer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            out_buffer: Vec::new(),
            out_position: 0,
            finished: false,
            encoder: PostOrderEncoder::new(),
        }
    }

    /// Currently we don't make any attempt to make IO errors recoverable
    /// during finish.
    pub fn finish(&mut self) -> io::Result<::Digest> {
        self.check_finished()?;
        self.finished = true;

        // Write out the output buffer. Doing this first is important, because
        // encoder.finish() will have more output.
        self.write_out()?;

        // Call finish on the post-order encoder, which formats the last chunk
        // + nodes + header.
        let (hash, final_out) = self.encoder.finish();
        self.inner.write_all(final_out)?;

        // Flip everything! This part is honestly a little hard to follow...
        let mut read_array = [0; 4096];
        let file_len = self.inner.seek(io::SeekFrom::Current(0))?;
        let mut read_position = file_len;
        let mut write_buffer = BackBuffer::new();
        let mut write_position = file_len;
        let mut flipper = PostToPreFlipper::new();
        while write_position > 0 {
            // Move the read position to the previous block start. Account for
            // the fact that the starting position at the end of the file
            // probably isn't on a block boundary.
            read_position -= 1;
            read_position -= read_position % read_array.len() as u64;
            self.inner.seek(io::SeekFrom::Start(read_position))?;
            let read_len = (file_len - read_position).min(read_array.len() as u64) as usize;
            let read_buffer = &mut read_array[..read_len];
            self.inner.read_exact(read_buffer)?;
            // Write the entire read buffer through the flipper, and accumulate
            // its output (back to front) in the write buffer.
            write_buffer.clear();
            let mut input_end = read_buffer.len();
            while input_end > 0 {
                let (used, output) = flipper.feed_back(&read_buffer[..input_end]);
                write_buffer.extend_front(output);
                input_end -= used;
            }
            // Write the entire write buffer.
            write_position -= write_buffer.len() as u64;
            self.inner.seek(io::SeekFrom::Start(write_position))?;
            self.inner.write_all(&write_buffer)?;
        }

        Ok(hash)
    }

    fn write_out(&mut self) -> io::Result<()> {
        write_out(
            &mut self.out_buffer,
            &mut self.out_position,
            &mut self.inner,
        )
    }

    fn check_finished(&self) -> io::Result<()> {
        if self.finished {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "can't use encoder after finish()",
            ))
        } else {
            Ok(())
        }
    }
}

impl<T: Read + Write + Seek> Drop for Writer<T> {
    fn drop(&mut self) {
        // We can't report errors from drop(), but we make a best effort to
        // finish the encoding.
        if !self.finished {
            let _ = self.finish();
        }
    }
}

impl<T: Read + Write + Seek> Write for Writer<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_finished()?;

        // First write out any existing bytes in the output buffer. Doing this
        // first keeps its size bounded.
        self.write_out()?;

        // Then write input to the encoder, possibly accepting output into the
        // output buffer.
        let (used, output) = self.encoder.feed(buf);
        self.out_buffer.extend_from_slice(output);
        Ok(used)
    }

    /// Flush isn't very useful to callers, since none of the output is
    /// decodable unless `finish` succeeds, and `finish` flushes automatically.
    fn flush(&mut self) -> io::Result<()> {
        self.check_finished()?;
        self.write_out()?;
        self.inner.flush()
    }
}

/// Note that `Reader` works even if the underlying type doesn't implement
/// `Seek`. This is a major design requirement of the tree layout.
pub struct Reader<T> {
    inner_reader: T,
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    decoder: Decoder,
}

impl<T> Reader<T> {
    pub fn new(inner_reader: T, hash: &::Digest) -> Self {
        Self {
            inner_reader,
            in_buffer: Vec::new(),
            out_buffer: Vec::new(),
            decoder: Decoder::new(hash),
        }
    }
}

impl<T: Read> Read for Reader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: performance, save state during errors
        while self.out_buffer.len() == 0 {
            let (_, needed) = self.decoder.needed();
            // Check for EOF.
            if needed == 0 {
                return Ok(0);
            }
            self.in_buffer.resize(needed, 0);
            self.inner_reader.read_exact(&mut self.in_buffer)?;
            let (_, out) = self.decoder.feed(&self.in_buffer).expect("was needed");
            // Could be empty.
            self.out_buffer.extend_from_slice(out);
        }

        let copy_len = min(self.out_buffer.len(), buf.len());
        buf[..copy_len].copy_from_slice(&self.out_buffer[..copy_len]);
        // TODO: perf
        self.out_buffer.drain(..copy_len);
        Ok(copy_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use simple;

    #[test]
    fn test_writer() {
        for &case in ::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0xb7; case];
            let mut encoded = Cursor::new(Vec::new());
            let hash = {
                let mut writer = Writer::new(&mut encoded);
                writer.write_all(&input).unwrap();
                writer.finish().unwrap()
            };

            // Compare to the simple encoder.
            let (simple_encoded, simple_hash) = simple::encode(&input);
            assert_eq!(hash, simple_hash);
            assert_eq!(encoded.get_ref(), &simple_encoded);
        }
    }

    #[test]
    fn test_reader() {
        for &case in ::TEST_CASES {
            println!("starting case {}", case);
            let input = vec![0xa9; case];
            let (encoded, hash) = simple::encode(&input);

            let mut reader = Reader::new(Cursor::new(&encoded), &hash);
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(input, output);
        }
    }
}
