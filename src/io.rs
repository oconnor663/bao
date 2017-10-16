use std::io::prelude::*;
use std::io;
use std::cmp::min;

use encoder::{PostOrderEncoder, PostToPreFlipper};
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
    inner_writer: T,
    // TODO: scrap the in_buffer, and let PostOrderEncoder accept smaller writes
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    out_position: usize,
    finished: bool,
    encoder: PostOrderEncoder,
    flipper: PostToPreFlipper,
}

impl<T: Read + Write + Seek> Writer<T> {
    pub fn new(inner_writer: T) -> Self {
        Self {
            inner_writer,
            in_buffer: Vec::new(),
            out_buffer: Vec::new(),
            out_position: 0,
            finished: false,
            encoder: PostOrderEncoder::new(),
            flipper: PostToPreFlipper::new(),
        }
    }

    /// Currently we don't make any attempt to make IO errors recoverable
    /// during finish. Errors should be somewhat less common, since finish is
    /// only overwriting existing bytes, and not allocating new space, but
    /// still anything can fail.
    pub fn finish(&mut self) -> io::Result<::Digest> {
        self.check_finished()?;

        // Write out the output buffer. Doing this first is important, because
        // encoder.finish() will have more output.
        self.write_out()?;

        // Call finish on the post-order encoder, which formats the last chunk
        // + nodes + header.
        let (final_out, hash) = self.encoder.finish(&self.in_buffer);
        self.inner_writer.write_all(final_out)?;

        // TODO: This doesn't make any attempt at efficient IO.
        let mut read_position = self.inner_writer.seek(io::SeekFrom::Current(0))?;
        let mut write_position = read_position;
        while write_position > 0 {
            let needed = self.flipper.needed();
            read_position -= needed as u64;
            self.inner_writer.seek(io::SeekFrom::Start(read_position))?;
            self.in_buffer.resize(needed, 0);
            self.inner_writer.read_exact(&mut self.in_buffer)?;
            let (_, out) = self.flipper.feed_back(&self.in_buffer).expect("needs met");
            write_position -= out.len() as u64;
            self.inner_writer.seek(io::SeekFrom::Start(write_position))?;
            self.inner_writer.write_all(out)?;
        }

        self.finished = true;
        Ok(hash)
    }

    fn write_out(&mut self) -> io::Result<()> {
        write_out(
            &mut self.out_buffer,
            &mut self.out_position,
            &mut self.inner_writer,
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

        // Do all the encoding steps in "last first order", first flushing
        // output, then encoding input we already have, then accepting more
        // input. This keeps buffer sizes fixed, and it guarantees that we
        // never return an error after we've (irreversibly) consumed bytes from
        // the caller.

        // Flush the output buffer.
        self.write_out()?;

        // If we have a full input buffer, encode it to the output buffer.
        if self.in_buffer.len() == ::CHUNK_SIZE {
            let output = self.encoder.feed(
                array_ref!(&self.in_buffer, 0, ::CHUNK_SIZE),
            );
            self.out_buffer.extend_from_slice(output);
            self.in_buffer.clear();
        }

        // Finally, if there's room in the input buffer, accept more input.
        let needed = ::CHUNK_SIZE - self.in_buffer.len();
        let copy_len = min(buf.len(), needed);
        self.in_buffer.extend_from_slice(&buf[..copy_len]);
        Ok(copy_len)
    }

    /// Flush isn't very useful to callers, since none of the output is
    /// decodable unless `finish` succeeds, and `finish` flushes automatically.
    fn flush(&mut self) -> io::Result<()> {
        self.check_finished()?;
        self.write_out()?;
        self.inner_writer.flush()
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
