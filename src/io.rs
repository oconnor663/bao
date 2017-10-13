use std::io::prelude::*;
use std::io;
use std::cmp::min;

use encoder::{PostOrderEncoder, PostToPreFlipper};

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

pub struct Encoder<T: Read + Write + Seek> {
    inner_writer: T,
    // TODO: scrap the in_buffer, and let PostOrderEncoder accept smaller writes
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    out_position: usize,
    finished: bool,
    encoder: PostOrderEncoder,
    flipper: PostToPreFlipper,
}

impl<T: Read + Write + Seek> Encoder<T> {
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

impl<T: Read + Write + Seek> Drop for Encoder<T> {
    fn drop(&mut self) {
        // We can't report errors from drop(), but we make a best effort to
        // finish the encoding.
        if !self.finished {
            let _ = self.finish();
        }
    }
}

impl<T: Read + Write + Seek> Write for Encoder<T> {
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
