use std::io::prelude::*;
use std::io;
use std::cmp::min;

pub struct Encoder<T: Write + Seek> {
    inner: T,
    // stack: Vec<Subtree>,
    buffer: Vec<u8>,
    finalized: bool,
}

impl<T: Write + Seek> Encoder<T> {
    fn finalize(&mut self) -> io::Result<()> {
        self.finalized = true;
        // Force all IO to disk, so that we can report any errors.
        self.flush()?;
        unimplemented!()
    }
}

impl<T: Write + Seek> Drop for Encoder<T> {
    fn drop(&mut self) {
        // We can't report errors from drop(), but we make a best effort to
        // finish the encoding.
        let _ = self.finalize();
    }
}

impl<T: Write + Seek> Write for Encoder<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finalized {
            panic!("Cannot write after finalizing.");
        }

        let copy_len = min(buf.len(), ::CHUNK_SIZE - self.buffer.len());
        self.buffer.extend_from_slice(&buf[..copy_len]);
        if self.buffer.len() == ::CHUNK_SIZE {
            //
        }
        unimplemented!()
    }

    /// Flush is mostly useless to callers, since the entire output is invalid
    /// until `finalize` succeeds, and `finalize` flushes automatically.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
