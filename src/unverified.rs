extern crate constant_time_eq;

use self::constant_time_eq::constant_time_eq;
use decoder::{Error, Result};
use hash::{self, Hash};

fn verify(input: &[u8], hash: &Hash) -> Result<()> {
    let computed = hash::hash(input);
    if constant_time_eq(hash, &computed) {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

/// A tiny wrapper around bytes that guarantees we check their hash before we
/// use them.
pub struct Unverified<'a>(&'a [u8]);

impl<'a> Unverified<'a> {
    pub fn wrap(bytes: &'a [u8]) -> Self {
        Unverified(bytes)
    }

    /// Take a slice from the unverified input, but only if its length and hash
    /// match what we expect. On success, move the input forward.
    pub fn read_verify(&mut self, len: usize, hash: &Hash) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(Error::ShortInput);
        }
        let ret = &self.0[..len];
        verify(ret, hash)?;
        self.0 = &self.0[len..];
        Ok(ret)
    }
}
