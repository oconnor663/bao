/// A tiny wrapper around bytes that guarantees we check their hash before we
/// use them.
pub struct Unverified<'a>(&'a [u8]);

impl<'a> Unverified<'a> {
    pub fn wrap(bytes: &'a [u8]) -> Self {
        Unverified(bytes)
    }

    /// Take a slice from the unverified input, but only if its length and hash
    /// match what we expect. On success, move the input forward.
    pub fn read_verify(&mut self, len: usize, hash: &::Digest) -> ::Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(::Error::ShortInput);
        }
        let ret = &self.0[..len];
        ::verify(ret, hash)?;
        self.0 = &self.0[len..];
        Ok(ret)
    }

    /// As with read_verify, but slice off the end of the array instead of the
    /// front. Only used in testing.
    #[cfg(test)]
    pub fn read_verify_back(&mut self, len: usize, hash: &::Digest) -> ::Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(::Error::ShortInput);
        }
        let start = self.0.len() - len;
        let ret = &self.0[start..];
        ::verify(ret, hash)?;
        self.0 = &self.0[..start];
        Ok(ret)
    }
}
