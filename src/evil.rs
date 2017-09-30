// TODO: make this Copy?
/// A tiny wrapper around bytes that guarantees we check their hash before we
/// use them.
pub struct EvilBytes<'a>(&'a [u8]);

impl<'a> EvilBytes<'a> {
    pub fn wrap(bytes: &'a [u8]) -> Self {
        EvilBytes(bytes)
    }

    // TODO: Get rid of the len param?
    /// Take a slice from the evil input, but only if its length and hash match
    /// what we expect.
    pub fn verify(&self, len: usize, hash: &::Digest) -> ::Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(::Error::ShortInput);
        }
        ::verify(&self.0[..len], hash)?;
        Ok(&self.0[..len])
    }

    // TODO: Get rid of this function, in favor of computing encoded_len.
    /// Same as `verify`, but also bump the start of the input forward on
    /// success.
    pub fn verify_bump(&mut self, len: usize, hash: &::Digest) -> ::Result<&'a [u8]> {
        let output = self.verify(len, hash)?;
        self.0 = &self.0[len..];
        Ok(output)
    }

    /// Get the length of the underlying slice.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Take a subslice of the unverified input.
    #[cfg(test)]
    pub fn slice(&self, start: usize, end: usize) -> EvilBytes<'a> {
        EvilBytes(&self.0[start..end])
    }
}
