use std::ops::Range;

pub struct EvilBytes<'a>(&'a [u8]);

impl<'a> EvilBytes<'a> {
    pub fn wrap(bytes: &'a [u8]) -> Self {
        EvilBytes(bytes)
    }

    pub fn verify(&self, range: Range<usize>, hash: &::Digest) -> ::Result<&'a [u8]> {
        if self.0.len() < range.end {
            return Err(::Error::ShortInput);
        }
        ::verify(&self.0[range.clone()], hash)?;
        Ok(&self.0[range])
    }
}
