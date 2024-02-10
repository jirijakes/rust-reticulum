use crate::encode::{Encode, Write};

#[derive(Debug)]
pub struct PathRequest<'a> {
    pub destination_hash: &'a [u8; 16],
    pub transport: Option<&'a [u8; 16]>,
    pub tag: Option<&'a [u8]>,
}

impl<'a> Encode for PathRequest<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.destination_hash.encode(writer)
            + self.transport.encode(writer)
            + self.tag.encode(writer)
    }
}
