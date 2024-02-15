use crate::{
    destination::{Destination, DestinationHash, Out, Plain, RNS_PATH_REQUEST_DESTINATION},
    encode::{Encode, Write},
};

#[derive(Debug)]
pub struct PathRequest<'a> {
    /// Destination hash that is requested.
    pub query: &'a [u8; 16],
    pub transport: Option<&'a [u8; 16]>,
    pub tag: Option<&'a [u8]>,
    pub destination: DestinationHash,
}

impl<'a> PathRequest<'a> {
    /// Creates new path with a given destination.
    pub const fn new(
        query: &'a [u8; 16],
        destination: &'a Destination<'a, Plain, Out, ()>,
        transport: Option<&'a [u8; 16]>,
        tag: Option<&'a [u8]>,
    ) -> PathRequest<'a> {
        destination.path_request(query, transport, tag)
    }

    /// Creates new path request with [RNS destination](../destination/index.html#rns-destination-for-path-requests).
    pub const fn new_rns(
        query: &'a [u8; 16],
        transport: Option<&'a [u8; 16]>,
        tag: Option<&'a [u8]>,
    ) -> PathRequest<'a> {
        Self::new(query, &RNS_PATH_REQUEST_DESTINATION, transport, tag)
    }
}

impl<'a> Encode for PathRequest<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.query.encode(writer) + self.transport.encode(writer) + self.tag.encode(writer)
    }
}
