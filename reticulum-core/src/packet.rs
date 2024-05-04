use core::marker::PhantomData;

use sha2::{Digest, Sha256};

use crate::announce::Announce;
use crate::context::{Context, RnsContext};
use crate::destination::{Destination, Out, Single, RNS_PATH_REQUEST_DESTINATION};
use crate::encode::{Encode, Write};
use crate::identity::Identity;
use crate::interface::Interface;
use crate::link::{LinkId, LinkProof, LinkRequest, Lynx};
use crate::path_request::PathRequest;

#[derive(Debug)]
pub struct Packet<'a, I: Interface, C: Context = RnsContext> {
    pub header: Header,
    pub ifac: Option<&'a [u8]>,
    pub destination: [u8; 16],
    pub transport_id: Option<[u8; 16]>,
    // TODO: make enum
    pub context: u8,
    pub data: Payload<'a>,
    pub interface: PhantomData<I>,
    pub xcontext: PhantomData<C>,
}

impl<'a, I: Interface, C: Context> Packet<'a, I, C> {
    pub const fn header(&self) -> &Header {
        &self.header
    }

    pub fn from_path_request(path_request: PathRequest<'a>) -> Packet<'a, I, C> {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: RNS_PATH_REQUEST_DESTINATION.destination_type(),
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: RNS_PATH_REQUEST_DESTINATION.hash(),
            transport_id: None,
            context: 0,
            data: Payload::PathRequest(path_request),
            interface: PhantomData,
            xcontext: PhantomData,
        }
    }

    pub const fn from_announce(announce: Announce<'a>) -> Packet<'a, I, C> {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: announce.destination,
            transport_id: None, // TODO: For rebroadcasting, this will be filled in.
            context: 0,
            data: Payload::Announce(announce),
            interface: PhantomData,
            xcontext: PhantomData,
        }
    }

    pub fn link_request(
        destination: Destination<Single, Out, Identity>,
        lynx: &'a Lynx,
    ) -> Packet<'a, I, C> {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
                hops: 0,
            },
            ifac: None,
            destination: destination.hash(),
            transport_id: None,
            context: 0x00,
            data: Payload::Data(lynx.as_bytes()),
            interface: PhantomData,
            xcontext: PhantomData,
        }
    }

    // TODO: Pass signature + pub key?
    pub const fn link_proof(link_id: &LinkId, s: &'a LinkProof) -> Packet<'a, I, C> {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 0,
            },
            ifac: None,
            destination: link_id.to_bytes(),
            transport_id: None,
            context: 0xFF,
            data: Payload::Data(s.as_bytes()),
            interface: PhantomData,
            xcontext: PhantomData,
        }
    }
}

impl<'a, I: Interface, C: Context> Packet<'a, I, C> {
    /// Special method to encode packet and at the same time calculate its hash.
    /// Unless hash is needed, it is recommend to call `encode`.
    ///
    /// Note: `out` will be overwritten.
    pub fn encode_get_hash<'b>(&self, out: &'b mut [u8; 512]) -> (&'b [u8], [u8; 16]) {
        let mut buf = &mut out[..];
        let mut packet_hash = Sha256::new();

        let h_len = self.header.encode(&mut buf);
        let t_len = self.transport_id.encode(&mut buf);
        let d_len = self.destination.encode(&mut buf);
        let c_len = self.context.encode(&mut buf);
        let dt_len = self.data.encode(&mut buf);

        let len = h_len + t_len + d_len + c_len + dt_len;

        // first byte of header (masked)
        packet_hash.update([out[0] & 0b00001111]);

        // destination + context + data
        packet_hash.update(&out[h_len + t_len..len]);

        let full_hash: [u8; 32] = packet_hash.finalize().into();
        let truncated: [u8; 16] = full_hash[..16].try_into().expect("16 bytes");

        (&out[..len], truncated)
    }
}

impl<'a, I: Interface, C: Context> Encode for Packet<'a, I, C> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.header.encode(writer)
            + self.transport_id.encode(writer)
            + self.destination.encode(writer)
            + self.context.encode(writer)
            + self.data.encode(writer)
    }
}

#[derive(Debug)]
pub struct Header {
    pub ifac_flag: IfacFlag,
    pub header_type: HeaderType,
    pub propagation_type: PropagationType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
    pub hops: u8,
}

impl Encode for Header {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        let mut header = 0u8;
        header |= match self.ifac_flag {
            IfacFlag::Open => 0,
            IfacFlag::Authenticated => 1,
        } << 7;
        header |= match self.header_type {
            HeaderType::Type1 => 0,
            HeaderType::Type2 => 1,
        } << 6;
        header |= match self.propagation_type {
            PropagationType::Broadcast => 0,
            PropagationType::Transport => 1,
            PropagationType::Relay => 2,
            PropagationType::Tunnel => 3,
        } << 4;
        header |= match self.destination_type {
            DestinationType::Single => 0,
            DestinationType::Group => 1,
            DestinationType::Plain => 2,
            DestinationType::Link => 3,
        } << 2;
        header |= match self.packet_type {
            PacketType::Data => 0,
            PacketType::Announce => 1,
            PacketType::LinkRequest => 2,
            PacketType::Proof => 3,
        };
        writer.write(&[header, self.hops])
    }
}

#[derive(Debug)]
pub enum Payload<'a> {
    Announce(Announce<'a>),
    PathRequest(PathRequest<'a>),
    LinkRequest(LinkRequest),
    LinkData(u8, &'a [u8]),
    LinkProof(LinkProof),
    Data(&'a [u8]),
}

impl<'a> Encode for Payload<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            Payload::Announce(a) => a.encode(writer),
            Payload::PathRequest(r) => r.encode(writer),
            Payload::LinkData(_, _) => todo!(),
            Payload::LinkRequest(_) => todo!(),
            Payload::LinkProof(_) => todo!(),
            Payload::Data(d) => d.encode(writer),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IfacFlag {
    Open,
    Authenticated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HeaderType {
    Type1,
    Type2,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PropagationType {
    Broadcast,
    Transport,
    Relay,
    Tunnel,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DestinationType {
    Single,
    Group,
    Plain,
    Link,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketType {
    Data,
    Announce,
    LinkRequest,
    Proof,
}
