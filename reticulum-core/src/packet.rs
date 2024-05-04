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

#[cfg(test)]
mod tests {
    use crate::parse::packet;

    use super::*;
    use std::io::prelude::*;

    #[derive(Debug)]
    struct TestInf;
    impl Interface for TestInf {
        const LENGTH: usize = 2;
    }

    #[test]
    fn encode_header() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
            hops: 0,
        };

        let mut buf = Vec::new();
        let written = header.encode(&mut buf);
        assert_eq!(written, 2);
        assert_eq!(buf, [0x08, 0x00]);
    }

    #[test]
    fn encode_packet_path_request() {
        let mut buf = Vec::new();
        let packet: Packet<TestInf> = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: [
                0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0,
                0x27, 0x61,
            ],
            transport_id: None,
            context: 0,
            data: Payload::PathRequest(PathRequest {
                query: &[
                    235, 252, 186, 213, 27, 223, 220, 228, 69, 35, 238, 49, 26, 222, 169, 162,
                ],
                transport: Some(&[
                    192, 202, 232, 46, 73, 147, 217, 13, 240, 198, 26, 209, 158, 195, 141, 166,
                ]),
                tag: Some(&[
                    4, 175, 40, 70, 0, 120, 59, 234, 132, 61, 97, 32, 189, 35, 51, 239,
                ]),
            }),
            interface: PhantomData,
            xcontext: PhantomData,
        };
        let written = packet.encode(&mut buf);
        let expected = vec![
            0x08, 0x00, 0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba,
            0x47, 0xd0, 0x27, 0x61, 0x00, 0xeb, 0xfc, 0xba, 0xd5, 0x1b, 0xdf, 0xdc, 0xe4, 0x45,
            0x23, 0xee, 0x31, 0x1a, 0xde, 0xa9, 0xa2, 0xc0, 0xca, 0xe8, 0x2e, 0x49, 0x93, 0xd9,
            0x0d, 0xf0, 0xc6, 0x1a, 0xd1, 0x9e, 0xc3, 0x8d, 0xa6, 0x04, 0xaf, 0x28, 0x46, 0x00,
            0x78, 0x3b, 0xea, 0x84, 0x3d, 0x61, 0x20, 0xbd, 0x23, 0x33, 0xef,
        ];

        assert_eq!(buf.len(), written);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_me() {
        let vec1 = vec![
            126, 81, 2, 82, 28, 135, 168, 58, 251, 143, 41, 228, 69, 94, 119, 147, 11, 151, 59,
            249, 140, 52, 214, 172, 42, 95, 111, 105, 79, 180, 139, 56, 90, 221, 163, 0, 120, 112,
            227, 55, 248, 252, 167, 4, 130, 47, 25, 107, 63, 232, 201, 37, 79, 153, 51, 50, 175,
            209, 189, 27, 132, 13, 231, 141, 186, 68, 157, 37, 9, 136, 155, 114, 111, 104, 85, 254,
            21, 252, 58, 138, 217, 169, 55, 93, 32, 98, 40, 14, 139, 42, 57, 240, 19, 181, 118,
            240, 74, 70, 209, 177, 224, 58, 9, 183, 122, 194, 27, 34, 37, 142, 12, 201, 72, 252,
            33, 0, 101, 190, 15, 152, 210, 228, 58, 196, 144, 196, 251, 237, 83, 132, 192, 112, 58,
            62, 165, 242, 221, 74, 222, 214, 69, 223, 89, 221, 53, 185, 103, 204, 77, 165, 244,
            105, 116, 175, 206, 194, 232, 184, 148, 155, 135, 98, 120, 191, 135, 176, 194, 76, 64,
            195, 170, 51, 218, 68, 143, 191, 103, 83, 195, 223, 9, 214, 228, 2, 146, 195, 206, 101,
            190, 15, 152, 126,
        ];

        let vec2 = vec![
            126, 8, 0, 107, 159, 102, 1, 77, 152, 83, 250, 171, 34, 15, 186, 71, 208, 39, 97, 0,
            235, 252, 186, 213, 27, 223, 220, 228, 69, 35, 238, 49, 26, 222, 169, 162, 82, 28, 135,
            168, 58, 251, 143, 41, 228, 69, 94, 119, 147, 11, 151, 59, 5, 24, 89, 137, 16, 74, 56,
            61, 78, 221, 62, 208, 160, 37, 163, 96, 126,
        ];

        let vec3 = vec![
            0x7e, 0x08, 0x00, 0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f,
            0xba, 0x47, 0xd0, 0x27, 0x61, 0x00, 0xeb, 0xfc, 0xba, 0xd5, 0x1b, 0xdf, 0xdc, 0xe4,
            0x45, 0x23, 0xee, 0x31, 0x1a, 0xde, 0xa9, 0xa2, 0xc0, 0xca, 0xe8, 0x2e, 0x49, 0x93,
            0xd9, 0x0d, 0xf0, 0xc6, 0x1a, 0xd1, 0x9e, 0xc3, 0x8d, 0xa6, 0xf6, 0xc9, 0x3c, 0xf7,
            0x67, 0x67, 0x65, 0x7c, 0x86, 0x2f, 0x6a, 0x71, 0x1d, 0x06, 0xa3, 0xc7, 0x7e,
        ];

        let vec4 = vec![
            0x7e, 0x51, 0x00, 0xc0, 0xca, 0xe8, 0x2e, 0x49, 0x93, 0xd9, 0x0d, 0xf0, 0xc6, 0x1a,
            0xd1, 0x9e, 0xc3, 0x8d, 0xa6, 0x65, 0x19, 0x62, 0xcc, 0x10, 0xca, 0x0f, 0x0c, 0x77,
            0x8a, 0x92, 0xa9, 0xe1, 0x7b, 0xb2, 0x52, 0x00, 0x2b, 0x20, 0x1d, 0xd1, 0xb7, 0xfe,
            0x93, 0xb1, 0xbc, 0x38, 0x71, 0x75, 0x03, 0x7b, 0x5b, 0xcb, 0xdf, 0x14, 0x6d, 0xb2,
            0x79, 0xfb, 0x20, 0x7d, 0x5d, 0xa6, 0xb5, 0x49, 0xbe, 0x21, 0x09, 0xb4, 0x3c, 0x87,
            0xba, 0x4a, 0x9d, 0x18, 0x9a, 0x14, 0x36, 0x46, 0x44, 0x0e, 0x19, 0xcb, 0x91, 0xf6,
            0xa8, 0xa8, 0xfc, 0xf5, 0x70, 0xf7, 0xfb, 0x64, 0xcd, 0xfe, 0x52, 0x31, 0x22, 0x53,
            0xbc, 0xc2, 0x47, 0x6e, 0xc6, 0x0b, 0xc3, 0x18, 0xe2, 0xc0, 0xf0, 0xd9, 0x08, 0x8f,
            0x99, 0x13, 0xdb, 0x96, 0x00, 0x65, 0xbe, 0x36, 0x85, 0xad, 0x9a, 0x31, 0x24, 0xab,
            0x6a, 0x67, 0x20, 0x92, 0x68, 0xef, 0x8d, 0x9e, 0xe0, 0xb3, 0xf3, 0x28, 0x30, 0xde,
            0x71, 0x44, 0xb2, 0xa3, 0x81, 0x3d, 0x7a, 0x22, 0x20, 0x07, 0xc1, 0xd3, 0x55, 0x3f,
            0x2a, 0x10, 0xdf, 0x9e, 0x18, 0x13, 0x50, 0xbd, 0xac, 0x2d, 0xdd, 0x49, 0x01, 0x51,
            0x9d, 0xac, 0x3f, 0xd4, 0xbf, 0x7c, 0xe4, 0xa3, 0x90, 0x6b, 0xd7, 0x7a, 0xe8, 0x09,
            0x44, 0x0b, 0x0b, 0x45, 0x63, 0x68, 0x6f, 0x42, 0x6f, 0x74, 0x20, 0x2d, 0x20, 0x53,
            0x65, 0x6e, 0x64, 0x20, 0x6d, 0x65, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x74, 0x65,
            0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x21, 0x7e,
        ];

        let vec5 = vec![
            0x7e, 0x51, 0x03, 0xc0, 0xca, 0xe8, 0x2e, 0x49, 0x93, 0xd9, 0x0d, 0xf0, 0xc6, 0x1a,
            0xd1, 0x9e, 0xc3, 0x8d, 0xa6, 0x77, 0x98, 0x56, 0x7d, 0x5e, 0x10, 0x8c, 0xc8, 0x5e,
            0x13, 0xd2, 0x8f, 0x72, 0x2b, 0x78, 0xee, 0x04, 0x00, 0xdc, 0xc5, 0x57, 0xc4, 0xac,
            0xb0, 0x47, 0x2b, 0xee, 0xa8, 0xa0, 0x72, 0x36, 0x88, 0x46, 0xe4, 0x85, 0xfa, 0xa2,
            0x68, 0x50, 0xd3, 0x5e, 0x86, 0x87, 0x28, 0x75, 0x7b, 0xce, 0x5c, 0xe5, 0x2b, 0xf1,
            0x61, 0x2d, 0xf5, 0x7f, 0x5f, 0x59, 0x00, 0x1f, 0x75, 0xf4, 0x15, 0x49, 0x61, 0xea,
            0x00, 0x08, 0x64, 0x77, 0xcd, 0xf6, 0xd8, 0xb1, 0x35, 0x66, 0x6b, 0x00, 0xfa, 0x86,
            0x8d, 0xe5, 0x9f, 0x21, 0x3e, 0x63, 0x11, 0xbc, 0xec, 0x54, 0xab, 0x4f, 0xde, 0xb9,
            0xdb, 0xb8, 0x0d, 0x1d, 0x00, 0x65, 0xbe, 0xcc, 0x42, 0xbf, 0xfe, 0xbe, 0x4c, 0xbd,
            0xd4, 0xca, 0xd8, 0xc4, 0x3c, 0x49, 0xea, 0x66, 0x21, 0x01, 0xdc, 0xf2, 0x54, 0xdd,
            0xcf, 0x74, 0x2b, 0x3a, 0xe3, 0xeb, 0x6e, 0x90, 0x60, 0x51, 0x90, 0x73, 0x1c, 0x8b,
            0x86, 0x27, 0x8a, 0x89, 0x72, 0x18, 0x8d, 0xc6, 0x5f, 0x5f, 0xe4, 0x5a, 0xe8, 0xdf,
            0x26, 0x7d, 0x5e, 0x88, 0xd1, 0x50, 0xe8, 0xc8, 0x4d, 0xa6, 0x3a, 0x26, 0x7d, 0x5d,
            0x49, 0x46, 0x36, 0x64, 0x0e, 0x6e, 0x73, 0x6c, 0x2d, 0x62, 0x6c, 0x61, 0x6b, 0x2d,
            0x74, 0x65, 0x73, 0x74, 0x6e, 0x6f, 0x64, 0x65, 0x31, 0x7e,
        ];

        let vec6: &[u8] = &vec![
            0x7e, 0x51, 0x01, 0xc0, 0xca, 0xe8, 0x2e, 0x49, 0x93, 0xd9, 0x0d, 0xf0, 0xc6, 0x1a,
            0xd1, 0x9e, 0xc3, 0x8d, 0xa6, 0x6d, 0x36, 0xf7, 0x82, 0xca, 0x49, 0x30, 0xb5, 0x20,
            0x6e, 0x03, 0x7d, 0x5e, 0xa2, 0x34, 0x7d, 0x5e, 0x4a, 0x00, 0x3a, 0x59, 0x5f, 0xbd,
            0xbf, 0xc3, 0xff, 0xc3, 0x3f, 0x2c, 0x3c, 0x1b, 0x51, 0xc5, 0x07, 0xd3, 0x6f, 0x30,
            0x88, 0xf1, 0xff, 0x39, 0xa3, 0x23, 0xbd, 0xad, 0x94, 0x44, 0x9c, 0xb2, 0x9f, 0x49,
            0x6d, 0x61, 0xd0, 0x9e, 0xa8, 0x79, 0x15, 0x24, 0x0d, 0xbf, 0x2e, 0xc3, 0x8c, 0x03,
            0x76, 0x0d, 0x1f, 0x00, 0x11, 0x2e, 0x9e, 0x52, 0x11, 0x24, 0xad, 0x3c, 0xba, 0xf9,
            0x1e, 0x76, 0xd0, 0xb3, 0x6e, 0xc6, 0x0b, 0xc3, 0x18, 0xe2, 0xc0, 0xf0, 0xd9, 0x08,
            0x10, 0xd1, 0xa8, 0xb2, 0x1e, 0x00, 0x65, 0xc4, 0x62, 0x11, 0x6e, 0x0c, 0x92, 0xa1,
            0x9b, 0x91, 0x5b, 0xca, 0xf6, 0x89, 0x79, 0x62, 0x33, 0xc6, 0xda, 0x25, 0x57, 0x1c,
            0x60, 0x71, 0x84, 0x02, 0xd3, 0xca, 0x7b, 0xae, 0xd6, 0xe5, 0xfd, 0x91, 0x91, 0x1e,
            0x66, 0x6e, 0xde, 0xe2, 0x43, 0x21, 0xa5, 0x8a, 0xda, 0x61, 0x49, 0xcc, 0x74, 0x20,
            0x06, 0xa1, 0x2c, 0x25, 0x40, 0x10, 0x39, 0x6f, 0x26, 0xf7, 0x68, 0x44, 0x41, 0x07,
            0xb1, 0x4d, 0x90, 0x09, 0x42, 0x74, 0x42, 0x20, 0x4e, 0x6f, 0x64, 0x65, 0x20, 0x52,
            0x6f, 0x6d, 0x65, 0x6f, 0x20, 0x41, 0x6c, 0x65, 0x72, 0x74, 0x73, 0x7e,
        ];

        let mut unescaped = Vec::new();
        let mut escaped = crate::hdlc::Hdlc::new(vec6);
        let _ = escaped.read_to_end(&mut unescaped);

        let packet: Packet<TestInf> = packet(&unescaped).unwrap().1;
        if let Payload::Announce(ann) = packet.data {
            ann.validate();
        }
    }
}
