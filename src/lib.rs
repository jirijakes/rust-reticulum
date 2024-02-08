use std::fmt::Debug;
use std::marker::PhantomData;

use ed25519_dalek::{Signature, VerifyingKey};
use nom::bits::bits;
use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_until};
use nom::combinator::{all_consuming, cond, map, map_opt, rest, success};
use nom::complete::bool;
use nom::error::{make_error, ErrorKind, ParseError};
use nom::number::complete::u8;
use nom::sequence::{delimited, tuple};
use nom::{Err, IResult, Parser};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

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

#[derive(Debug)]
pub enum PacketType {
    Data,
    Announce,
    LinkRequest,
    Proof,
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

pub trait Interface {
    const LENGTH: usize;
}

#[derive(Clone, Copy)]
pub enum Destination<'a> {
    Type1(&'a [u8; 16]),
    Type2(&'a [u8; 16], &'a [u8; 16]),
}

impl<'a> Debug for Destination<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tuple = f.debug_tuple("Destination");
        match self {
            Destination::Type1(h) => tuple.field(&hex::encode(h)).finish(),
            Destination::Type2(h1, h2) => tuple
                .field(&hex::encode(h1))
                .field(&hex::encode(h2))
                .finish(),
        }
    }
}

impl<'a> Encode for Destination<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            Destination::Type1(h) => h.encode(writer),
            Destination::Type2(h1, h2) => h1.encode(writer) + h2.encode(writer),
        }
    }
}

#[derive(Debug)]
pub struct Packet<'a, I: Interface> {
    pub header: Header,
    pub ifac: Option<&'a [u8]>,
    pub destination: Destination<'a>,
    pub context: u8,
    pub data: Payload<'a>,
    pub phantom: PhantomData<I>,
}

impl<'a, I: Interface> Packet<'a, I> {
    pub fn header(&self) -> &Header {
        &self.header
    }
}

fn ifac_flag(input: (&[u8], usize)) -> IResult<(&[u8], usize), IfacFlag> {
    map(bool, |b| match b {
        false => IfacFlag::Open,
        true => IfacFlag::Authenticated,
    })(input)
}

fn header_type(input: (&[u8], usize)) -> IResult<(&[u8], usize), HeaderType> {
    map(bool, |b| match b {
        false => HeaderType::Type1,
        true => HeaderType::Type2,
    })(input)
}

fn propagation_type(input: (&[u8], usize)) -> IResult<(&[u8], usize), PropagationType> {
    map(tuple((bool, bool)), |b| match b {
        (false, false) => PropagationType::Broadcast,
        (false, true) => PropagationType::Transport,
        (true, false) => PropagationType::Relay,
        (true, true) => PropagationType::Tunnel,
    })(input)
}

fn destination_type(input: (&[u8], usize)) -> IResult<(&[u8], usize), DestinationType> {
    map(tuple((bool, bool)), |b| match b {
        (false, false) => DestinationType::Single,
        (false, true) => DestinationType::Group,
        (true, false) => DestinationType::Plain,
        (true, true) => DestinationType::Link,
    })(input)
}

fn packet_type(input: (&[u8], usize)) -> IResult<(&[u8], usize), PacketType> {
    map(tuple((bool, bool)), |b| match b {
        (false, false) => PacketType::Data,
        (false, true) => PacketType::Announce,
        (true, false) => PacketType::LinkRequest,
        (true, true) => PacketType::Proof,
    })(input)
}

pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let header_bits = |input| -> IResult<_, _> {
        let (input, ifac_flag) = ifac_flag(input)?;
        let (input, header_type) = header_type(input)?;
        let (input, propagation_type) = propagation_type(input)?;
        let (input, destination_type) = destination_type(input)?;
        let (input, packet_type) = packet_type(input)?;
        let (input, hops) = nom::bits::complete::take(8usize)(input)?;
        Ok((
            input,
            Header {
                ifac_flag,
                header_type,
                propagation_type,
                destination_type,
                packet_type,
                hops,
            },
        ))
    };
    bits(header_bits)(input)
}

fn hash(input: &[u8]) -> IResult<&[u8], &[u8; 16]> {
    // let (input, _whatsthat) = u8(input)?;
    let (input, b): (&[u8], _) = take(16usize)(input)?;
    match b.try_into() {
        Ok(b) => Ok((input, b)),
        Err(_) => Err(Err::Failure(make_error(input, ErrorKind::LengthValue))),
    }
}

pub fn hdlc<'a, O, E: ParseError<&'a [u8]>, F>(
    f: F,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
where
    F: Parser<&'a [u8], O, E>,
{
    let mut parse_all = all_consuming(f);
    move |input: &'a [u8]| -> IResult<&'a [u8], O, E> {
        let flag: &[u8] = &[0x7e];
        let (input, data) = delimited(tag(flag), take_until(flag), tag(flag))(input)?;
        let (_, parsed) = parse_all(data)?;
        Ok((input, parsed))
    }
}

#[derive(Debug)]
pub struct Announce<'a> {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
    pub signature: Signature,
    pub name_hash: &'a [u8],
    pub random_hash: &'a [u8],
    pub app_data: Option<&'a [u8]>,
    pub destination: Destination<'a>,
}

impl<'a> Encode for Announce<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.public_key.as_bytes().encode(writer)
            + self.verifying_key.as_bytes().encode(writer)
            + self.signature.to_bytes().as_slice().encode(writer)
            + self.name_hash.encode(writer)
            + self.random_hash.encode(writer)
            + self.app_data.encode(writer)
            + self.destination.encode(writer)
    }
}

impl<'a> Announce<'a> {
    pub fn validate(&self) {
        let mut message = vec![];
        match self.destination {
            Destination::Type1(h) => {
                message.extend_from_slice(h);
            }
            Destination::Type2(_, h2) => {
                message.extend_from_slice(h2);
            }
        }

        message.extend_from_slice(self.public_key.as_bytes());
        message.extend_from_slice(self.verifying_key.as_bytes());
        message.extend_from_slice(self.name_hash);
        message.extend_from_slice(self.random_hash);
        if let Some(data) = self.app_data {
            message.extend_from_slice(data);
        }
        let x = self.verifying_key.verify_strict(&message, &self.signature);
        println!("{:?}", x);

        let mut engine = Sha256::new();
        engine.update(self.public_key);
        engine.update(self.verifying_key);
        let id: [u8; 32] = engine.finalize().into();

        let mut engine = Sha256::new();
        engine.update(self.name_hash);
        engine.update(&id[..16]);
        let x: [u8; 32] = engine.finalize().into();

        println!("{}", hex::encode(&x[..16]));
    }
}

#[derive(Debug)]
pub struct PathRequest<'a> {
    pub destination_hash: &'a [u8; 16],
    pub transport: Option<&'a [u8; 16]>,
    pub tag: Option<&'a [u8]>,
}

#[derive(Debug)]
pub enum Payload<'a> {
    Announce(Announce<'a>),
    PathRequest(PathRequest<'a>),
    Data(&'a [u8]),
}

impl<'a> Encode for Payload<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            Payload::Announce(a) => a.encode(writer),
            Payload::PathRequest(r) => r.encode(writer),
            Payload::Data(d) => d.encode(writer),
        }
    }
}

fn path_request(input: &[u8]) -> IResult<&[u8], Payload> {
    let (input, destination_hash) = hash(input)?;

    let (input, (transport, tag)) = alt((
        map(tuple((hash, rest)), |(tr, tag)| {
            (Some(tr), Some(tag).filter(|t| !t.is_empty()))
        }),
        map(rest, |tag: &[u8]| {
            (None, Some(tag).filter(|t| !t.is_empty()))
        }),
        success((None, None)),
    ))(input)?;

    Ok((
        input,
        Payload::PathRequest(PathRequest {
            destination_hash,
            transport,
            tag,
        }),
    ))
}

fn array<const N: usize>(input: &[u8]) -> IResult<&[u8], &[u8; N]> {
    let (input, bytes) = take(N)(input)?;
    let array = bytes
        .try_into()
        .map_err(|_| Err::Failure(make_error(input, ErrorKind::LengthValue)))?;

    Ok((input, array))
}

fn announce<'a>(
    destination: Destination<'a>,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Payload> {
    move |input| {
        let (input, public_key) = map(array, |a| PublicKey::from(*a))(input)?;
        let (input, verifying_key) = map_opt(array, |a| VerifyingKey::from_bytes(a).ok())(input)?;
        let (input, named_hash) = take(10usize)(input)?;
        let (input, random_hash) = take(10usize)(input)?;
        let (input, signature) = map(array, |a| a.into())(input)?;
        let (input, app_data) =
            map(rest, |data: &[u8]| Some(data).filter(|d| !d.is_empty()))(input)?;
        Ok((
            input,
            Payload::Announce(Announce {
                public_key,
                verifying_key,
                signature,
                name_hash: named_hash,
                random_hash,
                app_data,
                destination,
            }),
        ))
    }
}

pub fn when<I, O, E: ParseError<I>, F>(b: bool, mut f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    F: Parser<I, O, E>,
{
    move |input: I| {
        if b {
            f.parse(input)
        } else {
            Err(Err::Error(make_error(input, ErrorKind::Alt)))
        }
    }
}

pub fn packet<I: Interface>(input: &[u8]) -> IResult<&[u8], Packet<'_, I>> {
    // let (input, _) = value(0x7e, u8)(input)?;
    let (input, header) = header(input)?;
    let (input, ifac) = cond(header.ifac_flag == IfacFlag::Authenticated, take(I::LENGTH))(input)?;
    let (input, destination) = match header.header_type {
        HeaderType::Type1 => map(hash, Destination::Type1)(input)?,
        HeaderType::Type2 => {
            map(tuple((hash, hash)), |(h1, h2)| Destination::Type2(h1, h2))(input)?
        }
    };
    let (input, context) = u8(input)?;
    let (input, data) = match header.packet_type {
        PacketType::Data => alt((
            when(
                header.header_type == HeaderType::Type1
                    && header.propagation_type == PropagationType::Broadcast
                    && header.destination_type == DestinationType::Plain,
                path_request,
            ),
            map(rest, Payload::Data),
        ))(input)?,
        PacketType::Announce => announce(destination)(input)?,
        PacketType::LinkRequest => todo!(),
        PacketType::Proof => todo!(),
    };
    Ok((
        input,
        Packet {
            header,
            ifac,
            destination,
            context,
            data,
            phantom: PhantomData,
        },
    ))
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> usize;
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> usize {
        self.extend_from_slice(buf);
        buf.len()
    }
}

impl<'a> Write for &'a mut [u8] {
    fn write(&mut self, buf: &[u8]) -> usize {
        let available = self.len().min(buf.len());
        self[..available].copy_from_slice(&buf[..available]);
        *self = &mut core::mem::take(self)[available..];
        available
    }
}

pub trait Encode {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize;
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

impl<const N: usize> Encode for &[u8; N] {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(self.as_slice())
    }
}

impl<'a> Encode for &'a [u8] {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(self)
    }
}

impl Encode for u8 {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(&[*self])
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        if let Some(s) = self {
            s.encode(writer)
        } else {
            0
        }
    }
}

impl<'a> Encode for PathRequest<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.destination_hash.encode(writer)
            + self.transport.encode(writer)
            + self.tag.encode(writer)
    }
}

impl<'a, I: Interface> Encode for Packet<'a, I> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.header.encode(writer)
            + self.destination.encode(writer)
            + self.context.encode(writer)
            + self.data.encode(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            destination: Destination::Type1(&[
                0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0,
                0x27, 0x61,
            ]),
            context: 0,
            data: Payload::PathRequest(PathRequest {
                destination_hash: &[
                    235, 252, 186, 213, 27, 223, 220, 228, 69, 35, 238, 49, 26, 222, 169, 162,
                ],
                transport: Some(&[
                    192, 202, 232, 46, 73, 147, 217, 13, 240, 198, 26, 209, 158, 195, 141, 166,
                ]),
                tag: Some(&[
                    4, 175, 40, 70, 0, 120, 59, 234, 132, 61, 97, 32, 189, 35, 51, 239,
                ]),
            }),
            phantom: PhantomData,
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

        // Path request for <ebfcbad51bdfdce44523ee311adea9a2> on TCPInterface[…]

        let input: &[u8] =&hex::decode("7e5101c0cae82e4993d90df0c61ad19ec38da66d36f782ca4930b5206e037d5ea2347d5e4a003a595fbdbfc3ffc33f2c3c1b51c507d36f3088f1ff39a323bdad94449cb29f496d61d09ea87915240dbf2ec38c03760d1f00112e9e521124ad3cbaf91e76d0b36ec60bc318e2c0f0d90810d1a8b21e0065c462116e0c92a19b915bcaf689796233c6da25571c60718402d3ca7baed6e5fd91911e666edee24321a58ada6149cc742006a12c254010396f26f768444107b14d9009427442204e6f646520526f6d656f20416c657274737e").unwrap();

        // &hex::decode("7e08006b9f66014d9853faab220fba47d0276100ebfcbad51bdfdce44523ee311adea9a2c0cae82e4993d90df0c61ad19ec38da604af284600783bea843d6120bd2333ef7e").unwrap();

        let zzz: IResult<&[u8], Packet<TestInf>> = hdlc(packet::<TestInf>)(input);

        // println!("{:?}", zzz);

        if let Ok((_, packet)) = zzz {
            if let Payload::Announce(ann) = packet.data {
                ann.validate();
            }
        }
    }
}
