use core::marker::PhantomData;

use ed25519_dalek::VerifyingKey;
use generic_array::sequence::*;
use nom::bits::bits;
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, map_opt, map_res, rest, success, verify};
use nom::complete::bool;
use nom::error::{make_error, ErrorKind, ParseError};
use nom::number::complete::u8;
use nom::sequence::tuple;
use nom::{Err, IResult, Parser};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::announce::Announce;
use crate::context::Context;
use crate::identity::Identity;
use crate::interface::Interface;
use crate::link::{LinkId, LinkProof, LinkRequest};
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType, Payload,
    PropagationType,
};
use crate::path_request::PathRequest;

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

fn header(input: &[u8]) -> IResult<&[u8], Header> {
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

fn hash(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
    let (input, b): (&[u8], _) = take(16usize)(input)?;
    match b.try_into() {
        Ok(b) => Ok((input, b)),
        Err(_) => Err(Err::Failure(make_error(input, ErrorKind::LengthValue))),
    }
}

fn path_request(input: &[u8]) -> IResult<&[u8], Payload> {
    let (input, destination_hash) = hash(input)?;

    let (input, (transport, tag)) = alt((
        map(
            tuple((hash, verify(rest, |r: &[u8]| !r.is_empty()))),
            |(tr, tag)| (Some(tr), Some(tag)),
        ),
        map(rest, |tag: &[u8]| {
            (None, Some(tag).filter(|t| !t.is_empty()))
        }),
        success((None, None)),
    ))(input)?;

    Ok((
        input,
        Payload::PathRequest(PathRequest {
            query: destination_hash,
            transport,
            tag,
        }),
    ))
}

fn array<const N: usize>(input: &[u8]) -> IResult<&[u8], [u8; N]> {
    let (input, bytes) = take(N)(input)?;
    let array = bytes
        .try_into()
        .map_err(|_| Err::Failure(make_error(input, ErrorKind::LengthValue)))?;

    Ok((input, array))
}

fn identity(input: &[u8]) -> IResult<&[u8], Identity> {
    let (input, public_key) = map(array, |a| PublicKey::from(a))(input)?;
    let (input, verifying_key) = map_opt(array, |a| VerifyingKey::from_bytes(&a).ok())(input)?;
    Ok((input, Identity::new(public_key, verifying_key)))
}

fn announce(destination: [u8; 16]) -> impl FnMut(&[u8]) -> IResult<&[u8], Payload> {
    move |input| {
        let (input, identity) = identity(input)?;
        let (input, name_hash) = array(input)?;
        let (input, random_hash) = array(input)?;
        let (input, signature) = map(array, |a| a.into())(input)?;
        let (input, app_data) =
            map(rest, |data: &[u8]| Some(data).filter(|d| !d.is_empty()))(input)?;
        Ok((
            input,
            Payload::Announce(Announce {
                identity,
                signature,
                name_hash,
                random_hash,
                app_data,
                destination,
            }),
        ))
    }
}

/// Parser for Link Request for a link with `id` (derived from packet).
fn link_request(id: LinkId) -> impl FnMut(&[u8]) -> IResult<&[u8], Payload> {
    move |input| {
        let (input, public_key) = map(array, |a| PublicKey::from(a))(input)?;
        let (input, verifying_key) = map_opt(array, |a| VerifyingKey::from_bytes(&a).ok())(input)?;

        Ok((
            input,
            Payload::LinkRequest(LinkRequest::new(id, public_key, verifying_key)),
        ))
    }
}

fn link_data(context: PacketContext) -> impl FnMut(&[u8]) -> IResult<&[u8], Payload> {
    move |input| {
        let (input, data) = rest(input)?;
        Ok((input, Payload::LinkData(context, data)))
    }
}

/// Parser for a Link Proof.
fn link_proof(input: &[u8]) -> IResult<&[u8], Payload> {
    map(array, |s| Payload::LinkProof(LinkProof::from_bytes(s)))(input)
}

/// Parser for Packet Context.
fn packet_context(input: &[u8]) -> IResult<&[u8], PacketContext> {
    map_res(u8, PacketContext::try_from)(input)
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

pub fn packet<I: Interface, C: Context>(input: &[u8]) -> IResult<&[u8], Packet<'_, I, C>> {
    let mut packet_hash = Sha256::new();
    packet_hash.update([input[0] & 0b00001111]);

    let (input, header) = header(input)?;
    let (input, ifac) = cond(header.ifac_flag == IfacFlag::Authenticated, take(I::LENGTH))(input)?;
    let (input, transport_id) = if header.header_type == HeaderType::Type2 {
        map(hash, |h| Some(h))(input)?
    } else {
        success(None)(input)?
    };

    packet_hash.update(input);

    let (input, destination) = hash(input)?;
    let (input, context) = packet_context(input)?;
    let (input, data) = match header.packet_type {
        PacketType::Data => alt((
            when(
                header.header_type == HeaderType::Type1
                    && header.propagation_type == PropagationType::Broadcast
                    && header.destination_type == DestinationType::Plain
                    && <C as Context>::path_request_destinations()
                        .iter()
                        .any(|d| destination == d.hash()),
                path_request,
            ),
            when(
                header.header_type == HeaderType::Type1
                    && header.propagation_type == PropagationType::Broadcast
                    && header.destination_type == DestinationType::Link,
                link_data(context),
            ),
            map(rest, Payload::Data),
        ))(input)?,
        PacketType::Announce => announce(destination)(input)?,
        PacketType::LinkRequest => {
            let truncated: [_; 16] = packet_hash.finalize().split().0.into();
            link_request(truncated.into())(input)?
        }
        PacketType::Proof => link_proof(input)?,
    };
    Ok((
        input,
        Packet {
            header,
            ifac,
            destination,
            transport_id,
            context,
            data,
            interface: PhantomData,
            xcontext: PhantomData,
        },
    ))
}
