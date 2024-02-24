//!
//! # Predefined destinations
//!
//! ## RNS destination for path requests
//!
//! RNS [defines][rns-path-request-destination] a dedicated destination for path requests.
//! Only path requests sent to this destination are considered.
//!
//! The destination is accessible as constant [`RNS_PATH_REQUEST_DESTINATION`] and has the following properties:
//! ``` text
//!  type = Plain
//!  direction = Out
//!  app_name = "rnstransport"
//!  aspects = "path.request"
//!  name hash = 7926bbe7dd7f9aba88b0
//!  hash = 6b9f66014d9853faab220fba47d02761
//! ```
//!
//! [rns-path-request-destination]: https://github.com/markqvist/Reticulum/blob/35e9a0b38a4a88df1bde3d69ab014d35aadd05b9/RNS/Transport.py#L170
//!

use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::announce::Announce;
use crate::encode::{Encode, Write};
use crate::identity::Identity;
use crate::packet;
use crate::path_request::PathRequest;
use crate::sign::Sign;

/// 'SINGLE' destination type.
pub struct Single;

/// 'GROUP' destination type.
pub struct Group;

/// 'PLAIN' destination type.
pub struct Plain;

/// 'LINK' destination type.
pub struct Link;

/// 'IN' direction.
pub struct In;

/// 'OUT' direction.
pub struct Out;

mod sealed {
    use crate::identity::Identity;

    pub trait Type {}

    impl Type for super::Single {}
    impl Type for super::Group {}
    impl Type for super::Plain {}
    impl Type for super::Link {}

    pub trait Direction {}

    impl Direction for super::In {}
    impl Direction for super::Out {}

    pub trait AsIdentity {}

    impl AsIdentity for Identity {}
    impl AsIdentity for () {}
}

/// Marker trait for type of [`Destination`].
pub trait Type: sealed::Type {
    fn to_destination_type() -> packet::DestinationType;
}

impl Type for Single {
    fn to_destination_type() -> packet::DestinationType {
        packet::DestinationType::Single
    }
}

impl Type for Group {
    fn to_destination_type() -> packet::DestinationType {
        packet::DestinationType::Group
    }
}

impl Type for Plain {
    fn to_destination_type() -> packet::DestinationType {
        packet::DestinationType::Plain
    }
}

impl Type for Link {
    fn to_destination_type() -> packet::DestinationType {
        packet::DestinationType::Link
    }
}

pub trait Direction: sealed::Direction {}
impl Direction for In {}
impl Direction for Out {}

pub trait AsIdentity: sealed::AsIdentity {
    fn hash(&self) -> Option<&[u8; 16]>;
}
impl AsIdentity for Identity {
    fn hash(&self) -> Option<&[u8; 16]> {
        Some(self.hash())
    }
}
impl AsIdentity for () {
    fn hash(&self) -> Option<&[u8; 16]> {
        None
    }
}

/// RNS destination for path requests.
pub const RNS_PATH_REQUEST_DESTINATION: Destination<'_, Plain, Out, ()> =
    Destination::for_path_request();

pub struct Destination<'a, T, D, I> {
    identity: &'a I,
    app_name: &'a str,
    aspects: &'a str,
    name_hash: [u8; 10],
    hash: [u8; 16],
    destination_type: PhantomData<T>,
    direction: PhantomData<D>,
}

impl<'a> Destination<'a, Single, In, Identity> {
    pub fn single_in(
        identity: &'a Identity,
        app_name: &'a str,
        aspects: &'a str,
    ) -> Destination<'a, Single, In, Identity> {
        Self::new(identity, app_name, aspects)
    }

    /// Create a signed announcement for this destination.
    pub fn announce(
        &'a self,
        random_hash: [u8; 10],
        app_data: Option<&'a [u8]>,
        sign: &impl Sign,
    ) -> Announce<'a> {
        let mut buf = vec![];
        buf.extend_from_slice(&self.hash);
        buf.extend_from_slice(self.identity.public_key().as_bytes());
        buf.extend_from_slice(self.identity.verifying_key().as_bytes());
        buf.extend_from_slice(&self.name_hash);
        buf.extend_from_slice(&random_hash);
        if let Some(data) = app_data {
            buf.extend_from_slice(data);
        }

        Announce {
            identity: self.identity.clone(),
            signature: sign.sign(&buf), //sign(digest),
            name_hash: &self.name_hash,
            random_hash,
            app_data,
            destination: DestinationHash::Type1(self.hash),
        }
    }

    /// Create a signed announcement for this destination, generating random hash using provided RNG.
    pub fn announce_rnd<R: RngCore>(
        &'a self,
        rng: &mut R,
        app_data: Option<&'a [u8]>,
        sign: &impl Sign,
    ) -> Announce<'a> {
        let mut random_hash = [0u8; 10];
        rng.fill_bytes(&mut random_hash);
        self.announce(random_hash, app_data, sign)
    }

    pub fn name(&self) -> String {
        [
            self.app_name,
            ".",
            self.aspects,
            ".",
            &self.identity.hash_str(),
        ]
        .concat()
    }

    pub const fn identity(&self) -> &Identity {
        self.identity
    }
}

impl<'a> Destination<'a, Plain, Out, ()> {
    pub fn plain_out(app_name: &'a str, aspects: &'a str) -> Destination<'a, Plain, Out, ()> {
        Self::new(&(), app_name, aspects)
    }

    /// Returns destination used by path requests.
    ///
    /// In RNS, this is defined in `Transport.path_request_destination`. RNS will ignore any path
    /// requests that are not coming to exactly this destination.
    const fn for_path_request() -> Destination<'a, Plain, Out, ()> {
        Destination {
            identity: &(),
            app_name: "rnstransport",
            aspects: "path.request",
            name_hash: [0x79, 0x26, 0xbb, 0xe7, 0xdd, 0x7f, 0x9a, 0xba, 0x88, 0xb0],
            hash: [
                0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0,
                0x27, 0x61,
            ],
            destination_type: PhantomData,
            direction: PhantomData,
        }
    }

    pub const fn path_request(
        &'a self,
        query: &'a [u8; 16],
        transport: Option<&'a [u8; 16]>,
        tag: Option<&'a [u8]>,
    ) -> PathRequest<'a> {
        PathRequest {
            query,
            transport,
            tag,
        }
    }
}

impl<'a, T: Type, D: Direction, I: AsIdentity> Destination<'a, T, D, I> {
    pub fn new(identity: &'a I, app_name: &'a str, aspects: &'a str) -> Destination<'a, T, D, I> {
        let name_hash = Self::calculate_name_hash(app_name, aspects);
        let hash = Self::calculate_hash(&name_hash, identity);
        Destination {
            identity,
            app_name,
            aspects,
            name_hash,
            hash,
            destination_type: PhantomData,
            direction: PhantomData,
        }
    }

    fn calculate_name_hash(app_name: &str, aspects: &str) -> [u8; 10] {
        let mut engine = Sha256::new();
        engine.update(app_name);
        engine.update(".");
        engine.update(aspects);
        engine.finalize()[..10].try_into().expect("10 bytes")
    }

    fn calculate_hash(name_hash: &[u8; 10], identity: &I) -> [u8; 16] {
        let mut engine = Sha256::new();
        engine.update(name_hash);
        if let Some(id_hash) = identity.hash() {
            engine.update(id_hash);
        }
        engine.finalize()[..16].try_into().expect("16 bytes")
    }

    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::to_destination_type()
    }

    pub const fn app_name(&self) -> &str {
        self.app_name
    }

    pub const fn name_hash(&self) -> [u8; 10] {
        self.name_hash
    }

    pub const fn hash(&self) -> [u8; 16] {
        self.hash
    }

    pub const fn to_destination_hash(&self) -> DestinationHash {
        DestinationHash::Type1(self.hash())
    }

    pub const fn aspects(&self) -> &str {
        self.aspects
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DestinationHash {
    Type1([u8; 16]),
    Type2([u8; 16], [u8; 16]),
}

impl Debug for DestinationHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut tuple = f.debug_tuple("Destination");
        match self {
            DestinationHash::Type1(h) => tuple.field(&hex::encode(h)).finish(),
            DestinationHash::Type2(h1, h2) => tuple
                .field(&hex::encode(h1))
                .field(&hex::encode(h2))
                .finish(),
        }
    }
}

impl Encode for DestinationHash {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            DestinationHash::Type1(h) => h.encode(writer),
            DestinationHash::Type2(h1, h2) => h1.encode(writer) + h2.encode(writer),
        }
    }
}
