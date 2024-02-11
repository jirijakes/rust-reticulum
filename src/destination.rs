use std::fmt::Debug;
use std::marker::PhantomData;

use sha2::{Digest, Sha256};

use crate::announce::Announce;
use crate::encode::{Encode, Write};
use crate::identity::Identity;
use crate::packet;
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
    pub trait Type {}

    impl Type for super::Single {}
    impl Type for super::Group {}
    impl Type for super::Plain {}
    impl Type for super::Link {}

    pub trait Direction {}

    impl Direction for super::In {}
    impl Direction for super::Out {}
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

pub struct Destination<'a, T: Type, D: Direction> {
    identity: &'a Identity,
    app_name: &'a str,
    aspects: &'a str,
    name_hash: [u8; 10],
    hash: [u8; 16],
    destination_type: PhantomData<T>,
    direction: PhantomData<D>,
}

impl<'a> Destination<'a, Single, In> {
    pub fn single_in(
        identity: &'a Identity,
        app_name: &'a str,
        aspects: &'a str,
    ) -> Destination<'a, Single, In> {
        Self::new(identity, app_name, aspects)
    }

    /// Create a signed announcement for this destination.
    pub fn announce(
        &'a self,
        random_hash: &'a [u8; 10],
        app_data: Option<&[u8]>,
        sign: impl Sign,
    ) -> Announce<'a> {
        let mut buf = vec![];
        buf.extend_from_slice(&self.hash);
        buf.extend_from_slice(self.identity.public_key().as_bytes());
        buf.extend_from_slice(self.identity.verifying_key().as_bytes());
        buf.extend_from_slice(&self.name_hash);
        buf.extend_from_slice(random_hash);
        if let Some(data) = app_data {
            buf.extend_from_slice(data);
        }

        Announce {
            identity: self.identity.clone(),
            signature: sign.sign(&buf), //sign(digest),
            name_hash: &self.name_hash,
            random_hash,
            app_data: None,
            destination: DestinationHash::Type1(&self.hash),
        }
    }
}

impl<'a, T: Type, D: Direction> Destination<'a, T, D> {
    pub fn new(
        identity: &'a Identity,
        app_name: &'a str,
        aspects: &'a str,
    ) -> Destination<'a, T, D> {
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

    fn calculate_name_hash(app_name: &str, aspects: &str) -> [u8; 10] {
        let mut engine = Sha256::new();
        engine.update(app_name);
        engine.update(".");
        engine.update(aspects);
        engine.finalize()[..10].try_into().expect("10 bytes")
    }

    fn calculate_hash(name_hash: &[u8; 10], identity: &Identity) -> [u8; 16] {
        let mut engine = Sha256::new();
        engine.update(name_hash);
        engine.update(identity.hash());
        engine.finalize()[..16].try_into().expect("16 bytes")
    }

    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::to_destination_type()
    }

    pub fn app_name(&self) -> &str {
        self.app_name
    }

    pub fn name_hash(&self) -> [u8; 10] {
        self.name_hash
    }

    pub fn hash(&self) -> [u8; 16] {
        self.hash
    }

    pub fn identity(&self) -> &Identity {
        self.identity
    }

    pub fn aspects(&self) -> &str {
        self.aspects
    }
}

#[derive(Clone, Copy)]
pub enum DestinationHash<'a> {
    Type1(&'a [u8; 16]),
    Type2(&'a [u8; 16], &'a [u8; 16]),
}

impl<'a> Debug for DestinationHash<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl<'a> Encode for DestinationHash<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            DestinationHash::Type1(h) => h.encode(writer),
            DestinationHash::Type2(h1, h2) => h1.encode(writer) + h2.encode(writer),
        }
    }
}
