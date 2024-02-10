use std::fmt::Debug;

use sha2::{Digest, Sha256};

use crate::announce::Announce;
use crate::encode::{Encode, Write};
use crate::identity::Identity;
use crate::packet::DestinationType;
use crate::sign::Sign;

pub struct Destination<'a> {
    identity: &'a Identity,
    // direction?
    destination_type: DestinationType,
    app_name: &'a str,
    aspects: &'a str,
    name_hash: [u8; 10],
    hash: [u8; 16],
}

impl<'a> Destination<'a> {
    pub fn new(
        identity: &'a Identity,
        destination_type: DestinationType,
        app_name: &'a str,
        aspects: &'a str,
    ) -> Destination<'a> {
        let name_hash = Self::calculate_name_hash(app_name, aspects);
        let hash = Self::calculate_hash(&name_hash, identity);
        Destination {
            identity,
            destination_type,
            app_name,
            aspects,
            name_hash,
            hash,
        }
    }

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
            public_key: *self.identity.public_key(),
            verifying_key: *self.identity.verifying_key(),
            signature: sign.sign(&buf), //sign(digest),
            name_hash: &self.name_hash,
            random_hash,
            app_data: None,
            destination: DestinationHash::Type1(&self.hash),
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

    pub fn destination_type(&self) -> &DestinationType {
        &self.destination_type
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
