use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::{destination::DestinationHash, encode::{Encode, Write}, identity::Identity};

#[derive(Debug)]
pub struct Announce<'a> {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
    pub signature: Signature,
    pub name_hash: &'a [u8; 10],
    pub random_hash: &'a [u8; 10],
    pub app_data: Option<&'a [u8]>,
    pub destination: DestinationHash<'a>,
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
            DestinationHash::Type1(h) => {
                message.extend_from_slice(h);
            }
            DestinationHash::Type2(_, h2) => {
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
        let valid = self.verifying_key.verify_strict(&message, &self.signature);

        let identity = Identity::new(self.public_key, self.verifying_key);

        let mut engine = Sha256::new();
        engine.update(self.name_hash);
        engine.update(identity.hash());
        let x: [u8; 32] = engine.finalize().into();

        println!("Validation: {valid:?} {}", hex::encode(&x[..16]));
    }
}
