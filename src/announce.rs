use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::{
    destination::DestinationHash,
    encode::{Encode, Write},
    identity::Identity,
};

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
            + self.verifying_key.to_bytes().as_slice().encode(writer)
            + self.name_hash.encode(writer)
            + self.random_hash.encode(writer)
            + self.signature.to_bytes().as_slice().encode(writer)
            + self.app_data.encode(writer)
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

#[cfg(test)]
mod tests {
    use rand_core::*;

    use crate::destination::Destination;
    use crate::encode::*;
    use crate::identity::Identity;
    use crate::interface::Interface;
    use crate::packet::{Packet, Payload};
    use crate::parse;
    use crate::sign::FixedKey;

    #[derive(Debug)]
    struct TestInf;
    impl Interface for TestInf {
        const LENGTH: usize = 2;
    }

    #[test]
    fn there_and_back() {
        let (identity, _, sign_key) = Identity::generate(OsRng);
        let sign = FixedKey::new(sign_key);
        let destination = Destination::single_in(&identity, "testing_app", "fruits");
        let announce = destination.announce(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], None, sign);
        announce.validate();

        let packet: Packet<'_, TestInf> = Packet::from_announce(announce);

        let mut buf = Vec::new();
        let _ = packet.encode(&mut buf);

        if let Payload::Announce(ann) = parse::packet::<TestInf>(&buf).unwrap().1.data {
            ann.validate();
        }
    }
}
