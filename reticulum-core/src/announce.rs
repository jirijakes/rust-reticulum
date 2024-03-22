use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

use crate::encode::{Encode, Write};
use crate::identity::Identity;

#[derive(Debug)]
pub struct Announce<'a> {
    pub identity: Identity,
    pub signature: Signature,
    pub name_hash: &'a [u8; 10],
    pub random_hash: [u8; 10],
    pub app_data: Option<&'a [u8]>,
    pub destination: [u8; 16],
}

impl<'a> Encode for Announce<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.identity.encode(writer)
            + self.name_hash.encode(writer)
            + self.random_hash.encode(writer)
            + self.signature.to_bytes().as_slice().encode(writer)
            + self.app_data.encode(writer)
    }
}

impl<'a> Announce<'a> {
    pub fn validate(&self) {
        let mut message = vec![];
        message.extend_from_slice(&self.destination);
        message.extend_from_slice(self.identity.public_key().as_bytes());
        message.extend_from_slice(self.identity.verifying_key().as_bytes());
        message.extend_from_slice(self.name_hash);
        message.extend_from_slice(&self.random_hash);
        if let Some(data) = self.app_data {
            message.extend_from_slice(data);
        }
        let valid = self.identity.verify(&message, &self.signature);

        let mut engine = Sha256::new();
        engine.update(self.name_hash);
        engine.update(self.identity.hash());
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
        let announce = destination.announce([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], None, &sign);
        announce.validate();

        let packet: Packet<'_, TestInf> = Packet::from_announce(announce);

        let mut buf = Vec::new();
        let _ = packet.encode(&mut buf);

        let packet: Packet<TestInf> = parse::packet(&buf).unwrap().1;
        if let Payload::Announce(ann) = packet.data {
            ann.validate();
        }
    }
}
