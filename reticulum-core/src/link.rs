use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH};
use hex::DisplayHex;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::fernet::Fernet;
use crate::identity::Identity;
use crate::sign::{Dh, Sign};

pub struct Link {
    id: LinkId,
    public_key: PublicKey,
    verifying_key: VerifyingKey,
    fernet: Fernet<OsRng>,
}

impl Link {
    pub fn decrypt<'a>(&self, ciphertext: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        self.fernet.decrypt(ciphertext, buf)
    }

    pub const fn link_id(&self) -> &LinkId {
        &self.id
    }
}

#[derive(Debug)]
pub struct LinkRequest {
    id: LinkId,
    public_key: PublicKey,
    verifying_key: VerifyingKey,
}

impl LinkRequest {
    pub const fn new(id: LinkId, public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        Self {
            id,
            public_key,
            verifying_key,
        }
    }

    pub fn establish_link<S: Dh>(&self, secrets: &S) -> Link {
        let mut derived_key = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(
            Some(self.id.as_bytes()),
            secrets.dh(&self.public_key).as_bytes(),
        );
        hkdf.expand(&[], &mut derived_key)
            .expect("32 bytes is fine for Sha256");

        let (signing_key, encryption_key) = derived_key.split_at(16);

        let signing_key = signing_key.try_into().expect("There should be 16 bytes.");
        let encryption_key = encryption_key
            .try_into()
            .expect("There should be another 16 bytes.");

        let fernet = Fernet::new(signing_key, encryption_key, OsRng);

        Link {
            id: self.id,
            public_key: self.public_key,
            verifying_key: self.verifying_key,
            fernet,
        }
    }

    /// Generates a signed proof that the link request was received by `identity`.
    pub fn prove<S: Sign>(&self, identity: &Identity, secrets: &S) -> LinkProof {
        const M1: usize = 16;
        const M2: usize = M1 + PUBLIC_KEY_LENGTH;
        const M3: usize = M2 + PUBLIC_KEY_LENGTH;

        let mut message = [0u8; M3];

        message[0..M1].copy_from_slice(self.id.as_bytes());
        message[M1..M2].copy_from_slice(identity.public_key().as_bytes());
        message[M2..M3].copy_from_slice(identity.verifying_key().as_bytes());

        const P1: usize = Signature::BYTE_SIZE;
        const P2: usize = P1 + PUBLIC_KEY_LENGTH;

        let mut proof = [0u8; P2];

        proof[0..P1].copy_from_slice(&secrets.sign(&message).to_bytes());
        proof[P1..P2].copy_from_slice(identity.public_key().as_bytes());

        LinkProof(proof)
    }

    /// Returns ID of the link that is subject to this request.
    pub const fn link_id(&self) -> LinkId {
        self.id
    }
}

#[derive(Copy, Clone)]
pub struct LinkId([u8; 16]);

impl LinkId {
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }

    pub const fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }

    pub const BYTE_SIZE: usize = 16;
}

impl From<[u8; 16]> for LinkId {
    fn from(value: [u8; 16]) -> Self {
        LinkId(value)
    }
}

impl core::fmt::Debug for LinkId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LinkId({})", self.0.as_hex())
    }
}

impl core::fmt::Display for LinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_hex())
    }
}

/// Signed proof that link request was received.
pub struct LinkProof([u8; LinkProof::BYTE_SIZE]);

impl LinkProof {
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }

    pub const fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }

    pub const BYTE_SIZE: usize = Signature::BYTE_SIZE + PUBLIC_KEY_LENGTH;
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::context::RnsContext;
    use crate::interface::Interface;
    use crate::packet::Payload;
    use crate::parse;

    #[derive(Debug)]
    struct TestInf;
    impl Interface for TestInf {
        const LENGTH: usize = 2;
    }

    #[test]
    fn parse() {
        // cross-verified with reference implementation
        let raw = hex!("020077b65c2bc324a2fe1d6d7520ae53f17300eeb5be3cbdee6c56d23ca05cfce5342feaeb4bf2b3e54ab5defcf0c2706dc027a8410f9a44306cba01f58937610c31d4844cb84e86505c3ed3fb477d036965c8");
        let packet = parse::packet::<TestInf, RnsContext>(&raw);
        assert!(packet.is_ok());
        let (_, link_request) = packet.unwrap();
        assert!(matches!(link_request.data, Payload::LinkRequest(_)));
        if let Payload::LinkRequest(request) = link_request.data {
            assert_eq!(
                request.id,
                [
                    0x60, 0xc1, 0xb9, 0xa3, 0x5a, 0xc4, 0xbd, 0xc2, 0x3c, 0x09, 0x77, 0xb3, 0x8d,
                    0x5c, 0x72, 0xce,
                ]
            )
        }
    }
}
