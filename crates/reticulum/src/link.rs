use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use hex::DisplayHex;
use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::sign::Sign;
use crate::token::Token;

pub struct Lynx([u8; Self::LENGTH]);

impl Lynx {
    const LENGTH: usize = 32 /* x25519 public key length */  + ed25519_dalek::PUBLIC_KEY_LENGTH;

    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        let mut bytes: [u8; Self::LENGTH] = [0; Self::LENGTH];
        bytes[0..32].copy_from_slice(public_key.as_bytes());
        bytes[32..64].copy_from_slice(verifying_key.as_bytes());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

pub struct LinkKeys {
    signing_key: SigningKey,
    public_key: PublicKey,
}

impl LinkKeys {
    pub fn generate<T: CryptoRngCore>(mut csprng: T) -> (LinkKeys, EphemeralSecret) {
        let signing_key = SigningKey::generate(&mut csprng);
        let ephemeral_secret = EphemeralSecret::random_from_rng(csprng);
        let keys = LinkKeys {
            signing_key,
            public_key: (&ephemeral_secret).into(),
        };

        (keys, ephemeral_secret)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

pub struct Link {
    id: LinkId,
    public_key: PublicKey,
    verifying_key: VerifyingKey,
    token: Token<OsRng>,
}

impl Link {
    pub fn decrypt<'a>(&self, ciphertext: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        self.token.decrypt(ciphertext, buf).unwrap()
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

    pub fn establish_link(&self, ephemeral_secret: EphemeralSecret) -> Link {
        Link {
            id: self.id,
            public_key: self.public_key,
            verifying_key: self.verifying_key,
            token: Token::derive(ephemeral_secret, self.public_key, self.id.as_bytes(), OsRng),
        }
    }

    /// Generates a signed proof that the link request was received by `identity`.
    pub fn prove<S: Sign>(&self, keys: &LinkKeys, secrets: &S) -> LinkProof {
        const M1: usize = 16;
        const M2: usize = M1 + PUBLIC_KEY_LENGTH;
        const M3: usize = M2 + PUBLIC_KEY_LENGTH;

        let mut message = [0u8; M3];

        message[0..M1].copy_from_slice(self.id.as_bytes());
        message[M1..M2].copy_from_slice(keys.public_key().as_bytes());
        message[M2..M3].copy_from_slice(keys.verifying_key().as_bytes());

        const P1: usize = Signature::BYTE_SIZE;
        const P2: usize = P1 + PUBLIC_KEY_LENGTH;

        let mut proof = [0u8; P2];

        proof[0..P1].copy_from_slice(&secrets.sign(&message).to_bytes());
        proof[P1..P2].copy_from_slice(keys.public_key().as_bytes());

        LinkProof(proof)
    }

    /// Returns ID of the link that is subject to this request.
    pub const fn link_id(&self) -> LinkId {
        self.id
    }
}

#[derive(PartialEq, Eq, Copy, Clone)]
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.as_hex())
    }
}

#[derive(Debug)]
/// Signed proof that link request was received.
pub struct LinkProof([u8; LinkProof::BYTE_SIZE]);

impl LinkProof {
    pub const BYTE_SIZE: usize = Signature::BYTE_SIZE + PUBLIC_KEY_LENGTH;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }

    pub const fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }

    /// Extracts signature from the Link Proof.
    pub fn signature(&self) -> Signature {
        Signature::from_bytes(self.0[0..Signature::BYTE_SIZE].try_into().expect("64 < 96"))
    }

    /// Extracts public key from the Link Proof.
    pub fn public_key(&self) -> PublicKey {
        let data: [u8; PUBLIC_KEY_LENGTH] = self.0[Signature::BYTE_SIZE..]
            .try_into()
            .expect("64 + 32 = 96");
        PublicKey::from(data)
    }
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
                request.id.as_bytes(),
                &[
                    0x60, 0xc1, 0xb9, 0xa3, 0x5a, 0xc4, 0xbd, 0xc2, 0x3c, 0x09, 0x77, 0xb3, 0x8d,
                    0x5c, 0x72, 0xce,
                ]
            )
        }
    }
}
