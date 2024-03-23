use ed25519_dalek::{Signature, Signer, SigningKey};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub trait Sign {
    fn sign(&self, message: &[u8]) -> Signature;
}

pub trait Dh {
    fn dh(&self, public_key: &PublicKey) -> SharedSecret;
}

#[derive(Clone)]
pub struct FixedKeys(StaticSecret, SigningKey);

impl FixedKeys {
    pub const fn new(static_secret: StaticSecret, signing_key: SigningKey) -> Self {
        Self(static_secret, signing_key)
    }
}

impl Sign for FixedKeys {
    fn sign(&self, message: &[u8]) -> Signature {
        self.1.sign(message)
    }
}

impl Dh for FixedKeys {
    fn dh(&self, public_key: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(public_key)
    }
}
