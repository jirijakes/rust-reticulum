use ed25519_dalek::{Signature, Signer, SigningKey};

pub trait Sign {
    fn sign(&self, message: &[u8]) -> Signature;
}

pub struct FixedKey(SigningKey);

impl FixedKey {
    pub fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl Sign for FixedKey {
    fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }
}
