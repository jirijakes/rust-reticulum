use alloc::string::{String, ToString};
use core::fmt::Debug;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use generic_array::sequence::*;
use hex::DisplayHex;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::encode::Encode;

#[derive(Copy, Clone)]
pub struct Identity {
    public_key: PublicKey,
    verifying_key: VerifyingKey,
    hash: [u8; 16],
}

impl Identity {
    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Identity {
        Identity {
            public_key,
            verifying_key,
            hash: Self::calculate_hash(&public_key, &verifying_key),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn hash(&self) -> [u8; 16] {
        self.hash
    }

    pub fn hash_str(&self) -> String {
        self.hash().as_hex().to_string()
    }

    pub fn generate<T: CryptoRngCore>(mut csprng: T) -> (Identity, StaticSecret, SigningKey) {
        let sign_key = SigningKey::generate(&mut csprng);
        let dh_key = StaticSecret::random_from_rng(csprng);
        (
            Self::new((&dh_key).into(), sign_key.verifying_key()),
            dh_key,
            sign_key,
        )
    }

    pub fn load(sign_key: SigningKey, dh_key: StaticSecret) -> Identity {
        Self::new((&dh_key).into(), sign_key.verifying_key())
    }

    pub fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::ed25519::Error> {
        self.verifying_key.verify_strict(msg, signature)
    }

    fn calculate_hash(pubkey: &PublicKey, verifying_key: &VerifyingKey) -> [u8; 16] {
        Sha256::new()
            .chain_update(pubkey)
            .chain_update(verifying_key)
            .finalize()
            .split()
            .0
            .into()
    }
}

impl Encode for Identity {
    fn encode<W: crate::encode::Write + ?Sized>(&self, writer: &mut W) -> usize {
        self.public_key.as_bytes().encode(writer)
            + self.verifying_key.to_bytes().as_slice().encode(writer)
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("Identity({})", self.hash_str()))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::Identity;

    #[test]
    fn generates() {
        let (id, _sec, _sig) = Identity::generate(OsRng);
        // println!("{:?}", id);
    }
}
