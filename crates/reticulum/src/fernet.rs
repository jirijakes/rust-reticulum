use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockDecryptMut;
use aes::cipher::Iv;
use cbc::cipher::BlockEncryptMut;
use cbc::cipher::KeyIvInit;
use hmac::Mac;
use rand_core::CryptoRngCore;
use sha2::Sha256;

pub struct Fernet<Rng> {
    signing_key: [u8; 16],
    encryption_key: [u8; 16],
    rng: Rng,
}

const IV_LENGTH: usize = 16;
const HMAC_LENGTH: usize = 32;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

impl<Rng: CryptoRngCore> Fernet<Rng> {
    /// Encrypts `message` using this token. Writes encrypted message into `buf`
    /// and returns the relevant slice backed by `buf`.
    ///
    /// The method is not deterministic; internally it generates random data
    /// that are used as initial vector.
    pub fn encrypt<'a>(&mut self, message: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        let (iv, ciphertext) = buf.split_at_mut(IV_LENGTH);
        self.rng.fill_bytes(iv);

        let len = encrypt(
            message,
            ciphertext,
            iv.try_into().expect("correct length"),
            self.encryption_key,
            self.signing_key,
        );

        &buf[..len]
    }
}

impl<Rng> Fernet<Rng> {
    pub fn new(signing_key: [u8; 16], encryption_key: [u8; 16], rng: Rng) -> Self {
        Self {
            signing_key,
            encryption_key,
            rng,
        }
    }

    pub fn decrypt<'a>(&self, ciphertext: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        let hmac_index = ciphertext.len() - HMAC_LENGTH;

        let iv: [u8; IV_LENGTH] = ciphertext[0..IV_LENGTH].try_into().unwrap();
        let message = &ciphertext[IV_LENGTH..hmac_index];
        let tag: [u8; HMAC_LENGTH] = ciphertext[hmac_index..].try_into().unwrap();

        // let x = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
        //     .unwrap()
        //     .chain_update(iv)
        //     .chain_update(message)
        //     .verify_slice(&tag);

        Aes128CbcDec::new(&self.encryption_key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(message, &mut buf[..])
            .unwrap()
    }
}

/// Encrypts `plaintext` using `iv` as initial vector and `encryption_key`. Writes the encrypted message
/// into `ciphertext` and appends to it HMAC using `signing_key`. Returns total length of the encrypted message
/// including IV and HMAC.
fn encrypt(
    plaintext: &[u8],
    ciphertext: &mut [u8],
    iv: [u8; 16],
    encryption_key: [u8; 16],
    signing_key: [u8; 16],
) -> usize {
    let len = Aes128CbcEnc::new(&encryption_key.into(), &Iv::<Aes128CbcEnc>::from(iv))
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut ciphertext[..])
        .unwrap()
        .len();

    let mut digest = hmac::Hmac::<Sha256>::new_from_slice(signing_key.as_slice()).unwrap();
    digest.update(&iv);
    digest.update(&ciphertext[..len]);

    let hmac = digest.finalize().into_bytes();
    ciphertext[len..len + HMAC_LENGTH].copy_from_slice(&hmac[..]);

    IV_LENGTH + len + HMAC_LENGTH
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use hex::prelude::*;

    use crate::fernet::{Fernet, IV_LENGTH};

    use super::encrypt;

    struct T {
        sig: [u8; 16],
        enc: [u8; 16],
        iv: [u8; 16],
        plain: Vec<u8>,
        cipher: Vec<u8>,
    }

    fn token_enc_success() -> impl Iterator<Item = T> {
        include!("../tests/data/token_enc_success.txt").iter().map(
            |(sig, enc, iv, plain, cipher)| T {
                sig: <[u8; 16]>::from_hex(sig).unwrap(),
                enc: <[u8; 16]>::from_hex(enc).unwrap(),
                iv: <[u8; 16]>::from_hex(iv).unwrap(),
                plain: Vec::from_hex(plain).unwrap(),
                cipher: Vec::from_hex(cipher).unwrap(),
            },
        )
    }

    #[test]
    fn decrypt_reference() {
        token_enc_success().for_each(
            |T {
                 sig,
                 enc,
                 plain,
                 cipher,
                 ..
             }| {
                let mut buf = [0u8; 2048];
                let x = Fernet::new(sig, enc, ()).decrypt(&cipher, &mut buf);
                assert_eq!(plain, x);
            },
        )
    }

    #[test]
    fn encrypt_reference() {
        token_enc_success().for_each(
            |T {
                 sig,
                 enc,
                 iv,
                 plain,
                 cipher,
             }| {
                let mut buf = [0u8; 2048];
                buf[..IV_LENGTH].copy_from_slice(&iv);

                let len = encrypt(&plain, &mut buf[IV_LENGTH..], iv, enc, sig);

                assert_eq!(buf[..len], cipher);
            },
        );
    }
}
