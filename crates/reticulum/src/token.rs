use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, Iv};
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Token for encrypting and decrypting data.
///
/// ## Internals
///
/// Encryption tokens are based on [https://github.com/fernet/spec/](Fernet) without
/// version byte and timestamp. They use 16-byte signing key and 16-byte encryption key.
/// Underlying cipher is AES-128-CBC-HMAC-SHA256 with PKCS#7 padding.
///
/// ## Format of ciphertext
///
/// ```txt
///       16 B            N × 16 B                  32 B
/// +----------------+------/ /-------+--------------------------------+
/// |      IV        |    MESSAGE     |             HMAC               |
/// +----------------+------/ /-------+--------------------------------+
/// ```
pub struct Token<Rng> {
    signing_key: [u8; 16],
    encryption_key: [u8; 16],
    rng: Rng,
}

const IV_LENGTH: usize = 16;
const HMAC_LENGTH: usize = 32;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

impl<Rng: CryptoRngCore> Token<Rng> {
    /// Encrypts `message` using this token. Writes encrypted message into `buf`
    /// and returns the relevant slice backed by `buf`.
    ///
    /// The method is not deterministic; internally it generates
    /// random data that are used as initial vector. `buf` requires at
    /// least 64 bytes (16 bytes IV, 16 bytes padding, 32 bytes HMAC).
    ///
    /// Returns error if `buf` is not long enough for encrypted message.
    pub fn encrypt<'a>(
        &mut self,
        message: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], EncryptError> {
        let (iv, ciphertext) = buf
            .split_at_mut_checked(IV_LENGTH)
            .ok_or(EncryptError::InsufficientBuffer)?;
        self.rng.fill_bytes(iv);

        let len = encrypt(
            message,
            ciphertext,
            iv.try_into().expect("correct length"),
            self.encryption_key,
            self.signing_key,
        )?;

        buf.get(..len).ok_or(EncryptError::InsufficientBuffer)
    }

    /// Creates new token by deriving keys using ECDH and HKDF.
    pub fn derive(
        ephemeral_secret: EphemeralSecret,
        public_key: PublicKey,
        salt: &[u8],
        rng: Rng,
    ) -> Self {
        let hkdf = Hkdf::<Sha256>::new(
            Some(salt),
            ephemeral_secret.diffie_hellman(&public_key).as_bytes(),
        );

        let mut derived_key = [0u8; 32];
        hkdf.expand(&[], &mut derived_key)
            .expect("32 bytes is fine for Sha256");

        let (signing_key, encryption_key) = derived_key.split_at(16);

        let signing_key = signing_key.try_into().expect("There should be 16 bytes.");
        let encryption_key = encryption_key
            .try_into()
            .expect("There should be another 16 bytes.");

        Self::new(signing_key, encryption_key, rng)
    }

    /// Generates new random token.
    pub fn random(mut rng: Rng) -> Self {
        let mut signing_key = [0u8; 16];
        rng.fill_bytes(&mut signing_key[..]);

        let mut encryption_key = [0u8; 16];
        rng.fill_bytes(&mut encryption_key[..]);

        Self::new(signing_key, encryption_key, rng)
    }
}

impl<Rng> Token<Rng> {
    /// Returns new token with the given signing and encryption keys.
    pub const fn new(signing_key: [u8; 16], encryption_key: [u8; 16], rng: Rng) -> Self {
        Self {
            signing_key,
            encryption_key,
            rng,
        }
    }

    /// Decrypts `ciphertext` using this token. Writes decrypted message into `buf`
    /// and returns the relevant slice backekd by `buf`.
    ///
    /// Returns error if ciphertext is not longer than 48 bytes, HMAC is invalid
    /// or `buf` is not long enough for decrypted message.
    pub fn decrypt<'a>(
        &self,
        ciphertext: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], DecryptError> {
        let hmac_index = ciphertext
            .len()
            .checked_sub(HMAC_LENGTH)
            .ok_or(DecryptError::TooShort)?;

        let iv: [u8; IV_LENGTH] = ciphertext
            .get(0..IV_LENGTH)
            .ok_or(DecryptError::TooShort)?
            .try_into()
            .expect("enough bytes");
        let message = &ciphertext
            .get(IV_LENGTH..hmac_index)
            .ok_or(DecryptError::TooShort)?;
        let tag: [u8; HMAC_LENGTH] = ciphertext
            .get(hmac_index..)
            .ok_or(DecryptError::TooShort)?
            .try_into()
            .map_err(|_| DecryptError::TooShort)?;

        HmacSha256::new_from_slice(&self.signing_key)
            .expect("16 bytes is enough")
            .chain_update(iv)
            .chain_update(message)
            .verify_slice(&tag)
            .map_err(|_| DecryptError::BadMac)?;

        Aes128CbcDec::new(&self.encryption_key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(message, &mut buf[..])
            .map_err(|_| DecryptError::InsufficientBuffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum DecryptError {
    BadMac,
    TooShort,
    InsufficientBuffer,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EncryptError {
    InsufficientBuffer,
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
) -> Result<usize, EncryptError> {
    let len = Aes128CbcEnc::new(&encryption_key.into(), &Iv::<Aes128CbcEnc>::from(iv))
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut ciphertext[..])
        .map_err(|_| EncryptError::InsufficientBuffer)?
        .len();

    let mut digest = HmacSha256::new_from_slice(&signing_key).expect("16 bytes is enough");
    digest.update(&iv);
    digest.update(&ciphertext[..len]);

    let hmac = digest.finalize().into_bytes();
    let hmac_buf = ciphertext
        .get_mut(len..len + HMAC_LENGTH)
        .ok_or(EncryptError::InsufficientBuffer)?;
    hmac_buf.copy_from_slice(&hmac[..]);

    Ok(IV_LENGTH + len + HMAC_LENGTH)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use hex::prelude::*;

    use super::*;

    struct T {
        sig: [u8; 16],
        enc: [u8; 16],
        iv: [u8; 16],
        plain: Vec<u8>,
        cipher: Vec<u8>,
    }

    fn reference_samples() -> impl Iterator<Item = T> {
        include!("../tests/data/token_encryption_samples.txt").iter().map(
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
    fn decrypt_reference_success() {
        reference_samples().for_each(
            |T {
                 sig,
                 enc,
                 plain,
                 cipher,
                 ..
             }| {
                let mut buf = [0u8; 2048];
                let decrypted = Token::new(sig, enc, ()).decrypt(&cipher, &mut buf);
                assert!(decrypted.is_ok());
                assert_eq!(decrypted.unwrap(), plain);
            },
        )
    }

    #[test]
    fn decrypt_reference_invalid_hmac() {
        reference_samples().for_each(
            |T {
                 sig,
                 enc,
                 mut cipher,
                 ..
             }| {
                // Flip a bit in IV.
                cipher[0] ^= 1;

                // Buffer will not be used at all.
                let decrypted = Token::new(sig, enc, ()).decrypt(&cipher, &mut [0u8; 0]);

                assert!(decrypted.is_err());
                assert_eq!(decrypted.unwrap_err(), DecryptError::BadMac);
            },
        )
    }

    #[test]
    fn decrypt_reference_insufficient_buffer() {
        reference_samples().for_each(
            |T {
                 sig, enc, cipher, ..
             }| {
                // Less than 16 bytes for padding.
                let mut buf = [0u8; 15];
                let decrypted = Token::new(sig, enc, ()).decrypt(&cipher, &mut buf);
                assert!(decrypted.is_err());
                assert_eq!(decrypted.unwrap_err(), DecryptError::InsufficientBuffer);
            },
        )
    }

    #[test]
    fn decrypt_reference_too_short() {
        reference_samples().for_each(
            |T {
                 sig, enc, cipher, ..
             }| {
                // Cut message to less than 48 bytes (IV + HMAC). Buffer will not be used at all.
                let decrypted = Token::new(sig, enc, ()).decrypt(&cipher[..47], &mut [0u8; 0]);
                assert!(decrypted.is_err());
                assert_eq!(decrypted.unwrap_err(), DecryptError::TooShort);
            },
        )
    }

    #[test]
    fn encrypt_reference_success() {
        reference_samples().for_each(
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

                assert!(len.is_ok());
                assert_eq!(buf[..len.unwrap()], cipher);
            },
        );
    }

    #[test]
    fn encrypt_reference_insufficient_buffer() {
        reference_samples().for_each(
            |T {
                 sig,
                 enc,
                 iv,
                 plain,
                 ..
             }| {
                // IV + HMAC + 1 pad = 64
                let mut buf = [0u8; 63];
                buf[..IV_LENGTH].copy_from_slice(&iv);

                let len = encrypt(&plain, &mut buf[IV_LENGTH..], iv, enc, sig);

                assert!(len.is_err());
                assert_eq!(len.unwrap_err(), EncryptError::InsufficientBuffer);
            },
        );
    }
}
