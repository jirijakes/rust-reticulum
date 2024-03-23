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

impl<Rng: CryptoRngCore> Fernet<Rng> {
    pub fn new(signing_key: [u8; 16], encryption_key: [u8; 16], rng: Rng) -> Self {
        Self {
            signing_key,
            encryption_key,
            rng,
        }
    }

    pub fn encrypt<'a>(&mut self, message: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let iv = &mut buf[0..IV_LENGTH];
        self.rng.fill_bytes(iv);

        let len = Aes128CbcEnc::new(
            &self.encryption_key.into(),
            Iv::<Aes128CbcEnc>::from_slice(iv),
        )
        .encrypt_padded_b2b_mut::<Pkcs7>(message, &mut buf[IV_LENGTH..])
        .unwrap()
        .len();

        let mut h = hmac::Hmac::<Sha256>::new_from_slice(self.signing_key.as_slice()).unwrap();
        h.update(&buf[..len + IV_LENGTH]);

        buf[len + IV_LENGTH..len + IV_LENGTH + HMAC_LENGTH]
            .copy_from_slice(h.finalize().into_bytes().as_slice());

        &buf[0..len + IV_LENGTH + HMAC_LENGTH]
    }
}

impl<Rng> Fernet<Rng> {
    pub fn decrypt<'a>(&self, ciphertext: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
        let hmac_index = ciphertext.len() - HMAC_LENGTH;

        let iv: [u8; IV_LENGTH] = ciphertext[0..IV_LENGTH].try_into().unwrap();
        let message = &ciphertext[IV_LENGTH..hmac_index];
        let tag: [u8; HMAC_LENGTH] = ciphertext[hmac_index..].try_into().unwrap();

        let x = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .unwrap()
            .chain_update(iv)
            .chain_update(message)
            .verify_slice(&tag);

        println!("{:?}", x);

        Aes128CbcDec::new(&self.encryption_key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(message, &mut buf[..])
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::fernet::Fernet;

    #[test]
    fn go() {
        let mut f = Fernet {
            signing_key: [0x01; 16],
            encryption_key: [0x02; 16],
            rng: OsRng,
        };

        let m = b"rust-reticulum";

        let mut buf = [0; 500];

        let x = f.encrypt(m.as_slice(), &mut buf);

        println!(">> {} {}", x.len(), hex::encode(x));

        let mut buf = [0; 500];

        let y = f.decrypt(x, &mut buf);

        println!("{:?}", String::from_utf8_lossy(y));
    }
}
