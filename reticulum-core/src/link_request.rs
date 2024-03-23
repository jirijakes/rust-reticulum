use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::sign::Dh;

#[derive(Debug)]
pub struct Link {
    id: [u8; 16],
    public_key: PublicKey,
    verifying_key: VerifyingKey,
    signing_key: [u8; 16],
    encryption_key: [u8; 16],
}

#[derive(Debug)]
pub struct LinkRequest {
    pub id: [u8; 16],
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
}

impl LinkRequest {
    pub fn derive_keys<S: Dh>(&self, secrets: &S) {
        let mut derived_key = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(&self.id), secrets.dh(&self.public_key).as_bytes());
        hkdf.expand(&[], &mut derived_key)
            .expect("32 bytes is fine for Sha256");

        let (signing_key, encryption_key) = derived_key.split_at(16);

        let link = Link {
            id: self.id,
            public_key: self.public_key,
            verifying_key: self.verifying_key,
            signing_key: signing_key.try_into().expect("There should be 16 bytes."),
            encryption_key: encryption_key
                .try_into()
                .expect("There should be another 16 bytes."),
        };

        println!("{:02x?}", link);
    }
}

#[cfg(test)]
mod tests {
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
        let raw = hex::decode("020077b65c2bc324a2fe1d6d7520ae53f17300eeb5be3cbdee6c56d23ca05cfce5342feaeb4bf2b3e54ab5defcf0c2706dc027a8410f9a44306cba01f58937610c31d4844cb84e86505c3ed3fb477d036965c8").unwrap();
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
