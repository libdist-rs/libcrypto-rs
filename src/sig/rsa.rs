use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair};
use crate::{Signature, hash::Hash};

pub struct RSAPublicKey(pub(crate) Vec<u8>);

impl RSAPublicKey {
    pub(crate) fn verify_cached<T>(&self, data_hash: &Hash<T>, sig: &Signature<T>) -> Result<(), ring::error::Unspecified> {
        let key = ring::signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.0);
        key.verify(&data_hash,sig.as_ref())
    }
}

#[derive(Debug)]
pub struct RSAPrivateKey(pub(crate) RsaKeyPair);

impl RSAPrivateKey {
    pub(crate) fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, ring::error::Unspecified>
    {
        let mut sig_buf = vec![0; self.0.public_modulus_len()];
        let rng = SystemRandom::new();
        self.0.sign(&RSA_PKCS1_SHA256,
                        &rng,
                    &data_hash,
                    &mut sig_buf)
            .map(|_| Signature::from_raw_buf(sig_buf))
    }
}
