use std::sync::Arc;
use ring::{signature::{RsaKeyPair, RSA_PKCS1_SHA256}, rand::SystemRandom};
use crate::SigningError;

#[derive(Debug, Clone)]
pub struct SecretKey(pub(crate) Arc<RsaKeyPair>);

impl SecretKey {
    /// Sign a message with this keypair.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut signature = vec![0; self.0.public_modulus_len()];
        let rng = SystemRandom::new();
        match self.0.sign(&RSA_PKCS1_SHA256, &rng, &data, &mut signature) {
            Ok(()) => Ok(signature),
            Err(e) => Err(SigningError::new("RSA").source(e))
        }
    }
}

