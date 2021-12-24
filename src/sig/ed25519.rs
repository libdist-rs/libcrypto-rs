use ed25519_dalek::Signer;
use signature::Verifier;
use crate::{Hash, Signature};

pub struct ED25519PublicKey(pub(crate) ed25519_dalek::PublicKey);

impl ED25519PublicKey {
    pub(crate) fn verify_cached<T>(&self, data_hash: &Hash<T>, sig: &Signature<T>) -> Result<(), String>
    {
        let new_sig = ed25519_dalek::Signature::from_bytes(sig.as_ref()).map_err(|e| e.to_string())?;
        self.0.verify(data_hash, &new_sig)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
pub struct ED25519PrivateKey(pub(crate) ed25519_dalek::Keypair);

impl ED25519PrivateKey {
    pub(crate) fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, String>
    {
        let sig_bytes = self.0.sign(data_hash).to_bytes().to_vec();
        Ok(Signature::from_raw_buf(sig_bytes))
    }
}