use crate::{Hash, Signature};

#[derive(Debug)]
pub struct SECP256K1PublicKey(pub(crate) libsecp256k1::PublicKey);

impl SECP256K1PublicKey {
    pub(crate) fn verify_cached<T>(&self, data_hash: &Hash<T>, sig: &Signature<T>) -> Result<(), String>
    {
        let msg = libsecp256k1::Message::parse_slice(data_hash.as_ref()).map_err(|e| e.to_string())?;
        let internal_sig = libsecp256k1::Signature::parse_standard_slice(sig.as_ref()).map_err(|e| e.to_string())?;
        let res = libsecp256k1::verify(&msg, &internal_sig, &self.0);
        if res {
            Ok(())
        } else {
            Err(format!("Failed to verify secp256k1 signature"))
        }
    }
}

#[derive(Debug)]
pub struct SECP256K1PrivateKey(pub(crate) libsecp256k1::SecretKey);

impl SECP256K1PrivateKey {
    pub(crate) fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, String>
    {
        let msg = libsecp256k1::Message::parse_slice(data_hash.as_ref()).map_err(|e| e.to_string())?;
        let (sig, _)= libsecp256k1::sign(&msg, &self.0);
        return Ok(Signature::from_raw_buf(sig.serialize().to_vec()))
    }
}