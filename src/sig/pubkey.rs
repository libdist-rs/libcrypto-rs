use crate::{ED25519PublicKey, Hash, NetworkObject, RSAPublicKey, SECP256K1PublicKey, Signature};

pub enum PublicKey {
    RSA(RSAPublicKey),
    ED25519(ED25519PublicKey),
    SECP256K1(SECP256K1PublicKey),
}

impl PublicKey
{
    pub fn verify<T>(&self, data: &T, sig: &Signature<T>) -> Result<(), String>
    where T: NetworkObject,
    {
        let hash:Hash<T> = data.into();
        self.verify_cached(&hash, sig)
    }

    pub fn verify_cached<T>(&self, hash: &Hash<T>, sig: &Signature<T>) -> Result<(), String> {
        match self {
            PublicKey::RSA(key) => {
                key.verify_cached(hash, sig)
                    .map_err(|e| e.to_string())
            }
            PublicKey::ED25519(key) => { key.verify_cached(hash, sig) }
            PublicKey::SECP256K1(key) => { key.verify_cached(hash, sig) }
        }
    }
}