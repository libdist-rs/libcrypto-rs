use ring::signature::KeyPair;
use crate::{ED25519PrivateKey, ED25519PublicKey, Hash, NetworkObject, PublicKey, RSAPrivateKey, RSAPublicKey, SECP256K1PrivateKey, SECP256K1PublicKey, Signature};

#[derive(Debug)]
pub enum PrivateKey {
    RSA(RSAPrivateKey),
    ED25519(ED25519PrivateKey),
    SECP256K1(SECP256K1PrivateKey),
}

impl PrivateKey {
    pub fn sign<T>(&self, data: &T) -> Result<Signature<T>, String>
    where T: NetworkObject,
    {
        let hash: Hash<T> = data.into();
        self.sign_cached(&hash)
    }

    pub fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, String>
    where T: NetworkObject,
    {
        match self {
            PrivateKey::RSA(pkey) => {
                pkey.sign_cached(data_hash).map_err(|e| e.to_string())
            }
            PrivateKey::ED25519(pkey) => {
                pkey.sign_cached(data_hash)
            }
            PrivateKey::SECP256K1(pkey) => {
                pkey.sign_cached(data_hash)
            }
        }
    }

    pub fn public(&self) -> Result<PublicKey, String>  {
        match self {
            PrivateKey::RSA(pkey) => {
                let raw_pub_key = pkey.0.public_key().as_ref().to_vec();
                let rsa_pub_key = RSAPublicKey(raw_pub_key);
                Ok(PublicKey::RSA(rsa_pub_key))
            },
            PrivateKey::ED25519(pkey) => {
                let pub_key: ed25519_dalek::PublicKey = pkey.0.public;
                Ok(PublicKey::ED25519(ED25519PublicKey(pub_key)))
            }
            PrivateKey::SECP256K1(pkey) => {
                let pub_key = libsecp256k1::PublicKey::from_secret_key(&pkey.0);
                Ok(PublicKey::SECP256K1(SECP256K1PublicKey(pub_key)))
            }
        }
    }
}