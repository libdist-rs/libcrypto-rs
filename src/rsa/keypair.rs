use std::{sync::Arc, error};
use ring::signature::{RsaKeyPair, KeyPair};
use serde::{Serialize, Deserialize};
use crate::DecodingError;
use serde::de::Error as SerdeError;
use super::{PublicKey, SecretKey};

/// An RSA keypair.
#[derive(Clone)]
pub struct Keypair{
    pub(crate) key: Arc<RsaKeyPair>,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Inner { data: Vec<u8> }

impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer 
    {
        let data = Inner{ data: self.bytes.clone()};
        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> 
    {
        let inner = Inner::deserialize(deserializer)?;
        Ok(
            Self::from_pkcs8(inner.data.as_ref())
                .map_err(|_| SerdeError::custom("RSA Not in DER format"))?
        )
    }
}

impl Keypair {
    pub const SEC_PARAM: u32 = 2048;

    pub fn generate() -> Result<Self, Box<dyn error::Error>> 
    {
        let key = openssl::rsa::Rsa::generate(Self::SEC_PARAM)?;
        let der = key.private_key_to_der()?;
        Self::from_pkcs8(&der)
            .map_err(|e| e.into())
    }
    /// Decode an RSA keypair from a DER-encoded private key in PKCS#8 PrivateKeyInfo
    /// format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    pub fn from_pkcs8(der: &[u8]) -> Result<Keypair, DecodingError> {
        let kp = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| DecodingError::new("RSA PKCS#8 PrivateKeyInfo").source(e))?;
        Ok(Keypair{
            key: Arc::new(kp),
            bytes: der.to_vec(),
        })
    }

    /// Get the public key from the keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.key.public_key().as_ref().to_vec())
    }

    pub fn secret(&self) -> SecretKey {
        SecretKey(self.key.clone())
    }

}
