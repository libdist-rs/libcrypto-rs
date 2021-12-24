use ed25519_dalek::Signer;
use signature::Verifier;
use crate::{Hash, Signature};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use crate::sig::serde::InternalRepr;

#[derive(Debug, PartialEq)]
pub struct ED25519PublicKey(pub(crate) ed25519_dalek::PublicKey);

impl Serialize for ED25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let encoded:InternalRepr = InternalRepr(self.0.to_bytes().to_vec());
        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ED25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let ipk = InternalRepr::deserialize(deserializer)?;
        let pk = ed25519_dalek::PublicKey::from_bytes(&ipk.0)
            .map_err(|e| serde::de::Error::custom(format!("{}", e.to_string())))?;
        Ok(ED25519PublicKey(pk))
    }
}

impl ED25519PublicKey {
    pub(crate) fn verify_cached<T>(&self, data_hash: &Hash<T>, sig: &Signature<T>) -> Result<(), String>
    {
        let new_sig = ed25519_dalek::Signature::from_bytes(sig.as_ref()).map_err(|e| e.to_string())?;
        self.0.verify(data_hash, &new_sig)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
pub struct ED25519PrivateKey(
    pub(crate) ed25519_dalek::Keypair
);

impl Serialize for ED25519PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let internal = InternalRepr(self.0.to_bytes().to_vec());
        internal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ED25519PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let ipk = InternalRepr::deserialize(deserializer)?;
        let pk = ed25519_dalek::Keypair::from_bytes(&ipk.0)
            .map_err(|e| serde::de::Error::custom(format!("Failed with {}", e)))?;
        Ok(Self(pk))
    }
}

impl ED25519PrivateKey {
    pub(crate) fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, String>
    {
        let sig_bytes = self.0.sign(data_hash).to_bytes().to_vec();
        Ok(Signature::from_raw_buf(sig_bytes))
    }
}