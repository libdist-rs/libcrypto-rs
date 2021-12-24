use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::{Hash, Signature};
use crate::sig::serde::InternalRepr;

#[derive(Debug, PartialEq)]
pub struct SECP256K1PublicKey(pub(crate) libsecp256k1::PublicKey);

impl Serialize for SECP256K1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let internal = InternalRepr(self.0.serialize_compressed().to_vec());
        internal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SECP256K1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let ipk = InternalRepr::deserialize(deserializer)?;
        let mut bytes: [u8; 33] = [0; 33];
        if ipk.0.len() != 33 {
            return Err(serde::de::Error::custom("Invalid internal pk len"));
        }
        for i in 0..33 {
            bytes[i] = ipk.0[i];
        }
        let pk = libsecp256k1::PublicKey::parse_compressed(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("{}", e.to_string())))?;
        Ok(SECP256K1PublicKey(pk))
    }
}

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

impl Serialize for SECP256K1PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let internal = InternalRepr(self.0.serialize().to_vec());
        internal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SECP256K1PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let ipk = InternalRepr::deserialize(deserializer)?;
        let pk = libsecp256k1::SecretKey::parse_slice(&ipk.0)
            .map_err(|e| serde::de::Error::custom(format!("Failed with {}", e)))?;
        Ok(Self(pk))
    }
}


impl SECP256K1PrivateKey {
    pub(crate) fn sign_cached<T>(&self, data_hash: &Hash<T>) -> Result<Signature<T>, String>
    {
        let msg = libsecp256k1::Message::parse_slice(data_hash.as_ref()).map_err(|e| e.to_string())?;
        let (sig, _)= libsecp256k1::sign(&msg, &self.0);
        return Ok(Signature::from_raw_buf(sig.serialize().to_vec()))
    }
}