use std::{fmt, hash::Hash};

use asn1_der::typed::{DerDecodable, Sequence};
use libsecp256k1::Message;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigestTrait, Sha256};

/// A Secp256k1 secret key.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(pub(crate) libsecp256k1::SecretKey);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SecretKey") }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.serialize().hash(state);
    }
}

impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.serialize().partial_cmp(&other.0.serialize())
    }
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.serialize().cmp(&other.0.serialize())
    }
}

#[derive(Serialize, Deserialize)]
struct Serialized([u8; 32]);

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialized(self.0.serialize()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = Serialized::deserialize(deserializer)?;
        let inner_sk = libsecp256k1::SecretKey::parse(&data.0).map_err(serde::de::Error::custom)?;
        Ok(Self(inner_sk))
    }
}

impl SecretKey {
    /// Generate a new Secp256k1 secret key.
    pub fn generate() -> SecretKey {
        let mut r = rand::thread_rng();
        let mut b = [0; libsecp256k1::util::SECRET_KEY_SIZE];
        // This is how it is done in `secp256k1::SecretKey::random` which
        // we do not use here because it uses `rand::Rng` from rand-0.4.
        loop {
            r.fill_bytes(&mut b);
            if let Ok(k) = libsecp256k1::SecretKey::parse(&b) {
                return SecretKey(k);
            }
        }
    }

    /// Create a secret key from a byte slice, zeroing the slice on success.
    /// If the bytes do not constitute a valid Secp256k1 secret key, an
    /// error is returned.
    pub fn from_bytes(mut sk: impl AsMut<[u8]>) -> anyhow::Result<SecretKey> {
        let sk_bytes = sk.as_mut();
        let secret = libsecp256k1::SecretKey::parse_slice(&*sk_bytes)?;
        Ok(SecretKey(secret))
    }

    /// Decode a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915], zeroing the input slice on success.
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    pub fn from_der(mut der: impl AsMut<[u8]>) -> anyhow::Result<SecretKey> {
        // TODO: Stricter parsing.
        let der_obj = der.as_mut();
        let obj: Sequence = DerDecodable::decode(der_obj)?;
        let sk_obj = obj.get(1)?;
        let mut sk_bytes: Vec<u8> = asn1_der::typed::DerDecodable::load(sk_obj)?;
        let sk = SecretKey::from_bytes(&mut sk_bytes)?;
        Ok(sk)
    }

    /// Sign a message with this secret key, producing a DER-encoded
    /// ECDSA signature, as defined in [RFC3278].
    ///
    /// [RFC3278]: https://tools.ietf.org/html/rfc3278#section-8.2
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_hash(Sha256::digest(msg).as_ref())
    }

    /// Returns the raw bytes of the secret key.
    pub fn to_bytes(&self) -> [u8; 32] { self.0.serialize() }

    /// Sign a raw message of length 256 bits with this secret key, produces a DER-encoded
    /// ECDSA signature.
    pub fn sign_hash(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let m = Message::parse_slice(msg)?;
        Ok(libsecp256k1::sign(&m, &self.0).0.serialize_der().as_ref().into())
    }
}
