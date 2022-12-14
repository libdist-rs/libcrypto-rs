use std::fmt;

use libsecp256k1::{Message, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigestTrait, Sha256};

/// A Secp256k1 public key.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) libsecp256k1::PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(compressed): ")?;
        for byte in &self.encode() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl PublicKey {
    /// Verify the Secp256k1 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.verify_hash(Sha256::digest(msg).as_ref(), sig)
    }

    /// Verify the Secp256k1 DER-encoded signature on a raw 256-bit message using the public key.
    pub fn verify_hash(&self, msg: &[u8], sig: &[u8]) -> bool {
        Message::parse_slice(msg)
            .and_then(|m| Signature::parse_der(sig).map(|s| libsecp256k1::verify(&m, &s, &self.0)))
            .unwrap_or(false)
    }

    /// Encode the public key in compressed form, i.e. with one coordinate
    /// represented by a single bit.
    pub fn encode(&self) -> [u8; 33] { self.0.serialize_compressed() }

    /// Encode the public key in uncompressed form.
    pub fn encode_uncompressed(&self) -> [u8; 65] { self.0.serialize() }

    /// Decode a public key from a byte slice in the the format produced
    /// by `encode`.
    pub fn decode(k: &[u8]) -> anyhow::Result<PublicKey> {
        let pk = libsecp256k1::PublicKey::parse_slice(
            k,
            Some(libsecp256k1::PublicKeyFormat::Compressed),
        )?;
        Ok(PublicKey(pk))
    }
}
