use core::fmt;

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
/// An Ed25519 secret key.
pub struct SecretKey {
    pub(crate) signing_key: ed25519_dalek::SigningKey,
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key.to_bytes() == other.signing_key.to_bytes()
    }
}

impl Eq for SecretKey {}

impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.signing_key.to_bytes().partial_cmp(&other.signing_key.to_bytes())
    }
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signing_key.to_bytes().cmp(&other.signing_key.to_bytes())
    }
}

impl std::hash::Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.signing_key.to_bytes().hash(state);
    }
}

impl SecretKey {
    pub const SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
}

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        let bytes = self.signing_key.to_bytes();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        Self { signing_key }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SecretKey") }
}

impl SecretKey {
    /// Generate a new Ed25519 secret key.
    pub fn generate() -> anyhow::Result<SecretKey> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        Ok(Self { signing_key })
    }

    /// Sign a message using the private key of this keypair.
    #[inline]
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.signing_key.sign(msg).to_bytes().to_vec())
    }
}
