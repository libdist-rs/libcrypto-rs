use core::fmt;

use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};

/// An Ed25519 public key.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) ed25519_dalek::PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(compressed): ")?;
        for byte in self.0.as_bytes() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.as_bytes().partial_cmp(other.0.as_bytes())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        ed25519_dalek::Signature::try_from(sig).and_then(|s| self.0.verify(msg, &s)).is_ok()
    }
}
