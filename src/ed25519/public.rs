use core::fmt;
use ed25519_dalek::Verifier;
use serde::{Serialize, Deserialize};

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

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        ed25519_dalek::Signature::try_from(sig)
            .and_then(|s| 
                self.0.verify(msg, &s)
            ).is_ok()
    }
}
