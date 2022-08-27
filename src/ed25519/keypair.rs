//! Ed25519 keys.

use super::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use core::fmt;

#[derive(Serialize, Deserialize, Clone)]
/// An Ed25519 keypair.
pub struct Keypair {
    sk: SecretKey,
    pk: PublicKey,
}

impl Keypair {
    /// Generate a new Ed25519 keypair.
    pub fn generate() -> anyhow::Result<Keypair> {
        let sk = SecretKey::generate()?;
        Ok(Keypair::from(sk))
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.pk.0)
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> SecretKey {
        self.sk.clone()
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.pk)
            .field("secret", &self.sk)
            .finish()
    }
}

/// Demote an Ed25519 keypair to a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        SecretKey{ sk: kp.sk.sk, pk: kp.pk.0}
    }
}

/// Promote an Ed25519 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Keypair {
        Self { 
            sk: SecretKey { 
                sk: sk.sk, 
                pk: sk.pk 
            }, 
            pk: PublicKey(sk.pk),
        }
    }
}