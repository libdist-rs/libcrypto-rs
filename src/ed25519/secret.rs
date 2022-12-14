use core::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
/// An Ed25519 secret key.
pub struct SecretKey {
    pub(crate) sk: ed25519_dalek::SecretKey,
    pub(crate) pk: ed25519_dalek::PublicKey,
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.sk.as_bytes() == other.sk.as_bytes() && 
        self.pk == other.pk
    }
}

impl Eq for SecretKey {}

impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.sk.as_bytes().partial_cmp(&other.sk.as_bytes()) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        self.pk.as_bytes().partial_cmp(&other.pk.as_bytes())
    }
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let res = self.sk.as_bytes().cmp(other.sk.as_bytes());
        match res {
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater => {
                return res;
            },
            _ => (),
        };
        self.pk.as_bytes().cmp(other.pk.as_bytes())
    }
}

impl std::hash::Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sk.as_bytes().hash(state);
        self.pk.as_bytes().hash(state);
    }
}

impl SecretKey {
    pub const SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
}

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        let mut bytes = self.sk.to_bytes();
        let sk_bytes = bytes.as_mut();
        let sk = ed25519_dalek::SecretKey::from_bytes(&*sk_bytes).unwrap();
        let pk = ed25519_dalek::PublicKey::from(&sk);
        Self { sk: sk, pk: pk }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "SecretKey") }
}

impl SecretKey {
    /// Generate a new Ed25519 secret key.
    pub fn generate() -> anyhow::Result<SecretKey> {
        let mut bytes = [0u8; Self::SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        let sk_bytes = bytes.as_mut();
        let sk = ed25519_dalek::SecretKey::from_bytes(&*sk_bytes)?;
        let pk = ed25519_dalek::PublicKey::from(&sk);
        Ok(Self { sk: sk, pk: pk })
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let expanded: ed25519_dalek::ExpandedSecretKey = (&self.sk).into();
        Ok(expanded.sign(msg, &self.pk).to_bytes().to_vec())
    }
}
