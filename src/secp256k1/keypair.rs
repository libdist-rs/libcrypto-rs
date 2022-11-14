use std::fmt;

use super::{SecretKey, PublicKey};

/// A Secp256k1 keypair.
#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey
}

impl Keypair {
    // Generate Keys
    // use crypto::secp256k1::Keypair::generate().{public(), secret()} to
    // generate keys
    // Codec
    // use self.encode() to serialize
    // use crypto::secp256k1::PublicKey::decode to deserialize
    pub const PK_SIZE: usize = 33;
    // Codec
    // use self.to_bytes() to serialize
    // use crypto::secp256k1::SecretKey::from_bytes to deserialize
    pub const PVT_SIZE: usize = 32;
}

impl Keypair {
    /// Generate a new sec256k1 `Keypair`.
    pub fn generate() -> Keypair {
        Keypair::from(SecretKey::generate())
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Serialize the keypair
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }

    /// Deserialize the keypair
    pub fn from_bytes(data: &mut [u8]) -> anyhow::Result<Self> {
        let sk = SecretKey::from_bytes(data)?;
        let kpair = Keypair::from(sk);
        Ok(kpair)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair").field("public", &self.public).finish()
    }
}

/// Promote a Secp256k1 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = PublicKey(libsecp256k1::PublicKey::from_secret_key(&secret.0));
        Keypair { secret, public }
    }
}

/// Demote a Secp256k1 keypair into a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        kp.secret
    }
}

