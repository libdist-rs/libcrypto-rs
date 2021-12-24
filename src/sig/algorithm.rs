use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::{ED25519PrivateKey, PrivateKey, RSAPrivateKey, SECP256K1PrivateKey};

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Algorithm {
    RSA,
    ED25519,
    SECP256K1,
}

impl FromStr for Algorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RSA" => Ok(Algorithm::RSA),
            "ED25519" => Ok(Algorithm::ED25519),
            "SECP256K1" => Ok(Algorithm::SECP256K1),
            _ => Err("no match"),
        }
    }
}

impl Algorithm {
    pub const VALUES: [Algorithm; 3] = [
        Algorithm::RSA,
        Algorithm::ED25519,
        Algorithm::SECP256K1
    ];

    pub const fn public_key_size(&self) -> usize {
        match self {
            Algorithm::RSA => 64,
            Algorithm::ED25519 => 32,
            Algorithm::SECP256K1 => 33,
        }
    }

    pub const fn private_key_size(&self) -> usize {
        match self {
            Algorithm::RSA => 64,
            Algorithm::ED25519 => 64,
            Algorithm::SECP256K1 => 32,
        }
    }

    pub fn generate(&self) -> Result<PrivateKey, String> {
        let key = match self {
            Algorithm::RSA => {
                let key_material = openssl::rsa::Rsa::generate(2048)
                                    .map_err(|e| format!("Failed to generate RSA keys {}", e))?;
                let rsa_key = openssl::pkey::PKey::from_rsa(key_material)
                                    .map_err(|e| format!("Failed to convert RSA material into a key {}", e))?
                                    .private_key_to_der()
                                    .map_err(|e| format!("Failed to convert private key to PEM: {}", e))?;
                PrivateKey::RSA(RSAPrivateKey(
                    ring::signature::RsaKeyPair::from_der(&rsa_key)
                        .map_err(|e| format!("Failed to create an RSA Private key: {}", e))?
                ))
            },
            Algorithm::ED25519 => {
                let mut rng = rand7::rngs::OsRng{};
                let priv_key = ED25519PrivateKey(ed25519_dalek::Keypair::generate(&mut rng));
                PrivateKey::ED25519(priv_key)
            }
            Algorithm::SECP256K1 => {
                let mut rng = rand8::rngs::OsRng{};
                let priv_key = SECP256K1PrivateKey(libsecp256k1::SecretKey::random(&mut rng));
                PrivateKey::SECP256K1(priv_key)
            }
        };
        return Ok(key);
    }
}
