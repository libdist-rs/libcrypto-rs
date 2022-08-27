use serde::{Serialize, Deserialize};
use std::str::FromStr;

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
