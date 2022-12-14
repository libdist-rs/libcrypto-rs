// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use serde::{Deserialize, Serialize};

#[cfg(feature = "ed25519")]
use crate::ed25519;
#[cfg(feature = "rsa")]
use crate::rsa;
#[cfg(feature = "secp256k1")]
use crate::secp256k1;

/// Identity keypair of a node.
///
/// # Example: Generating RSA keys with OpenSSL
///
/// ```text
/// openssl genrsa -out private.pem 2048
/// openssl pkcs8 -in private.pem -inform PEM -topk8 -out private.pk8 -outform DER -nocrypt
/// rm private.pem      # optional
/// ```
///
/// Loading the keys:
///
/// ```text
/// let mut bytes = std::fs::read("private.pk8").unwrap();
/// let keypair = Keypair::rsa_from_pkcs8(&mut bytes);
/// ```
///
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Keypair {
    /// An Ed25519 keypair.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Keypair),

    /// An RSA keypair.
    #[cfg(feature = "rsa")]
    Rsa(rsa::Keypair),

    /// A Secp256k1 keypair.
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::Keypair),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecretKey {
    /// An Ed25519 keypair.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::SecretKey),
    /// An RSA keypair.
    #[cfg(feature = "rsa")]
    Rsa(rsa::SecretKey),
    /// A Secp256k1 keypair.
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::SecretKey),
}

impl SecretKey {
    /// Sign a message using the private key of this keypair, producing
    /// a signature that can be verified using the corresponding public key.
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(ref key) => Ok(key.sign(msg)?),
            #[cfg(feature = "rsa")]
            SecretKey::Rsa(ref key) => key.sign(msg),
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(ref pair) => pair.sign(msg),
        }
    }
}

impl Keypair {
    /// Generate a new Ed25519 keypair.
    #[cfg(feature = "ed25519")]
    pub fn generate_ed25519() -> anyhow::Result<Keypair> {
        let kp = ed25519::Keypair::generate()?;
        Ok(Keypair::Ed25519(kp))
    }

    /// Generate a new Secp256k1 keypair.
    #[cfg(feature = "secp256k1")]
    pub fn generate_secp256k1() -> Keypair { Keypair::Secp256k1(secp256k1::Keypair::generate()) }

    /// Decode an keypair from a DER-encoded secret key in PKCS#8 PrivateKeyInfo
    /// format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    #[cfg(feature = "rsa")]
    pub fn rsa_from_pkcs8(pkcs8_der: &mut [u8]) -> Result<Keypair, DecodingError> {
        rsa::Keypair::from_pkcs8(pkcs8_der).map(Keypair::Rsa)
    }

    pub fn private(&self) -> SecretKey {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(kpair) => SecretKey::Ed25519(kpair.secret()),
            #[cfg(feature = "rsa")]
            Self::Rsa(kpair) => SecretKey::Rsa(kpair.secret()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(kpair) => SecretKey::Secp256k1(kpair.secret().clone()),
        }
    }

    /// Decode a keypair from a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915].
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1_from_der(der: &mut [u8]) -> anyhow::Result<Keypair> {
        let sk = secp256k1::SecretKey::from_der(der)?;
        Ok(Keypair::Secp256k1(secp256k1::Keypair::from(sk)))
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        use Keypair::*;
        match self {
            #[cfg(feature = "ed25519")]
            Ed25519(pair) => PublicKey::Ed25519(pair.public()),
            #[cfg(feature = "rsa")]
            Rsa(pair) => PublicKey::Rsa(pair.public()),
            #[cfg(feature = "secp256k1")]
            Secp256k1(pair) => PublicKey::Secp256k1(pair.public().clone()),
        }
    }
}

/// The public key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    /// A public Ed25519 key.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::PublicKey),
    /// A public RSA key.
    #[cfg(feature = "rsa")]
    Rsa(rsa::PublicKey),
    /// A public Secp256k1 key.
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::PublicKey),
}

impl PublicKey {
    /// Verify a signature for a message using this public key, i.e. check
    /// that the signature has been produced by the corresponding
    /// private key (authenticity), and that the message has not been
    /// tampered with (integrity).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        use PublicKey::*;
        match self {
            #[cfg(feature = "ed25519")]
            Ed25519(pk) => pk.verify(msg, sig),
            #[cfg(feature = "rsa")]
            Rsa(pk) => pk.verify(msg, sig),
            #[cfg(feature = "secp256k1")]
            Secp256k1(pk) => pk.verify(msg, sig),
        }
    }
}
