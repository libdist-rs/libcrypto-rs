pub mod hash;

mod crypto;
pub use crypto::*;

mod gen;
pub use gen::*;

mod error;
pub use error::*;

// Supports the following cryptographic schemes
// Might add more in the future
#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

// Not implemented
#[cfg(feature = "rsa")]
pub mod rsa;