use std::marker::PhantomData;
use serde::{Deserialize, Serialize};

/// A signature object is a wrapper around the `Signature` trait in the crate `signature`
/// that is type-aware.
///
/// ADITHYA: This prevents a ton of bugs that arise because we sign X, but verify against Y.
/// A signature is also a `NetworkObject` in this definition
#[derive(Serialize, Deserialize, Debug)]
pub struct Signature<D> {
    _tp: PhantomData<D>,
    data: Vec<u8>,
}

impl<D> Signature<D> {
    pub fn from_raw_buf(buf: Vec<u8>) -> Self {
        Self {
            data: buf,
            _tp: PhantomData,
        }
    }
}

impl<D> AsRef<[u8]> for Signature<D> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}
