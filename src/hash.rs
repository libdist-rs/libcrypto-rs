use std::marker::PhantomData;
use std::ops::Deref;
use openssl::sha::sha256;
use serde::{Serialize, Deserialize};
use crate::NetworkObject;

/// A hash object is a wrapper around the a data byte array
/// that is type-aware.
///
/// ADITHYA: This prevents a ton of bugs that arise because we hash X, but verify against Y.
#[derive(Serialize,Deserialize,Debug)]
pub struct Hash<D> {
    _tp: PhantomData<D>,
    data: [u8; 32],
}

impl<D> AsRef<[u8]> for Hash<D> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

impl<D> From<&D> for Hash<D>
where D: NetworkObject
{
    fn from(data: &D) -> Self {
        let bytes = data.to_bytes();
        Self{
            _tp: PhantomData,
            data: sha256(& bytes),
        }
    }
}

impl<D> Deref for Hash<D> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}