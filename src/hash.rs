use std::{marker::PhantomData, fmt::{Display, self, Debug}, array::TryFromSliceError};
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};

const HASH_SIZE: usize = 32;

#[derive(Default, Clone, Deserialize, Serialize)]
pub struct Hash<T> {
    inner: [u8; HASH_SIZE],
    _x: PhantomData<T>,
}

impl<T> std::hash::Hash for Hash<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<T> PartialEq for Hash<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T> Eq for Hash<T> {}

impl<T> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl<T> Ord for Hash<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<T> Hash<T> {
    pub const EMPTY_HASH: Hash<T> = Hash::<T>{
        inner: [0 as u8; HASH_SIZE], 
        _x: PhantomData
    };
    
    /// Creates a hash from serialized data
    pub fn do_hash(serialized: &[u8]) -> Self {
        let hash = Sha256::digest(serialized);
        return Self{
            inner: hash.into(),
            _x: PhantomData,
        };
    } 

    /// Creates a hash vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
}

impl<T> AsRef<[u8]> for Hash<T> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<T> TryFrom<&[u8]> for Hash<T> {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self{inner: item.try_into()?, _x: PhantomData})
    }
}

impl<T> Hash<T> 
where
    T: Serialize,
{
    /// Returns the hash of the bincode serialized object
    pub fn ser_and_hash(data: &T) -> Self {
        let serialized_bytes = bincode::serialize(data).unwrap();
        return Self::do_hash(&serialized_bytes);
    }
}

impl<T> Display for Hash<T> {
    /// The display implementation intentionally outputs a shorter hash for easier reading
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.inner).get(0..8).unwrap())
    }
}

impl<T> Debug for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.inner).get(0..HASH_SIZE).unwrap())
    }
}