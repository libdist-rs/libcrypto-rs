use std::array::TryFromSliceError;
use std::fmt::{self, Debug, Display};
use std::io::Write;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A writer that feeds bytes directly into a SHA256 hasher,
/// avoiding intermediate allocations when used with bincode::serialize_into.
struct HashWriter(Sha256);

impl Write for HashWriter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const HASH_SIZE: usize = 32;

#[derive(Default, Deserialize, Serialize)]
pub struct Hash<T> {
    inner: [u8; HASH_SIZE],
    _x: PhantomData<T>,
}

/// Hash<T> is cloneable even if T is not cloneable
impl<T> Clone for Hash<T> {
    fn clone(&self) -> Self { Self { inner: self.inner, _x: PhantomData } }
}

impl<T> std::hash::Hash for Hash<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) { self.inner.hash(state); }
}

impl<T> PartialEq for Hash<T> {
    fn eq(&self, other: &Self) -> bool { self.inner == other.inner }
}

impl<T> Eq for Hash<T> {}

impl<T> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl<T> Ord for Hash<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.inner.cmp(&other.inner) }
}

impl<T> Hash<T> {
    pub const EMPTY_HASH: Hash<T> = Hash::<T> { 
        inner: [0; HASH_SIZE], 
        _x: PhantomData,
    };

    /// Creates a hash from serialized data
    #[inline]
    pub fn do_hash(serialized: &[u8]) -> Self {
        let hash = Sha256::digest(serialized);
        Self {
            inner: hash.into(),
            _x: PhantomData,
        }
    }

    /// Creates a hash vector
    pub fn to_vec(&self) -> Vec<u8> { self.inner.to_vec() }
}

impl<T> AsRef<[u8]> for Hash<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.inner }
}

impl<T> TryFrom<&[u8]> for Hash<T> {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self { inner: item.try_into()?, _x: PhantomData })
    }
}

impl<T> Hash<T>
where
    T: Serialize,
{
    /// Returns the hash of the bincode serialized object.
    /// Serializes directly into the SHA256 hasher to avoid allocating
    /// an intermediate buffer.
    #[inline]
    pub fn ser_and_hash(data: &T) -> Self {
        let mut writer = HashWriter(Sha256::new());
        bincode::serialize_into(&mut writer, data).expect("Serialization error");
        let hash = writer.0.finalize();
        Self {
            inner: hash.into(),
            _x: PhantomData,
        }
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
