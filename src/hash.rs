use std::array::TryFromSliceError;
use std::fmt::{self, Debug, Display};
use std::io::Write;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A buffered writer that accumulates bytes on the stack before flushing
/// to SHA256 in large chunks. This avoids both heap allocation (unlike
/// bincode::serialize → Vec) and per-field update overhead (unlike
/// unbuffered writes to Sha256::update).
const HASH_BUF_SIZE: usize = 8192;

struct BufHashWriter {
    hasher: Sha256,
    buf: [u8; HASH_BUF_SIZE],
    pos: usize,
}

impl BufHashWriter {
    #[inline]
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            buf: [0u8; HASH_BUF_SIZE],
            pos: 0,
        }
    }

    #[inline]
    fn flush_buf(&mut self) {
        if self.pos > 0 {
            self.hasher.update(&self.buf[..self.pos]);
            self.pos = 0;
        }
    }

    #[inline]
    fn finalize(mut self) -> [u8; 32] {
        self.flush_buf();
        self.hasher.finalize().into()
    }
}

impl Write for BufHashWriter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len();
        if self.pos + len <= HASH_BUF_SIZE {
            // Fast path: fits in buffer
            self.buf[self.pos..self.pos + len].copy_from_slice(buf);
            self.pos += len;
        } else if len >= HASH_BUF_SIZE {
            // Large write: flush buffer, then pass directly to hasher
            self.flush_buf();
            self.hasher.update(buf);
        } else {
            // Partial fit: flush buffer, then buffer the new data
            self.flush_buf();
            self.buf[..len].copy_from_slice(buf);
            self.pos = len;
        }
        Ok(len)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_buf();
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
    /// Uses a stack-buffered writer to avoid heap allocation while
    /// still giving SHA256 large contiguous chunks to process.
    #[inline]
    pub fn ser_and_hash(data: &T) -> Self {
        let mut writer = BufHashWriter::new();
        bincode::serialize_into(&mut writer, data).expect("Serialization error");
        Self {
            inner: writer.finalize(),
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
