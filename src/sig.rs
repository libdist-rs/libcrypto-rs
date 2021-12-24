use crate::NetworkObject;

/// A signature object is a wrapper around the `Signature` trait in the crate `signature`
/// that is type-aware.
///
/// ADITHYA: This prevents a ton of bugs that arise because we sign X, but verify against Y.
/// A signature is also a `NetworkObject` in this definition
pub trait Signature<D, V, Signer>: signature::Signature + NetworkObject
where
    Signer: signature::Signer<Self>,
    V: signature::Verifier<Self>,
    D: NetworkObject,
{
    /// Verify that this signature is for the correct data
    fn verify(&self, data: &D, verifier: &V) -> Result<(), signature::Error> {
        verifier.verify(&data.to_bytes(), self)
    }

    /// A cached version of `verify`, where we can re-use the serialized message
    fn verify_cached(&self, data_bytes: &[u8], verifier: &V) -> Result<(), signature::Error> {
        verifier.verify(data_bytes, self)
    }

    /// Generates a signature on the message
    fn generate(object: &D, signer: &Signer) -> Self
    where
        Self: Sized,
    {
        signer.sign(&object.to_bytes())
    }

    /// A cached version of `generate` to re-use the serialized data
    fn generate_cached(object_bytes: &[u8], signer: &Signer) -> Self {
        signer.sign(object_bytes)
    }
}
