/// A network object is an object that knows how to serialize itself and deserialize itself
pub trait NetworkObject {
    type Object;

    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> <Self as NetworkObject>::Object;
}
