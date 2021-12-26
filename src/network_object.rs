/// A network object is an object that knows how to serialize itself and deserialize itself
pub trait NetworkObject {
    fn to_bytes(&self) -> Result<Vec<u8>, String>;
    fn from_bytes(data: &[u8]) -> Result<Self, String> where Self:Sized;
}
