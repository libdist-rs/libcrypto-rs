use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct InternalRepr (pub(crate) Vec<u8>);
