pub mod messaging;
pub mod protocols;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait ABFTValue:
    Default + std::fmt::Debug + Clone + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

impl<V> ABFTValue for V where
    V: Default + std::fmt::Debug + Clone + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, PartialOrd)]
pub struct Value {
    pub(crate) inner: usize,
}

impl Value {
    pub fn new(inner: usize) -> Self {
        Self { inner }
    }
}
