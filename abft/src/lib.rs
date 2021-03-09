pub mod messaging;
pub mod protocols;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, PartialOrd)]
pub struct Value {
    pub(crate) inner: usize,
}

impl Value {
    pub fn new(inner: usize) -> Self {
        Self { inner }
    }
}
