use thiserror::Error;

use super::{
    elect::ElectError, messages::ProtocolMessage, proposal_promotion::PPError,
    view_change::ViewChangeError,
};

pub type MVBAResult<Output> = Result<Output, MVBAError>;

#[derive(Error, Debug)]
pub enum MVBAError {
    #[error("MVBA State {0} was not initialized")]
    UninitState(String),

    #[error("An invariant was broken: {0}")]
    /// Something went horribly wrong that should not happen (e.g. check that value is not None, but error when unwrapping)
    InvariantBroken(String),
    #[error("Received invalid signature for {0}")]
    InvalidSignature(String),
    #[error("Failed to serialize {0} at {1}")]
    FailedSerialization(String, String),
    #[error("Not ready to handle message")]
    NotReadyForMessage(ProtocolMessage),

    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    PPError(#[from] PPError),
    #[error(transparent)]
    ElectError(#[from] ElectError),
    #[error(transparent)]
    ViewChangeError(#[from] ViewChangeError),
}
