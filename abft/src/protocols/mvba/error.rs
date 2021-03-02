use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

use crate::messaging::ProtocolMessage;

use super::{
    buffer::MVBABufferCommand, elect::ElectError, proposal_promotion::PPError,
    view_change::ViewChangeError,
};

use bincode::Error as BincodeError;

pub type MVBAResult<Output> = Result<Output, MVBAError>;

#[derive(Error, Debug)]
pub enum MVBAError {
    #[error("MVBA State {0} was not initialized")]
    UninitState(String),

    #[error("An invariant was broken: {0}")]
    /// Something went horribly wrong that should not happen (e.g. check that value is not None, but error when unwrapping)
    InvariantBroken(String),
    #[error("Produced/Received invalid signature for {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    FailedSerialization(#[from] BincodeError),
    #[error("Not ready to handle message")]
    NotReadyForMessage(ProtocolMessage),
    #[error("Failed to send MVBABufferCommand from MVBA instance")]
    BufferSender(#[from] SendError<MVBABufferCommand>),

    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    PPError(#[from] PPError),
    #[error(transparent)]
    ElectError(#[from] ElectError),
    #[error(transparent)]
    ViewChangeError(#[from] ViewChangeError),
}
