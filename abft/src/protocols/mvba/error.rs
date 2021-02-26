use thiserror::Error;

pub type MVBAResult<Output> = Result<Output, MVBAError>;

#[derive(Error, Debug)]
pub enum MVBAError {
    #[error("MVBA State {0} was not initialized")]
    UninitState(String),

    #[error("An invariant was broken: {0}")]
    /// Something went horribly wrong that should not happen (e.g. check that value is not None, but error when unwrapping)
    InvariantBroken(String),
    #[error("Failed to serialize {0} at {1}")]
    FailedSerialization(String, String),
}
