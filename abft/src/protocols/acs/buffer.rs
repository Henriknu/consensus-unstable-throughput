use crate::messaging::ProtocolMessage;

#[derive(Debug)]
pub enum ACSBufferCommand {
    PRBC,
    MVBA,

    Store { message: ProtocolMessage },
}
