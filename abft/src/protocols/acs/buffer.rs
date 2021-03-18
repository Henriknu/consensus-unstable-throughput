use std::collections::HashMap;

use crate::{
    proto::ProtocolMessage,
    protocols::{
        mvba::buffer::{MVBABuffer, MVBABufferCommand},
        prbc::buffer::{PRBCBuffer, PRBCBufferCommand},
    },
};

pub struct ACSBuffer {
    prbcs: HashMap<u32, PRBCBuffer>,
    mvba: MVBABuffer,
}

impl ACSBuffer {
    pub fn new() -> Self {
        Self {
            prbcs: Default::default(),
            mvba: MVBABuffer::new(),
        }
    }

    pub fn execute(&mut self, command: ACSBufferCommand) -> Vec<ProtocolMessage> {
        match command {
            ACSBufferCommand::PRBC { send_id, inner } => {
                self.prbcs.entry(send_id).or_default().execute(inner)
            }
            ACSBufferCommand::MVBA { inner } => self.mvba.execute(inner),
        }
    }
}

#[derive(Debug)]
pub enum ACSBufferCommand {
    PRBC {
        send_id: u32,
        inner: PRBCBufferCommand,
    },
    MVBA {
        inner: MVBABufferCommand,
    },
}
