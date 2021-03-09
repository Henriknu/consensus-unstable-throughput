use std::collections::HashMap;

use crate::{
    messaging::ProtocolMessage,
    protocols::{
        mvba::buffer::{MVBABuffer, MVBABufferCommand},
        prbc::buffer::{PRBCBuffer, PRBCBufferCommand},
    },
};

pub struct ACSBuffer {
    prbcs: HashMap<usize, PRBCBuffer>,
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
        send_id: usize,
        inner: PRBCBufferCommand,
    },
    MVBA {
        inner: MVBABufferCommand,
    },
}
