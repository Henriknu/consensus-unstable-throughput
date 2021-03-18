use async_trait::async_trait;
use log::error;
use std::collections::HashMap;
use tokio::sync::mpsc::Sender;

use crate::{
    buffer::{ABFTBufferCommand, ABFTReceiver},
    messaging::{ProtocolMessageSender, ToProtocolMessage},
    proto::ProtocolMessage,
    protocols::{
        acs::buffer::ACSBufferCommand,
        mvba::buffer::{MVBABufferCommand, MVBAReceiver},
        prbc::{
            buffer::{PRBCBufferCommand, PRBCReceiver},
            PRBCResult,
        },
    },
};

#[derive(Clone)]
pub struct ChannelSender {
    pub senders: HashMap<u32, Sender<ProtocolMessage>>,
}

#[async_trait]
impl ProtocolMessageSender for ChannelSender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: u32,
        send_id: u32,
        recv_id: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    ) {
        if !self.senders.contains_key(&recv_id) {
            return;
        }

        let sender = &self.senders[&recv_id];
        if let Err(e) = sender
            .send(message.to_protocol_message(id, send_id, recv_id, view, prbc_index))
            .await
        {
            error!("Got error when sending message: {}", e);
        }
    }

    async fn broadcast<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: u32,
        send_id: u32,
        n_parties: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    ) {
        let message = message.to_protocol_message(id, send_id, 0, view, prbc_index);

        for i in (0..n_parties) {
            if !self.senders.contains_key(&i) {
                continue;
            }
            let mut inner = message.clone();
            inner.recv_id = i;
            let sender = &self.senders[&i];
            if let Err(e) = sender.send(inner).await {
                error!("Got error when sending message: {}", e);
            }
        }
    }
}

pub struct PRBCBufferManager {
    pub sender: Sender<PRBCBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for PRBCBufferManager {
    async fn drain_rbc(&self, _send_id: u32) -> PRBCResult<()> {
        self.sender.send(PRBCBufferCommand::RBC).await?;
        Ok(())
    }

    async fn drain_prbc_done(&self, _send_id: u32) -> PRBCResult<()> {
        self.sender.send(PRBCBufferCommand::PRBC).await?;
        Ok(())
    }
}

pub struct MVBABufferManager {
    pub sender: Sender<MVBABufferCommand>,
}

#[async_trait]
impl MVBAReceiver for MVBABufferManager {
    async fn drain_pp_receive(
        &self,
        view: u32,
        send_id: u32,
    ) -> crate::protocols::mvba::proposal_promotion::PPResult<()> {
        self.sender
            .send(MVBABufferCommand::PPReceive { view, send_id })
            .await?;

        Ok(())
    }

    async fn drain_elect(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        self.sender
            .send(MVBABufferCommand::ElectCoinShare { view })
            .await?;

        Ok(())
    }

    async fn drain_view_change(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        self.sender
            .send(MVBABufferCommand::ViewChange { view })
            .await?;

        Ok(())
    }
}

pub struct ACSBufferManager {
    pub sender: Sender<ACSBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for ACSBufferManager {
    async fn drain_rbc(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::PRBC {
                send_id,
                inner: PRBCBufferCommand::RBC,
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }

    async fn drain_prbc_done(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::PRBC {
                send_id,
                inner: PRBCBufferCommand::PRBC,
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }
}

#[async_trait]
impl MVBAReceiver for ACSBufferManager {
    async fn drain_pp_receive(
        &self,
        view: u32,
        send_id: u32,
    ) -> crate::protocols::mvba::proposal_promotion::PPResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::PPReceive { view, send_id },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_elect(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::ElectCoinShare { view },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_view_change(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::ViewChange { view },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }
}

pub struct ABFTBufferManager {
    pub sender: Sender<ABFTBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for ABFTBufferManager {
    async fn drain_rbc(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::PRBC {
                    send_id,
                    inner: PRBCBufferCommand::RBC,
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }

    async fn drain_prbc_done(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::PRBC {
                    send_id,
                    inner: PRBCBufferCommand::PRBC,
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }
}

#[async_trait]
impl MVBAReceiver for ABFTBufferManager {
    async fn drain_pp_receive(
        &self,
        view: u32,
        send_id: u32,
    ) -> crate::protocols::mvba::proposal_promotion::PPResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::PPReceive { view, send_id },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_elect(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::ElectCoinShare { view },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_view_change(&self, view: u32) -> crate::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::ViewChange { view },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }
}

#[async_trait]
impl ABFTReceiver for ABFTBufferManager {
    async fn drain_decryption_shares(&self) -> crate::ABFTResult<()> {
        self.sender
            .send(ABFTBufferCommand::ABFTDecryptionShare)
            .await?;

        Ok(())
    }
}
