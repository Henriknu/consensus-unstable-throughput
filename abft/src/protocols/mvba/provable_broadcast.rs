use consensus_core::crypto::sign::{Signature, SignatureShare, Signer};

use bincode::serialize;
use serde::{Deserialize, Serialize};

pub struct PBSender<'s> {
    id: PBID,
    n_parties: usize,
    signer: &'s Signer,
    message: PBMessage,
    shares: Vec<PBSigShare>,
}

impl<'s> PBSender<'_> {
    pub fn invoke(
        id: PBID,
        n_parties: usize,
        signer: &'s Signer,
        value: PBvalue,
        proof: PBproof,
        send_handle: &dyn Fn(usize, &PBMessage),
    ) -> PBSender<'s> {
        let shares = Vec::<PBSigShare>::with_capacity(n_parties);

        //send <ID, SEND, value, proof> to all parties

        let message = PBMessage { value, proof, id };
        for i in 0..n_parties {
            send_handle(i, &message);
        }

        PBSender {
            id,
            n_parties,
            signer,
            message,
            shares,
        }

        // wait for n - f shares

        // return aggregate(shares)
    }

    pub fn on_share_ack(&mut self, index: usize, share: PBSigShare) -> bool {
        if self.signer.verify_share(
            index,
            &share.inner,
            &serialize(&self.message).expect("Could not serialize PB message for ack"),
        ) {
            self.shares.push(share);
        }

        self.shares.len() == (self.n_parties * 2 / 3) + 1
    }

    pub fn deliver(&mut self) -> PBSig {
        let shares = self
            .shares
            .iter()
            .enumerate()
            .map(|(index, share)| (index, share.inner.clone()))
            .collect();

        let signature = self.signer.combine_signatures(&shares).unwrap();

        PBSig { inner: signature }
    }
}

#[derive(Debug, Clone)]
pub struct PBReceiver<'s> {
    id: PBID,
    signer: &'s Signer,
    should_stop: bool,
    message: Option<PBMessage>,
}

impl<'s> PBReceiver<'s> {
    fn batch_init(id: PBID, n_parties: usize, signer: &Signer) -> Vec<PBReceiver> {
        vec![
            PBReceiver {
                id,
                signer,
                should_stop: false,
                message: None
            };
            n_parties
        ]
    }

    fn on_value_send(&mut self, message: PBMessage, send_handle: &dyn Fn(PBID, PBSigShare)) {
        if !self.should_stop && self.evaluate_pb_val(&message) {
            self.abandon();
            let response = PBResponse {
                id: message.id,
                value: message.value,
            };

            let inner = self.signer.sign(
                &serialize(&response).expect("Could not serialize message for on_value_send"),
            );
            send_handle(self.id, PBSigShare { inner });
            self.message.replace(message);
        }
    }

    fn evaluate_pb_val(&self, message: &PBMessage) -> bool {
        let PBID { id, step } = self.id;
        let PBproof { key, proof_prev } = &message.proof;

        // If first step, verify that the key provided is valid
        if step == 1 && self.check_key(&message.value, key) {
            return true;
        }

        let response_prev = PBResponse {
            id: PBID { id, step: step - 1 },
            value: message.value,
        };

        // If later step, verify that the proof provided is valid for the previous step.
        if step > 1
            && self.signer.verify_signature(
                &proof_prev.inner,
                &serialize(&response_prev)
                    .expect("Could not serialize response_prev for evaluate_pb_val"),
            )
        {
            return true;
        }

        false
    }

    fn check_key(&self, value: &PBvalue, key: &PBkey) -> bool {
        //TODO: FIX dummy id for MVBA protocol variables
        let MVBA_LOCK = 0;
        let MVBA_ID = 0;

        // Check that value is valid high-level application
        if !eval_mvba_val(value) {
            return false;
        }

        let PBkey {
            view,
            view_key_proof,
        } = key;

        let view_key = PBResponse {
            id: PBID {
                id: MVBA_ID,
                step: 1,
            },
            value: *value,
        };

        // Verify the validity of the key provided
        if *view != 1
            && !self.signer.verify_signature(
                &view_key_proof.inner,
                &serialize(&view_key).expect("Could not serialize view_key for check_key"),
            )
        {
            return false;
        }

        // Verify that the key was not obtained in an earlier view than what is currently locked
        if view < &MVBA_LOCK {
            return false;
        }

        true
    }
    fn abandon(&mut self) {
        self.should_stop = true;
    }
}

fn eval_mvba_val(value: &PBvalue) -> bool {
    todo!()
}

struct PBSigShare {
    inner: SignatureShare,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PBID {
    id: usize,
    step: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBMessage {
    id: PBID,
    value: PBvalue,
    proof: PBproof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBResponse {
    id: PBID,
    value: PBvalue,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PBSig {
    inner: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PBvalue {
    inner: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBproof {
    key: PBkey,
    proof_prev: PBSig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PBkey {
    view: usize,
    view_key_proof: PBSig,
}
