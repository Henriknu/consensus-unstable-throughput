use consensus_core::crypto::sign2::{aggregate, sign};

pub struct PBSender {
    id: usize,
    n_parties: usize,
    shares: Vec<SigShare>,
}

impl PBSender {
    pub fn invoke(
        id: usize,
        value: PBvalue,
        proof: PBproof,
        n_parties: usize,
        send_handle: &dyn Fn(usize, &PBvalue, &PBproof),
    ) -> PBSender {
        let shares = Vec::<SigShare>::with_capacity(n_parties);

        //send <ID, SEND, value, proof> to all parties
        for i in 0..n_parties {
            send_handle(i, &value, &proof);
        }

        PBSender {
            id,
            n_parties,
            shares,
        }

        // wait for n - f shares

        // return aggregate(shares)
    }

    pub fn on_share_ack(&mut self, share: SigShare) -> bool {
        // if share is valid

        self.shares.push(share);

        self.shares.len() == (self.n_parties * 2 / 3) + 1
    }

    pub fn deliver(&mut self) -> PBsig {
        aggregate(msg, signing_commitments, signing_responses, signer_pubkeys);

        PBsig
    }
}

#[derive(Debug, Clone)]
pub struct PBReceiver {
    id: usize,
    should_stop: bool,
    key: Option<PBkey>,
}

impl PBReceiver {
    fn batch_init(id: usize, n_parties: usize) -> Vec<PBReceiver> {
        vec![
            PBReceiver {
                id,
                should_stop: false,
                key: None
            };
            n_parties
        ]
    }

    fn on_value_send(
        &mut self,
        value: &PBvalue,
        proof: &PBproof,
        send_handle: &dyn Fn(usize, &SigShare),
    ) {
        if !self.should_stop || self.evaluate_pb_val(value, proof) {
            self.abandon();
            let share = sign((id, value));
            self.key.replace(value);
        }
    }

    fn evaluate_pb_val(&self, value: &PBvalue, proof: &PBproof) -> bool {
        // parse ID as <_ID_, step>

        // parse proof as <key, _proof_>

        // if step == 1 && check_key(value, key){ return true;}

        // if step > 1 && sig_validate(<<_ID_, step - 1>, v>, _proof_) {return true;}

        // return false
        todo!()
    }

    fn check_key(value: &PBvalue, key: &PBkey) -> bool {
        // if !eval_mvba_val(value) {return false;}

        //parse key as <view, p>

        //if view != 1 && !sig_validate(<<<id, Leader[view], view>, 1>, v> p){return false;}

        //if view >= LOCK {return true;}

        //return false;
        todo!()
    }
    fn abandon(&mut self) {
        self.should_stop = true;
    }
}

struct SigShare;

struct PBsig;

pub struct PBvalue;

pub struct PBproof;

struct PBkey {
    value: PBvalue,
    proof: PBproof,
}
