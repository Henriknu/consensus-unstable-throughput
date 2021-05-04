use crate::crypto::hash::hash_sha256;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::{rngs::StdRng, Rng};
use serde::{Deserialize, Serialize};

/// Placeholder transaction for testing purposes. Fixed size of 250 bytes.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Transaction {
    _id: u64,
    _sender: u64,
    _recipient: u64,
    _payload1: [u64; 28],
    _payload2: u16,
}

#[derive(Serialize, Default, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct TransactionSet {
    transactions: Vec<Transaction>,
}

impl TransactionSet {
    pub fn generate_transactions(seed: u32, num_transactions: u64) -> TransactionSet {
        let seed = hash_sha256(&seed.to_ne_bytes());

        let mut rng = StdRng::from_seed(seed);

        let transactions = (0..num_transactions)
            .map(|_| Transaction {
                _id: rng.gen(),
                _sender: rng.gen(),
                _recipient: rng.gen(),
                _payload1: rng.gen(),
                _payload2: rng.gen(),
            })
            .collect();

        TransactionSet { transactions }
    }

    pub fn random_selection(mut self, selection: usize) -> TransactionSet {
        let mut rng = StdRng::from_entropy();
        let num_transactions = self.transactions.len();

        self.transactions.shuffle(&mut rng);
        let transactions = self
            .transactions
            .into_iter()
            .take(num_transactions / selection)
            .collect();

        TransactionSet { transactions }
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }
}

impl std::fmt::Debug for TransactionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = hash_sha256(&self.transactions[0]._id.to_ne_bytes());
        write!(f, "({}..{})", hash[0], hash[31],)
    }
}

#[cfg(test)]
mod test_super {
    use super::*;
    use bincode::serialize;

    const SEED: u32 = 42;
    const NUM_TRANSACTIONS: u64 = 1000;
    const SELECTION: usize = 8;

    #[test]
    fn test_transaction_250_bytes() {
        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);
        let transaction = &t1.transactions[0];

        let bytes = serialize(&transaction).unwrap();

        assert_eq!(bytes.len(), 250)
    }

    #[test]
    fn test_generate() {
        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        let t2 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        assert_eq!(t1.transactions.len() as u64, NUM_TRANSACTIONS);

        assert_eq!(t1, t2);
    }

    #[test]
    fn test_random_selection() {
        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        let t2 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        assert_eq!(t1.transactions.len() as u64, NUM_TRANSACTIONS);

        assert_eq!(t1, t2);

        let t1 = t1.random_selection(SELECTION);
        let t2 = t2.random_selection(SELECTION);

        dbg!(&t1);
        dbg!(&t2);

        assert_eq!(t1.transactions.len(), NUM_TRANSACTIONS as usize / SELECTION);

        assert_ne!(t1, t2);
    }
}
