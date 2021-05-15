use crate::crypto::hash::hash_sha256;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::{rngs::StdRng, Rng};
use serde::{Deserialize, Serialize};

/// Placeholder transaction for testing purposes. Fixed size of 250 bytes.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Transaction {
    _payload1: [u16; 25],
    _payload2: [u16; 25],
    _payload3: [u16; 25],
    _payload4: [u16; 25],
    _payload5: [u16; 25],
}

#[derive(Serialize, Default, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct TransactionSet {
    transactions: Vec<Transaction>,
}

impl TransactionSet {
    pub fn generate_transactions(seed: u32, num_transactions: u32) -> TransactionSet {
        let seed = hash_sha256(&seed.to_ne_bytes());

        let mut rng = StdRng::from_seed(seed);

        let transactions = (0..num_transactions)
            .map(|_| Transaction {
                _payload1: rng.gen(),
                _payload2: rng.gen(),
                _payload3: rng.gen(),
                _payload4: rng.gen(),
                _payload5: rng.gen(),
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
        write!(
            f,
            "({}..{})",
            &self.transactions[0]._payload1[0], &self.transactions[0]._payload1[24],
        )
    }
}

#[cfg(test)]
mod test_super {
    use super::*;

    const SEED: u32 = 42;
    const NUM_TRANSACTIONS: u32 = 2_000_000;
    const SELECTION: usize = 8;

    #[test]
    fn test_transaction_250_bytes() {
        assert_eq!(std::mem::size_of::<Transaction>(), 250);
    }

    #[test]
    fn test_generate() {
        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        let t2 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        assert_eq!(t1.transactions.len() as u32, NUM_TRANSACTIONS);

        assert_eq!(t1, t2);
    }

    #[test]
    fn test_random_selection() {
        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        let t2 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);

        assert_eq!(t1.transactions.len() as u32, NUM_TRANSACTIONS);

        assert_eq!(t1, t2);

        let t1 = t1.random_selection(SELECTION);
        let t2 = t2.random_selection(SELECTION);

        dbg!(&t1);
        dbg!(&t2);

        assert_eq!(t1.transactions.len(), NUM_TRANSACTIONS as usize / SELECTION);

        assert_ne!(t1, t2);
    }

    #[test]
    fn test_compress() {
        use bincode::serialize;
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::prelude::*;

        let t1 = TransactionSet::generate_transactions(SEED, NUM_TRANSACTIONS);
        let serialized = serialize(&t1).unwrap();
        println!("serialized size: {}", serialized.len());

        let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(&serialized).unwrap();
        let compressed_bytes = e.finish().unwrap();
        println!("compressed_bytes size: {}", compressed_bytes.len());
    }
}
