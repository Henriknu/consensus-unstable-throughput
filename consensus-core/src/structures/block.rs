use super::transaction::Transaction;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Hash)]
pub struct BlockHeader {
    block_id: u64,
    parent_id: u64,
    signer_id: u64,
    sequence_num: u64,
}

impl BlockHeader {
    pub fn new(block_id: u64, parent_id: u64, signer_id: u64, sequence_num: u64) -> Self {
        Self {
            block_id,
            parent_id,
            signer_id,
            sequence_num,
        }
    }
}

pub struct Block {
    header: BlockHeader,
    header_signature: [u8; 32],
    transactions: Vec<Transaction>,
}

impl Block {
    pub fn validate_header(&self) -> bool {
        crypto::hash::verify_sha256(
            &bincode::serialize(&self.header).unwrap(),
            self.header_signature,
        )
    }
}

#[derive(Default)]
pub struct BlockBuilder {
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    pub fn new() -> Self {
        BlockBuilder::default()
    }

    pub fn with_transactions(&mut self, transactions: Vec<Transaction>) -> &mut Self {
        self.transactions = transactions;
        self
    }

    pub fn build_block(self) -> Block {
        let header = BlockHeader::default();

        let header_signature = crypto::hash::hash_sha256(&bincode::serialize(&header).unwrap());

        Block {
            header,
            header_signature,
            transactions: self.transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BlockBuilder;

    #[test]
    fn test_build_default() {
        let block = BlockBuilder::new().build_block();

        assert!(block.validate_header());
        assert_eq!(block.transactions.len(), 0);
    }
}
