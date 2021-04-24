use serde::{Deserialize, Serialize};

use super::hash::{Hashable, H256};

#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<H256>,
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self
    where
        T: Hashable,
    {
        let n = data.len();

        assert!(n >= 1);

        let leaf_width = 2usize.pow(f64::log2(n as f64).ceil() as u32);

        let mut nodes = vec![H256::default(); 2 * leaf_width];

        for i in 0..n {
            nodes[leaf_width + i] = data[i].hash();
        }

        for i in (1..leaf_width).rev() {
            nodes[i] = H256::hash_together(nodes[i * 2], nodes[i * 2 + 1]);
        }

        Self { nodes }
    }

    pub fn root(&self) -> &H256 {
        &self.nodes[1]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleBranch {
    nodes: Vec<H256>,
}

pub fn get_branch(merkle: &MerkleTree, index: usize) -> MerkleBranch {
    let mut t = index + (merkle.nodes.len() >> 1);

    let mut nodes = Vec::with_capacity(merkle.nodes.len() >> 1);

    while t > 1 {
        nodes.push(merkle.nodes[t ^ 1]);
        t >>= 1;
    }

    MerkleBranch { nodes }
}

pub fn verify_branch(
    root: &H256,
    data: &H256,
    index: usize,
    leaf_width: usize,
    branch: &MerkleBranch,
) -> bool {
    assert!(index <= leaf_width);
    assert!(
        branch.nodes.len() as u32 == f64::log2(leaf_width as f64).ceil() as u32,
        "Branch len: {}, len from leafs: {}",
        branch.nodes.len() as u32,
        f64::log2(leaf_width as f64).ceil() as u32
    );

    let mut tmp = *data;
    let mut tindex = index;

    for node in &branch.nodes {
        // Want to recompute the hash of the parrent, which is temp + node. Need to know the order which is based of parity of tindex.
        if tindex & 0x01 == 1 {
            tmp = H256::hash_together(*node, tmp);
        } else {
            tmp = H256::hash_together(tmp, *node);
        }
        tindex >>= 1;
    }

    tmp == *root
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::{hash_sha256, Hashable};

    use rand::prelude::*;

    use super::*;

    impl Hashable for u64 {
        fn hash(&self) -> H256 {
            H256 {
                inner: hash_sha256(&self.to_be_bytes()),
            }
        }
    }

    #[test]
    fn it_works() {
        let data: Vec<u64> = vec![13, 12, 13213, 1, 5, 55];
        let index = 3;

        let merkle = MerkleTree::new(&data);

        let branch = get_branch(&merkle, index);

        let input = Hashable::hash(&data[index]);

        assert!(verify_branch(
            merkle.root(),
            &input,
            index,
            data.len(),
            &branch
        ))
    }

    #[test]
    fn many_elements() {
        let mut rng = thread_rng();
        let mut data: [u64; 32] = [0; 32];
        rng.fill(&mut data);
        let index = 3;

        let merkle = MerkleTree::new(&data);

        let branch = get_branch(&merkle, index);

        let input = Hashable::hash(&data[index]);

        assert!(verify_branch(
            merkle.root(),
            &input,
            index,
            data.len(),
            &branch
        ))
    }

    #[test]
    #[should_panic]
    fn not_with_empty() {
        let data: Vec<u64> = vec![];

        let _ = MerkleTree::new(&data);
    }
}
