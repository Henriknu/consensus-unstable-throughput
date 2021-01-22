use tiny_keccak::{Hasher, Sha3};

pub fn hash_sha256(bytes: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];
    sha3.update(&bytes);
    sha3.finalize(&mut output);
    output
}

pub fn verify_sha256(bytes: &[u8], hash: [u8; 32]) -> bool {
    let computed = hash_sha256(bytes);

    computed == hash
}
