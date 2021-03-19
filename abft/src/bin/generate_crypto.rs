use bincode::serialize;
use consensus_core::crypto::{commoncoin::Coin, encrypt::Encrypter, sign::Signer, KeySet};
use std::io::prelude::*;
use std::{
    error::Error,
    fs::{self, File},
};

const N_PARTIES: usize = THRESHOLD * 3 + 1;
const THRESHOLD: usize = 1;

fn main() -> Result<(), Box<dyn Error>> {
    // generate crypto

    let mut mvba_signers = Signer::generate_signers(N_PARTIES, N_PARTIES - THRESHOLD - 1);
    let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD + 1);

    assert_eq!(mvba_signers.len(), N_PARTIES);
    assert_eq!(coins.len(), N_PARTIES);

    let mut prbc_signers = Signer::generate_signers(N_PARTIES, THRESHOLD);

    assert_eq!(prbc_signers.len(), N_PARTIES);

    let mut encrypters = Encrypter::generate_keys(N_PARTIES, THRESHOLD);

    assert_eq!(encrypters.len(), N_PARTIES);

    // write to file

    fs::create_dir_all("abft/crypto/")?;

    println!("Created dir");

    for i in 0..N_PARTIES {
        let keyset = KeySet::new(
            prbc_signers.remove(0),
            mvba_signers.remove(0),
            coins.remove(0),
            encrypters.remove(0),
        );

        let mut file = File::create(format!("abft/crypto/key_material{}", i))?;
        file.write_all(&serialize(&keyset)?)?;
    }

    Ok(())
}
