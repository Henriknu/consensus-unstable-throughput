use bincode::serialize;
use consensus_core::crypto::{commoncoin::Coin, encrypt::Encrypter, sign::Signer, KeySet};
use std::io::prelude::*;
use std::{
    error::Error,
    fs::{self, File},
};

fn main() -> Result<(), Box<dyn Error>> {
    // Get threshold

    let args = std::env::args();

    assert_eq!(args.len(), 2);

    let threshold: usize = args.skip(1).next().unwrap().parse()?;

    let n_parties = threshold * 3 + 1;

    // generate crypto

    let mut mvba_signers = Signer::generate_signers(n_parties, n_parties - threshold - 1);
    let mut coins = Coin::generate_coins(n_parties, threshold + 1);

    assert_eq!(mvba_signers.len(), n_parties);
    assert_eq!(coins.len(), n_parties);

    let mut prbc_signers = Signer::generate_signers(n_parties, threshold);

    assert_eq!(prbc_signers.len(), n_parties);

    let mut encrypters = Encrypter::generate_keys(n_parties, threshold);

    assert_eq!(encrypters.len(), n_parties);

    // delete current crypto material, if exists

    fs::remove_dir_all("abft/crypto/")?;

    // write to file

    fs::create_dir_all("abft/crypto/")?;

    for i in 0..n_parties {
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
