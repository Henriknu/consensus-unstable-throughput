pub use frost::keygen::keygen_with_dealer;
pub use frost::sign::*;
use rand::rngs::ThreadRng;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use frost::keygen::KeyPair;

    use super::*;

    #[test]
    fn test_it_works() {
        let num_signers = 5;
        let threshold = 3;
        let mut rng: ThreadRng = rand::thread_rng();

        let (_, keypairs) = keygen_with_dealer(num_signers, threshold, &mut rng).unwrap();

        let msg = "testing sign";
        let (signing_package, signing_nonces) = gen_signing_helper(threshold, &keypairs, &mut rng);

        let mut all_responses: Vec<SigningResponse> = Vec::with_capacity(threshold as usize);

        for counter in 0..threshold {
            let mut my_signing_nonces = signing_nonces[&counter].clone();
            assert!(my_signing_nonces.len() == 1);
            let res = sign(
                &keypairs[counter as usize],
                &signing_package,
                &mut my_signing_nonces,
                msg,
            )
            .unwrap();

            all_responses.push(res);
        }

        let signer_pubkeys = get_signer_pubkeys(&keypairs);
        let group_sig = aggregate(msg, &signing_package, &all_responses, &signer_pubkeys).unwrap();
        let group_pubkey = keypairs[1].group_public;
        assert!(validate(msg, &group_sig, group_pubkey).is_ok());
    }

    fn gen_signing_helper(
        num_signers: u32,
        keypairs: &Vec<KeyPair>,
        rng: &mut ThreadRng,
    ) -> (Vec<SigningCommitment>, HashMap<u32, Vec<NoncePair>>) {
        let mut nonces: HashMap<u32, Vec<NoncePair>> = HashMap::with_capacity(num_signers as usize);
        let mut signing_commitments: Vec<SigningCommitment> =
            Vec::with_capacity(num_signers as usize);
        let number_nonces_to_generate = 1;

        for counter in 0..num_signers {
            let signing_keypair = &keypairs[counter as usize];
            let (participant_commitments, participant_nonces) =
                preprocess(number_nonces_to_generate, signing_keypair.index, rng).unwrap();

            signing_commitments.push(participant_commitments[0]);
            nonces.insert(counter, participant_nonces);
        }
        assert!(nonces.len() == (num_signers as usize));
        (signing_commitments, nonces)
    }

    fn get_signer_pubkeys(keypairs: &Vec<KeyPair>) -> HashMap<u32, RistrettoPoint> {
        let mut signer_pubkeys: HashMap<u32, RistrettoPoint> =
            HashMap::with_capacity(keypairs.len());

        for keypair in keypairs {
            signer_pubkeys.insert(keypair.index, keypair.public);
        }

        signer_pubkeys
    }
}
