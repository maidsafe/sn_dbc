use std::collections::BTreeSet;

use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier};
use thiserror::Error;
use tiny_keccak::{Hasher, Sha3};

use crate::Hash;
use crate::{VecMap, VecSet};

pub fn ed25519_keypair() -> Keypair {
    Keypair::generate(&mut rand::thread_rng())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Provided threshold is larger than the number of participants")]
    ThresholdCanNotExceedParticipants,
    #[error("Expected at least {expected} shares, got {got}")]
    NotEnoughShares { got: u64, expected: u64 },
    #[error("Received signature from non-paticipant {0:?}")]
    ImposterKey(PublicKey),
    #[error("Failed to verify signature")]
    Ed25519(#[from] ed25519::ed25519::Error),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ThresholdPublicKey {
    participants: VecSet<PublicKey>,
    threshold: u64,
}

impl ThresholdPublicKey {
    pub fn new(threshold: u64, participants: VecSet<PublicKey>) -> Result<Self, Error> {
        if threshold > participants.len() as u64 {
            Err(Error::ThresholdCanNotExceedParticipants)
        } else {
            Ok(Self {
                participants,
                threshold,
            })
        }
    }

    pub fn verify(&self, msg_hash: &Hash, signature: &ThresholdSignature) -> Result<(), Error> {
        if signature.num_shares() < self.threshold {
            return Err(Error::NotEnoughShares {
                got: signature.num_shares(),
                expected: self.threshold,
            });
        }
        for (signer, sig) in signature.shares.iter() {
            self.verify_share(msg_hash, signer, sig)?;
        }
        Ok(())
    }

    pub fn verify_share(
        &self,
        msg_hash: &Hash,
        pub_share: &PublicKey,
        sig_share: &Signature,
    ) -> Result<(), Error> {
        if self.participants.contains(pub_share) {
            Ok(pub_share.verify(msg_hash, sig_share)?)
        } else {
            Err(Error::ImposterKey(*pub_share))
        }
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();

        let participant_bytes: BTreeSet<_> =
            self.participants.iter().map(|p| p.as_bytes()).collect();

        for participant in participant_bytes {
            sha3.update(participant)
        }

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }
}

#[derive(Debug, Clone)]
pub struct ThresholdSignature {
    shares: VecMap<PublicKey, Signature>,
}

impl ThresholdSignature {
    pub fn new() -> Self {
        Self {
            shares: Default::default(),
        }
    }

    pub fn shares(&self) -> impl Iterator<Item = &(PublicKey, Signature)> {
        self.shares.iter()
    }

    pub fn num_shares(&self) -> u64 {
        self.shares.len() as u64
    }

    pub fn add_share(&mut self, signer: PublicKey, sig: Signature) {
        self.shares.insert(signer, sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3_256;

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_threshold(n_parties: u64, threshold: u64, msg: u64) -> TestResult {
        if threshold > n_parties || n_parties > 7 {
            return TestResult::discard();
        }
        let msg_hash = sha3_256(&u64::to_be_bytes(msg));

        let parties: Vec<_> = (0..n_parties)
            .into_iter()
            .map(|_| ed25519_keypair())
            .collect();

        let threshold_key =
            ThresholdPublicKey::new(threshold, parties.iter().map(|kp| kp.public).collect())
                .unwrap();

        let mut threshold_signature = ThresholdSignature::new();
        for (i, id) in parties.iter().enumerate() {
            let sig = id.sign(&msg_hash);
            assert!(threshold_key
                .verify_share(&msg_hash, &id.public, &sig)
                .is_ok());
            threshold_signature.add_share(id.public, sig);
            assert_eq!(threshold_signature.num_shares(), (i + 1) as u64);

            let threshold_verification = threshold_key.verify(&msg_hash, &threshold_signature);
            if (i as u64 + 1) < threshold {
                assert!(matches!(
                    threshold_verification,
                    Err(Error::NotEnoughShares {
                        got,
                        expected
                    }) if got == (i as u64) && expected == threshold
                ))
            } else {
                assert!(matches!(threshold_verification, Ok(())))
            }
        }
        let threshold_verification = threshold_key.verify(&msg_hash, &threshold_signature);
        assert!(matches!(threshold_verification, Ok(())));

        TestResult::passed()
    }

    #[quickcheck]
    fn prop_signatures_only_signatures_from_parties_are_accepted(
        n_parties: u64,
        n_imposters: u64,
        threshold: u64,
        msg: u64,
    ) -> TestResult {
        if n_parties == 0 || threshold > n_parties || n_parties > 7 {
            return TestResult::discard();
        }

        let msg_hash = sha3_256(&u64::to_be_bytes(msg));

        let parties: Vec<_> = (0..n_parties)
            .into_iter()
            .map(|_| ed25519_keypair())
            .collect();

        let imposters: Vec<_> = (0..n_parties)
            .into_iter()
            .map(|_| ed25519_keypair())
            .collect();

        let threshold_key =
            ThresholdPublicKey::new(threshold, parties.iter().map(|kp| kp.public).collect())
                .unwrap();

        // A sig with only imposter shares should be rejected
        let mut imposter_sig = ThresholdSignature::new();
        for id in imposters.iter() {
            let sig = id.sign(&msg_hash);
            imposter_sig.add_share(id.public, sig);
        }
        assert!(threshold_key.verify(&msg_hash, &imposter_sig).is_err());

        let mut valid_sig = ThresholdSignature::new();
        for id in parties.iter() {
            let sig = id.sign(&msg_hash);
            valid_sig.add_share(id.public, sig);
        }
        assert!(threshold_key.verify(&msg_hash, &valid_sig).is_ok());

        // adding an imposter signature invalidates the signature
        if let Some(id) = imposters.iter().next() {
            let sig = id.sign(&msg_hash);
            valid_sig.add_share(id.public, sig);

            assert!(matches!(
                threshold_key.verify(&msg_hash, &valid_sig),
                Err(Error::ImposterKey(key)) if key == id.public
            ));
        }

        TestResult::passed()
    }

    #[quickcheck]
    fn prop_construct_threshold_pubkey(n_parties: u64, threshold: u64) -> TestResult {
        if threshold > n_parties || n_parties > 7 {
            return TestResult::discard();
        }

        let parties: Vec<_> = (0..n_parties)
            .into_iter()
            .map(|_| ed25519_keypair())
            .collect();

        let pubkey_set: VecSet<_> = parties.iter().map(|kp| kp.public).collect();
        let thresh_key_res = ThresholdPublicKey::new(threshold, pubkey_set.clone());

        if threshold > n_parties {
            assert!(matches!(
                thresh_key_res,
                Err(Error::ThresholdCanNotExceedParticipants)
            ));
        } else {
            assert!(matches!(&thresh_key_res, Ok(key)));

            let key = thresh_key_res.unwrap();
            assert_eq!(key.participants, pubkey_set);
            assert_eq!(key.threshold, threshold);
        }

        TestResult::passed()
    }
}
