// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use blsttc::PublicKey;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::{cmp::Ordering, collections::BTreeSet};
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Error, Input, Result, RevealedAmount, RevealedInput};
pub(super) const RANGE_PROOF_BITS: usize = 64; // note: Range Proof max-bits is 64. allowed are: 8, 16, 32, 64 (only)
                                               //       This limits our amount field to 64 bits also.
pub(super) const RANGE_PROOF_PARTIES: usize = 1; // The maximum number of parties that can produce an aggregated proof
pub(super) const MERLIN_TRANSCRIPT_LABEL: &[u8] = b"SN_DBC";

use crate::rand::{CryptoRng, RngCore};
use crate::BlindedAmount;

/// Represents a Dbc's value.
pub type Amount = u64;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Output {
    pub public_key: PublicKey,
    pub amount: Amount,
}

impl Output {
    pub fn new<G: Into<PublicKey>>(public_key: G, amount: Amount) -> Self {
        Self {
            public_key: public_key.into(),
            amount,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    /// Generate a revealed amount, with random blinding factor, which will be used for an input in a tx.
    pub fn revealed_amount(&self, rng: impl RngCore + CryptoRng) -> RevealedAmount {
        RevealedAmount::from_amount(self.amount, rng)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
struct RevealedOutputAmount {
    pub public_key: PublicKey,
    pub revealed_amount: RevealedAmount,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct RevealedTransaction {
    pub inputs: Vec<RevealedInput>,
    pub outputs: Vec<Output>,
}

impl RevealedTransaction {
    pub fn sign(
        &self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(DbcTransaction, Vec<RevealedAmount>)> {
        // We need to gather a bunch of things for our message to sign.
        //   All public keys in all inputs
        //   All input blinded amounts
        //   All output public keys.
        //   All output blinded amounts
        //   All output range proofs
        //
        //   notes:
        //     1. output blinded amounts, range_proofs, and public_keys are bundled
        //        together in OutputProofs
        let revealed_input_amounts = self.revealed_input_amounts();
        let input_amounts = self.blinded_input_amounts();

        let revealed_output_amounts =
            self.revealed_output_amounts(&revealed_input_amounts, &mut rng);
        let output_proofs = self.output_range_proofs(&revealed_output_amounts, &mut rng)?;

        // Generate message to sign.
        // note: must match message generated by DbcTransaction::verify()
        let msg = gen_message_for_signing(&self.public_keys(), &input_amounts, &output_proofs);

        // We create a signature for each input
        let signed_inputs: Vec<Input> = self
            .inputs
            .iter()
            .map(|input| input.sign(&msg, &Self::pc_gens()))
            .collect();

        let revealed_output_amounts = revealed_output_amounts
            .iter()
            .map(|r| r.revealed_amount)
            .collect::<Vec<_>>();

        Ok((
            DbcTransaction {
                inputs: signed_inputs,
                outputs: output_proofs,
            },
            revealed_output_amounts,
        ))
    }

    fn bp_gens() -> BulletproofGens {
        BulletproofGens::new(RANGE_PROOF_BITS, RANGE_PROOF_PARTIES)
    }

    fn pc_gens() -> PedersenGens {
        Default::default()
    }

    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.inputs.iter().map(|input| input.public_key()).collect()
    }

    fn revealed_input_amounts(&self) -> Vec<RevealedAmount> {
        self.inputs
            .iter()
            .map(|input| *input.revealed_amount())
            .collect()
    }

    fn blinded_input_amounts(&self) -> Vec<BlindedAmount> {
        self.inputs
            .iter()
            .map(|input| input.blinded_amount(&Self::pc_gens()))
            .collect()
    }

    fn revealed_output_amounts(
        &self,
        revealed_input_amounts: &[RevealedAmount],
        mut rng: impl RngCore + CryptoRng,
    ) -> Vec<RevealedOutputAmount> {
        // Avoid subtraction underflow in next step.
        if self.outputs.is_empty() {
            return vec![];
        }

        let mut revealed_output_amounts: Vec<RevealedOutputAmount> = self
            .outputs
            .iter()
            .map(|out| RevealedOutputAmount {
                public_key: out.public_key,
                revealed_amount: out.revealed_amount(&mut rng),
            })
            .take(self.outputs.len() - 1)
            .collect();

        // todo: replace fold() with sum() when supported in blstrs
        let input_summed_blinding_factors: Scalar = revealed_input_amounts
            .iter()
            .map(RevealedAmount::blinding_factor)
            .fold(Scalar::zero(), |sum, x| sum + x);

        // todo: replace fold() with sum() when supported in blstrs
        let output_summed_blinding_factors: Scalar = revealed_output_amounts
            .iter()
            .map(|r| r.revealed_amount.blinding_factor())
            .fold(Scalar::zero(), |sum, x| sum + x);

        let output_blinding_correction =
            input_summed_blinding_factors - output_summed_blinding_factors;

        if let Some(last_output) = self.outputs.last() {
            revealed_output_amounts.push(RevealedOutputAmount {
                public_key: last_output.public_key,
                revealed_amount: RevealedAmount {
                    value: last_output.amount,
                    blinding_factor: output_blinding_correction,
                },
            });
        } else {
            panic!("Expected at least one output")
        }
        revealed_output_amounts
    }

    fn output_range_proofs(
        &self,
        revealed_output_amounts: &[RevealedOutputAmount],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<OutputProof>> {
        let mut prover_ts = Transcript::new(MERLIN_TRANSCRIPT_LABEL);

        let bp_gens = Self::bp_gens();

        revealed_output_amounts
            .iter()
            .map(|c| {
                let (range_proof, compressed_blinded_amount) = RangeProof::prove_single_with_rng(
                    &bp_gens,
                    &Self::pc_gens(),
                    &mut prover_ts,
                    c.revealed_amount.value,
                    &c.revealed_amount.blinding_factor,
                    RANGE_PROOF_BITS,
                    &mut rng,
                )?;
                let blinded_amount = compressed_blinded_amount
                    .decompress()
                    .ok_or(Error::FailedToDecompressBlindedAmount)?;

                Ok(OutputProof {
                    public_key: c.public_key,
                    range_proof,
                    blinded_amount,
                })
            })
            .collect::<Result<Vec<_>>>()
    }
}

// note: used by both RevealedTransaction::sign and DbcTransaction::verify()
//       which must match.
fn gen_message_for_signing(
    public_keys: &[PublicKey],
    input_amounts: &[BlindedAmount],
    output_proofs: &[OutputProof],
) -> Vec<u8> {
    // Generate message to sign.
    let mut msg: Vec<u8> = Default::default();
    msg.extend("public_keys".as_bytes());
    for pk in public_keys.iter() {
        msg.extend(pk.to_bytes().as_ref());
    }
    msg.extend("input_amounts".as_bytes());
    for r in input_amounts.iter() {
        msg.extend(r.compress().as_bytes());
    }
    msg.extend("output_proofs".as_bytes());
    for o in output_proofs.iter() {
        msg.extend(o.to_bytes());
    }
    msg.extend("end".as_bytes());
    msg
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct OutputProof {
    public_key: PublicKey,
    range_proof: RangeProof,
    blinded_amount: BlindedAmount,
}

impl OutputProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.public_key.to_bytes().as_ref());
        v.extend(&self.range_proof.to_bytes());
        v.extend(self.blinded_amount.compress().as_bytes());
        v
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    pub fn blinded_amount(&self) -> BlindedAmount {
        self.blinded_amount
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DbcTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputProof>,
}

impl PartialEq for DbcTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

impl Eq for DbcTransaction {}

impl PartialOrd for DbcTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DbcTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash().cmp(&other.hash())
    }
}

impl DbcTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend("inputs".as_bytes());
        for m in self.inputs.iter() {
            v.extend(&m.to_bytes());
        }
        v.extend("outputs".as_bytes());
        for o in self.outputs.iter() {
            v.extend(&o.to_bytes());
        }
        v.extend("end".as_bytes());
        v
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }

    // note: must match message generated by RevealedTransaction::sign()
    pub fn gen_message(&self) -> Vec<u8> {
        // All public keys
        let public_keys: Vec<PublicKey> = self.inputs.iter().map(|m| m.public_key).collect();
        // All input blinded amounts
        let input_amounts: Vec<BlindedAmount> =
            self.inputs.iter().map(|i| i.blinded_amount).collect();
        gen_message_for_signing(&public_keys, &input_amounts, &self.outputs)
    }

    /// Verify if the blinded amounts of the inputs, are
    /// the same as the set of blinded amounts you know of.
    /// This also checks that every input has the signature over this very tx,
    /// and that each public key of the inputs was the signer.
    pub fn verify(&self, blinded_amounts: &[BlindedAmount]) -> Result<()> {
        // check input sigs
        let msg = self.gen_message();
        for (input, blinded_amount) in self.inputs.iter().zip(blinded_amounts) {
            input.verify(&msg, *blinded_amount)?
        }

        let mut prover_ts = Transcript::new(MERLIN_TRANSCRIPT_LABEL);
        let bp_gens = RevealedTransaction::bp_gens();

        for output in self.outputs.iter() {
            // Verification requires a transcript with identical initial state:
            output.range_proof.verify_single(
                &bp_gens,
                &RevealedTransaction::pc_gens(),
                &mut prover_ts,
                &output.blinded_amount.compress(),
                RANGE_PROOF_BITS,
            )?;
        }

        // Verify that the tx has at least one input
        if self.inputs.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        }

        // Verify that each public_key is unique.
        let pk_count = self.inputs.len();
        let pk_unique: BTreeSet<_> = self.inputs.iter().map(|input| input.public_key).collect();
        if pk_unique.len() != pk_count {
            return Err(Error::PublicKeyNotUniqueAcrossInputs);
        }

        // Check that the input and output blinded amounts are equal.
        let input_sum: RistrettoPoint = self
            .inputs
            .iter()
            .map(|i| i.blinded_amount)
            .map(RistrettoPoint::from)
            .sum();
        let output_sum: RistrettoPoint = self
            .outputs
            .iter()
            .map(OutputProof::blinded_amount)
            .map(RistrettoPoint::from)
            .sum();

        if input_sum != output_sum {
            Err(Error::InconsistentDbcTransaction)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use blsttc::rand::rngs::OsRng;
    use blsttc::IntoFr;
    use std::{collections::BTreeMap, iter::FromIterator};

    use super::*;
    use crate::blsttc::SecretKey;
    use crate::rand;
    use crate::RevealedInput;

    #[derive(Default)]
    struct TestLedger {
        blinded_amounts: BTreeMap<PublicKey, BlindedAmount>, // Compressed public keys -> BlindedAmounts
    }

    impl TestLedger {
        fn log(&mut self, public_key: PublicKey, blinded_amount: BlindedAmount) {
            self.blinded_amounts.insert(public_key, blinded_amount);
        }

        fn lookup(&self, public_key: PublicKey) -> Option<BlindedAmount> {
            self.blinded_amounts.get(&public_key).copied()
        }
    }

    #[test]
    fn test_input_sign() {
        let mut rng = OsRng::default();
        let pc_gens = PedersenGens::default();

        let input_sk_seed: u64 = rand::random();
        let true_input = RevealedInput {
            secret_key: SecretKey::from_mut(&mut input_sk_seed.into_fr()),
            revealed_amount: RevealedAmount {
                value: 3,
                blinding_factor: 5u32.into(),
            },
        };

        let mut ledger = TestLedger::default();
        ledger.log(
            true_input.public_key(),
            true_input.revealed_amount.blinded_amount(&pc_gens),
        );
        ledger.log(
            SecretKey::random().public_key(),
            RistrettoPoint::random(&mut rng),
        );
        ledger.log(
            SecretKey::random().public_key(),
            RistrettoPoint::random(&mut rng),
        );

        let output_sk_seed: u64 = rand::random();
        let revealed_tx = RevealedTransaction {
            inputs: vec![true_input],
            outputs: vec![Output {
                public_key: SecretKey::from_mut(&mut output_sk_seed.into_fr()).public_key(),
                amount: 3,
            }],
        };

        let (signed_tx, _revealed_output_amounts) =
            revealed_tx.sign(rng).expect("Failed to sign transaction");

        let blinded_amounts = Vec::from_iter(
            signed_tx
                .inputs
                .iter()
                .map(|input| ledger.lookup(input.public_key()).unwrap()),
        );

        assert!(signed_tx.verify(&blinded_amounts).is_ok());
    }
}
