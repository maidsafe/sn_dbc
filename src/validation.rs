use crate::{Error, Hash, KeyImage, KeyManager, PublicKey, Result, SpentProof};
use blst_ringct::ringct::RingCtTransaction;
use blstrs::G1Affine;
use blsttc::Signature;
use std::collections::{BTreeMap, BTreeSet};

// Here we are putting transaction validation logic that is common to both
// MintNode::reissue() and Dbc::confirm_valid().
//
// It is best to have the validation logic in one place only!
//
// Note also that MintNode is server-side (mint) and Dbc is client-side (wallet).
// In a future refactor, we intend to break the code into 3 modules:
//   server, client, and common.  (or maybe mint, wallet, and common)
// So TransactionValidator would go into common.
//
// Another way to do this would be to create a NewType wrapper for RingCtTransaction.
// We can discuss if that is better or not.

pub struct TransactionValidator {}

impl TransactionValidator {
    // note: for spent_proofs to validate, the mint_verifier must have/know the spentbook section's public key.
    pub fn validate<K: KeyManager>(
        mint_verifier: &K,
        transaction: &RingCtTransaction,
        transaction_sigs: &BTreeMap<KeyImage, (PublicKey, Signature)>,
        spent_proofs: &BTreeSet<SpentProof>,
    ) -> Result<(), Error> {
        // Do quick checks first to reduce potential DOS vectors.

        if transaction_sigs.len() < transaction.mlsags.len() {
            return Err(Error::MissingSignatureForInput);
        }

        let tx_hash = Hash::from(transaction.hash());

        // Verify that each input has a corresponding valid mint signature.
        for (key_image, (mint_key, mint_sig)) in transaction_sigs.iter() {
            if !transaction
                .mlsags
                .iter()
                .any(|m| m.key_image.to_compressed() == *key_image)
            {
                return Err(Error::UnknownInput);
            }

            mint_verifier
                .verify(&tx_hash, mint_key, mint_sig)
                .map_err(|e| Error::Signing(e.to_string()))?;
        }

        Self::validate_without_sigs_internal(mint_verifier, transaction, tx_hash, spent_proofs)
    }

    pub fn validate_without_sigs<K: KeyManager>(
        mint_verifier: &K,
        transaction: &RingCtTransaction,
        spent_proofs: &BTreeSet<SpentProof>,
    ) -> Result<(), Error> {
        let tx_hash = Hash::from(transaction.hash());
        Self::validate_without_sigs_internal(mint_verifier, transaction, tx_hash, spent_proofs)
    }

    fn validate_without_sigs_internal<K: KeyManager>(
        mint_verifier: &K,
        transaction: &RingCtTransaction,
        transaction_hash: Hash,
        spent_proofs: &BTreeSet<SpentProof>,
    ) -> Result<(), Error> {
        if transaction.mlsags.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        } else if spent_proofs.len() != transaction.mlsags.len() {
            return Err(Error::SpentProofInputMismatch);
        }

        // Verify that each KeyImage is unique in this tx.
        let keyimage_unique: BTreeSet<KeyImage> = transaction
            .mlsags
            .iter()
            .map(|m| m.key_image.to_compressed())
            .collect();
        if keyimage_unique.len() != transaction.mlsags.len() {
            return Err(Error::KeyImageNotUniqueAcrossInputs);
        }

        // Verify that each pubkey is unique in this transaction.
        let pubkey_unique: BTreeSet<KeyImage> = transaction
            .outputs
            .iter()
            .map(|o| o.public_key().to_compressed())
            .collect();
        if pubkey_unique.len() != transaction.outputs.len() {
            return Err(Error::PublicKeyNotUniqueAcrossOutputs);
        }

        // Verify that each input has a corresponding valid spent proof.
        //
        // note: for the proofs to validate, our key_manager must have/know
        // the pubkey of the spentbook section that signed the proof.
        // This is a responsibility of our caller, not this crate.
        for spent_proof in spent_proofs.iter() {
            if !transaction
                .mlsags
                .iter()
                .any(|m| m.key_image.to_compressed() == spent_proof.key_image)
            {
                return Err(Error::SpentProofInputMismatch);
            }
            spent_proof.validate(transaction_hash, mint_verifier)?;
        }

        // We must get the spent_proofs into the same order as mlsags
        // so that resulting public_commitments will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut spent_proofs_found: Vec<(usize, &SpentProof)> = spent_proofs
            .iter()
            .filter_map(|s| {
                transaction
                    .mlsags
                    .iter()
                    .position(|m| m.key_image.to_compressed() == s.key_image)
                    .map(|idx| (idx, s))
            })
            .collect();

        spent_proofs_found.sort_by_key(|s| s.0);
        let spent_proofs_sorted: Vec<&SpentProof> =
            spent_proofs_found.into_iter().map(|s| s.1).collect();

        let public_commitments: Vec<Vec<G1Affine>> = spent_proofs_sorted
            .iter()
            .map(|s| s.public_commitments.clone())
            .collect();

        transaction.verify(&public_commitments)?;

        Ok(())
    }
}
