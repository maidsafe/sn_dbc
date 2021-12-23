use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use sn_dbc::{
    KeyManager, ReissueTransaction, Signature, SimpleKeyManager, SpendKey, SpentProof,
    SpentProofShare,
};

/// This is a toy SpentBook used in our mint-repl, a proper implementation
/// will be distributed, and include signatures and be auditable.
#[derive(Debug, Clone)]
pub struct SpentBook {
    key_manager: SimpleKeyManager,
    transactions: BTreeMap<SpendKey, ReissueTransaction>,
}

impl SpentBook {
    pub fn new(key_manager: SimpleKeyManager) -> Self {
        Self {
            key_manager,
            transactions: Default::default(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SpendKey, &ReissueTransaction)> {
        self.transactions.iter()
    }

    pub fn is_spent(&self, spend_key: &SpendKey) -> bool {
        self.transactions.contains_key(spend_key)
    }

    pub fn log_spent(
        &mut self,
        spend_key: SpendKey,
        spent_sig: Signature,
        tx: ReissueTransaction,
    ) -> Result<SpentProofShare> {
        let tx_hash = tx.blinded().hash();
        if !spend_key.0.verify(&spent_sig, &tx_hash) {
            return Err(anyhow!("Failed to validate spent signature"));
        }
        let spentbook_pks = self.key_manager.public_key_set()?;
        let proof_msg_hash = SpentProof::proof_msg(&tx_hash, &spent_sig);
        let spentbook_sig_share = self.key_manager.sign(&proof_msg_hash)?;

        let public_commitments: Vec<G1Affine> = tx.mlsags.iter().map(|mlsag| {
            mlsag.public_keys().iter.map(|pk| {
                let output_proof = self.transactions.values().filter_map(|ringct_tx| {
                    ringct_tx.outputs.iter().find(|proof| proof.public_key() == pk)
                });
                output_proof.commitment
            }).collect()
        });

        let existing_tx = self.transactions.entry(spend_key).or_insert(tx);
        if existing_tx.blinded().hash() == tx_hash {
            Ok(SpentProofShare {
                spent_sig,
                spentbook_pks,
                spentbook_sig_share,
            })
        } else {
            Err(anyhow!("Attempt to Double Spend"))
        }
    }
}
