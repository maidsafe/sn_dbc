use std::collections::BTreeMap;

use sn_dbc::{
    Error, KeyManager, ReissueTransaction, Result, Signature, SimpleKeyManager, SpendKey,
    SpentProof, SpentProofShare,
};

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
        spend_sig: Signature,
        tx: ReissueTransaction,
    ) -> Result<SpentProofShare> {
        let tx_hash = tx.blinded().hash();
        if !spend_key.0.verify(&spend_sig, &tx_hash) {
            return Err(Error::FailedSignature);
        }
        let spentbook_pks = self.key_manager.public_key_set()?;
        let proof_msg_hash = SpentProof::proof_msg(&tx_hash, &spend_sig);
        let spentbook_sig_share = self.key_manager.sign(&proof_msg_hash)?;

        let existing_tx = self.transactions.entry(spend_key).or_insert(tx);
        if existing_tx.blinded().hash() == tx_hash {
            Ok(SpentProofShare {
                spend_sig,
                spentbook_pks,
                spentbook_sig_share,
            })
        } else {
            Err(Error::DoubleSpend)
        }
    }
}
