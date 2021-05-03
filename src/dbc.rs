// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeMap;

use crate::{
    DbcContent, DbcContentHash, DbcTransaction, Error, KeyCache, PublicKey, Result, Signature,
};

pub struct Dbc {
    pub content: DbcContent,
    pub transaction: DbcTransaction,
    pub transaction_sigs: BTreeMap<DbcContentHash, (PublicKey, Signature)>,
}

impl Dbc {
    // Check there exists a DbcTransaction with the output containing this Dbc
    // Check there DOES NOT exist a DbcTransaction with this Dbc as parent (already minted)
    pub fn confirm_valid(&self, key_cache: &KeyCache) -> Result<(), Error> {
        todo!();
        // if !self.transaction.outputs.contains(&self.content.hash()) {
        //     return Err(Error::DbcContentNotPresentInTransactionOutput);
        // } else if self.transaction.inputs != self.content.parents {
        //     return Err(Error::DbcContentParentsDifferentFromTransactionInputs);
        // } else if {
        // }
        // if network.get(self.parent()).await {
        //     return err(Error::DoubleSpend);
        // }
    }
    // Check the output values summed are  =< input value
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<DbcTransaction> {
        // self.confirm_valid()?;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier};
    use quickcheck_macros::quickcheck;

    use crate::{sha3_256, threshold_crypto::ed25519_keypair};

    #[quickcheck]
    fn prop_invalid_if_content_not_in_transaction_output(
        amount: u64,
        inputs: Vec<u8>,
        outputs: Vec<u8>,
    ) {
        let input_hashes: BTreeSet<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let output_hashes: BTreeSet<DbcContentHash> =
            outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

        let content = DbcContent {
            parents: input_hashes.clone(),
            amount: amount,
        };

        let id = ed25519_keypair();
        let thresh_key = ThresholdPublicKey::new(1, vec![id.public].into_iter().collect()).unwrap();
        let mut thresh_sig = ThresholdSignature::new();
        thresh_sig.add_share(id.public, id.sign(&content.hash()));

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: input_hashes
                .into_iter()
                .map(|i| (i, (thresh_key.clone(), thresh_sig.clone())))
                .collect(),
        };

        assert!(matches!(
            dbc.confirm_valid(&[&thresh_key]),
            Err(Error::DbcContentNotPresentInTransactionOutput)
        ));
    }

    #[quickcheck]
    fn prop_invalid_if_content_parents_is_not_transaction_inputs(
        amount: u64,
        inputs: Vec<u8>,
        content_parents: Vec<u8>,
        outputs: Vec<u8>,
    ) {
        let input_hashes: BTreeSet<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let parents: BTreeSet<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let mut output_hashes: BTreeSet<DbcContentHash> =
            outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let content = DbcContent { parents, amount };
        output_hashes.insert(content.hash());

        let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

        let id = ed25519_keypair();
        let thresh_key = ThresholdPublicKey::new(1, vec![id.public].into_iter().collect()).unwrap();
        let mut thresh_sig = ThresholdSignature::new();
        thresh_sig.add_share(id.public, id.sign(&content.hash()));

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: input_hashes
                .into_iter()
                .map(|i| (i, (thresh_key.clone(), thresh_sig.clone())))
                .collect(),
        };

        assert!(matches!(
            dbc.confirm_valid(&[&thresh_key]),
            Err(Error::DbcContentParentsDifferentFromTransactionInputs)
        ));
    }

    #[quickcheck]
    fn prop_mix_of_invalid_and_valid_sigs(
        amount: u64,
        inputs: Vec<u8>,
        outputs: Vec<u8>,
        mints: u8,
        invalid_mints: u8,
    ) {
        let input_hashes: BTreeSet<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let mut output_hashes: BTreeSet<DbcContentHash> =
            outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let content = DbcContent {
            parents: input_hashes.clone(),
            amount,
        };
        output_hashes.insert(content.hash());

        let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

        let id = ed25519_keypair();
        let thresh_key = ThresholdPublicKey::new(1, vec![id.public].into_iter().collect()).unwrap();
        let mut thresh_sig = ThresholdSignature::new();
        thresh_sig.add_share(id.public, id.sign(&content.hash()));

        let mint_ids: Vec<_> = (0..mints).map(|_| ed25519_keypair()).collect();
        let invalid_mint_ids: Vec<_> = (0..invalid_mints).map(|_| ed25519_keypair()).collect();

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: input_hashes
                .iter()
                .zip(invalid_mint_ids)
                .map(|(in_hash, mint_id)| {
                    let thresh_key =
                        ThresholdPublicKey::new(1, vec![mint_id.public].into_iter().collect())
                            .unwrap();
                    let mut thresh_sig = ThresholdSignature::new();
                    thresh_sig.add_share(mint_id.public, mint_id.sign(in_hash));

                    (*in_hash, (thresh_key, thresh_sig))
                })
                .chain(
                    input_hashes
                        .iter()
                        .skip(invalid_mints as usize)
                        .zip(mint_ids)
                        .map(|(in_hash, mint_id)| {
                            let thresh_key = ThresholdPublicKey::new(
                                1,
                                vec![mint_id.public].into_iter().collect(),
                            )
                            .unwrap();
                            let mut thresh_sig = ThresholdSignature::new();
                            thresh_sig.add_share(mint_id.public, mint_id.sign(in_hash));

                            (*in_hash, (thresh_key, thresh_sig))
                        }),
                )
                .collect(),
        };

        if invalid_mints > 0 {
            assert!(matches!(
                dbc.confirm_valid(&[&thresh_key]),
                Err(Error::UnrecognisedAuthority)
            ));
        } else {
            assert!(matches!(dbc.confirm_valid(&[&thresh_key]), Ok(())));
        }
    }

    #[quickcheck]
    fn prop_each_input_must_have_a_corresponding_signature(
        amount: u64,
        inputs: Vec<u8>,
        outputs: Vec<u8>,
        n_mints: u8,
    ) {
        let input_hashes: BTreeSet<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let mut output_hashes: BTreeSet<DbcContentHash> =
            outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let content = DbcContent {
            parents: input_hashes.clone(),
            amount,
        };
        output_hashes.insert(content.hash());

        let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

        let id = ed25519_keypair();
        let thresh_key = ThresholdPublicKey::new(1, vec![id.public].into_iter().collect()).unwrap();
        let mut thresh_sig = ThresholdSignature::new();
        thresh_sig.add_share(id.public, id.sign(&content.hash()));

        let mint_ids: Vec<_> = (0..n_mints).map(|_| ed25519_keypair()).collect();

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: input_hashes
                .iter()
                .zip(mint_ids)
                .map(|(in_hash, mint_id)| {
                    let thresh_key =
                        ThresholdPublicKey::new(1, vec![mint_id.public].into_iter().collect())
                            .unwrap();
                    let mut thresh_sig = ThresholdSignature::new();
                    thresh_sig.add_share(mint_id.public, mint_id.sign(in_hash));

                    (*in_hash, (thresh_key, thresh_sig))
                })
                .collect(),
        };

        let validation_res = dbc.confirm_valid(&[&thresh_key]);

        if (n_mints as usize) < inputs.len() {
            assert!(matches!(
                validation_res,
                Err(Error::MissingSignatureForInput)
            ));
        } else {
            assert!(matches!(validation_res, Ok(())));
        }
    }
}
