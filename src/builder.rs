use blsttc::{Fr, IntoFr, PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use curve25519_dalek_ng::scalar::Scalar;

use crate::{
    Amount, AmountSecrets, Dbc, DbcContent, Error, NodeSignature, PublicKey, ReissueRequest,
    ReissueShare, ReissueTransaction, Result, SpendKey,
};

///! Unblinded data for creating sn_dbc::DbcContent
pub struct Output {
    pub amount: Amount,
    pub owner: PublicKey,
}

#[derive(Default)]
pub struct TransactionBuilder {
    pub inputs: HashMap<Dbc, AmountSecrets>,
    pub outputs: Vec<Output>,
}

impl TransactionBuilder {
    pub fn add_input(mut self, dbc: Dbc, amount_secrets: AmountSecrets) -> Self {
        self.inputs.insert(dbc, amount_secrets);
        self
    }

    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = (Dbc, AmountSecrets)>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    pub fn add_output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = Output>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    pub fn input_owners(&self) -> BTreeSet<PublicKey> {
        BTreeSet::from_iter(self.inputs.keys().map(Dbc::owner))
    }

    pub fn input_spend_keys(&self) -> BTreeSet<SpendKey> {
        BTreeSet::from_iter(self.inputs.keys().map(Dbc::spend_key))
    }

    pub fn inputs_amount_sum(&self) -> Amount {
        self.inputs.iter().map(|(_, s)| s.amount).sum()
    }

    pub fn outputs_amount_sum(&self) -> Amount {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    pub fn build(self) -> Result<ReissueTransaction> {
        let parents = BTreeSet::from_iter(self.inputs.keys().map(Dbc::spend_key));
        let inputs_bf_sum = self
            .inputs
            .values()
            .map(|amount_secrets| amount_secrets.blinding_factor)
            .sum();

        let mut outputs_bf_sum: Scalar = Default::default();
        let outputs_and_owners = self
            .outputs
            .iter()
            .enumerate()
            .map(|(out_idx, output)| {
                let blinding_factor = DbcContent::calc_blinding_factor(
                    out_idx == self.outputs.len() - 1,
                    inputs_bf_sum,
                    outputs_bf_sum,
                );
                outputs_bf_sum += blinding_factor;

                let dbc_content = DbcContent::new(
                    parents.clone(),
                    output.amount,
                    output.owner,
                    blinding_factor,
                )?;
                Ok((dbc_content, output.owner))
            })
            .collect::<Result<Vec<_>>>()?;

        let inputs = HashSet::from_iter(self.inputs.into_keys());
        let outputs = HashSet::from_iter(outputs_and_owners.into_iter().map(|(o, _)| o));
        Ok(ReissueTransaction { inputs, outputs })
    }
}

/// Builds a ReissueRequest from a ReissueTransaction and
/// any number of (input) DBC hashes with associated ownership share(s).
#[derive(Debug, Default)]
pub struct ReissueRequestBuilder {
    pub reissue_transaction: Option<ReissueTransaction>,
    #[allow(clippy::type_complexity)]
    pub signers_by_dbc: HashMap<SpendKey, BTreeMap<PublicKeySet, BTreeMap<Fr, SecretKeyShare>>>,
}

impl ReissueRequestBuilder {
    /// Create a new ReissueRequestBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction: Some(reissue_transaction),
            signers_by_dbc: Default::default(),
        }
    }

    /// Set the reissue_transaction
    pub fn set_reissue_transaction(mut self, reissue_transaction: ReissueTransaction) -> Self {
        self.reissue_transaction = Some(reissue_transaction);
        self
    }

    /// Add a single signer share for a DBC hash
    pub fn add_dbc_signer<FR: IntoFr>(
        mut self,
        dbc_key: SpendKey,
        public_key_set: PublicKeySet,
        secret_key_share: (FR, SecretKeyShare),
    ) -> Self {
        self.signers_by_dbc
            .entry(dbc_key)
            .or_default()
            .entry(public_key_set)
            .or_default()
            .insert(secret_key_share.0.into_fr(), secret_key_share.1);
        self
    }

    /// Add a list of signer shares for a DBC hash
    pub fn add_dbc_signers<FR: IntoFr>(
        mut self,
        dbc_key: SpendKey,
        public_key_set: PublicKeySet,
        secret_key_shares: Vec<(FR, SecretKeyShare)>,
    ) -> Self {
        let dbc_owners = self.signers_by_dbc.entry(dbc_key).or_default();
        for (idx, secret_key_share) in secret_key_shares.into_iter() {
            dbc_owners
                .entry(public_key_set.clone())
                .or_default()
                .insert(idx.into_fr(), secret_key_share);
        }
        self
    }

    pub fn num_signers_by_dbc(&self, dbc_key: SpendKey) -> usize {
        self.signers_by_dbc
            .get(&dbc_key)
            .map(BTreeMap::len)
            .unwrap_or(0)
    }

    pub fn get_signers(
        &self,
        dbc_key: SpendKey,
    ) -> Option<&BTreeMap<PublicKeySet, BTreeMap<Fr, SecretKeyShare>>> {
        self.signers_by_dbc.get(&dbc_key)
    }

    /// Aggregates SecretKeyShares for all DBC owners in a ReissueTransaction
    /// in order to combine signature shares into Signatures, thereby
    /// creating the ownership proofs necessary to construct
    /// a ReissueRequest.
    pub fn build(self) -> Result<ReissueRequest> {
        let mut input_ownership_proofs: HashMap<SpendKey, Signature> = Default::default();
        let transaction = match self.reissue_transaction {
            Some(tx) => tx,
            None => return Err(Error::MissingReissueTransaction),
        };

        for dbc in transaction.inputs.iter() {
            let signers = self
                .signers_by_dbc
                .get(&dbc.spend_key())
                .ok_or(Error::MissingInputOwnerProof)?;

            if signers.len() != 1 {
                return Err(Error::ReissueRequestPublicKeySetMismatch);
            }
            let (owner_pks, secret_shares) = signers
                .iter()
                .next()
                .ok_or(Error::ReissueRequestPublicKeySetMismatch)?;

            let sig_shares: BTreeMap<Fr, SignatureShare> = secret_shares
                .iter()
                .map(|(idx, secret_key_share)| {
                    let sks = secret_key_share.derive_child(&dbc.spend_key_index());
                    let sig_share = sks.sign(transaction.blinded().hash());
                    (*idx, sig_share)
                })
                .collect();

            let signature = owner_pks.combine_signatures(sig_shares)?;
            input_ownership_proofs.insert(dbc.spend_key(), signature);
        }

        let rr = ReissueRequest {
            transaction,
            input_ownership_proofs,
        };
        Ok(rr)
    }
}

/// A Builder for aggregating ReissueShare (Mint::reissue() results)
/// from multiple mint nodes and combining signatures to
/// generate the final Dbc outputs.
#[derive(Debug)]
pub struct DbcBuilder {
    pub reissue_transaction: ReissueTransaction,
    pub reissue_shares: Vec<ReissueShare>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction,
            reissue_shares: Default::default(),
        }
    }

    /// Add a ReissueShare from Mint::reissue()
    pub fn add_reissue_share(mut self, reissue_share: ReissueShare) -> Self {
        self.reissue_shares.push(reissue_share);
        self
    }

    /// Add multiple ReissueShare from Mint::reissue()
    pub fn add_reissue_shares(mut self, shares: impl IntoIterator<Item = ReissueShare>) -> Self {
        self.reissue_shares.extend(shares);
        self
    }

    /// Build the output DBCs
    pub fn build(self) -> Result<Vec<Dbc>> {
        if self.reissue_shares.is_empty() {
            return Err(Error::NoReissueShares);
        }

        let mut mint_sig_shares: Vec<NodeSignature> = Default::default();
        let mut pk_set: HashSet<PublicKeySet> = Default::default();

        for rs in self.reissue_shares.iter() {
            // Make a list of NodeSignature (sigshare from each Mint Node)
            let mut node_shares: Vec<NodeSignature> = rs
                .mint_node_signatures
                .iter()
                .map(|e| e.1 .1.clone())
                .collect();
            mint_sig_shares.append(&mut node_shares);

            let pub_key_sets: HashSet<PublicKeySet> = rs
                .mint_node_signatures
                .iter()
                .map(|e| e.1 .0.clone())
                .collect();

            // add pubkeyset to HashSet, so we can verify there is only one distinct PubKeySet
            pk_set = &pk_set | &pub_key_sets; // union the sets together.

            // Verify transaction returned to us by the Mint matches our request
            if self.reissue_transaction.blinded() != rs.dbc_transaction {
                return Err(Error::ReissueShareDbcTransactionMismatch);
            }

            // Verify that mint sig count matches input count.
            if rs.mint_node_signatures.len() != self.reissue_transaction.inputs.len() {
                return Err(Error::ReissueShareMintNodeSignaturesLenMismatch);
            }

            // Verify that each input has a NodeSignature
            for input in self.reissue_transaction.inputs.iter() {
                if rs.mint_node_signatures.get(&input.spend_key()).is_none() {
                    return Err(Error::ReissueShareMintNodeSignatureNotFoundForInput);
                }
            }
        }

        // verify that PublicKeySet for all Dbc in all ReissueShare match.
        if pk_set.len() != 1 {
            return Err(Error::ReissueSharePublicKeySetMismatch);
        }
        let mint_public_key_set = match pk_set.iter().next() {
            Some(pks) => pks,
            None => return Err(Error::ReissueSharePublicKeySetMismatch),
        };

        // Transform Vec<NodeSignature> to Vec<u64, &SignatureShare>
        let mint_sig_shares_ref: Vec<(u64, &SignatureShare)> = mint_sig_shares
            .iter()
            .map(|e| e.threshold_crypto())
            .collect();

        // Note: we can just use the first item because we already verified that
        // all the ReissueShare match for dbc_transaction
        let dbc_transaction = &self.reissue_shares[0].dbc_transaction;

        // Combine signatures from all the mint nodes to obtain Mint's Signature.
        let mint_sig = mint_public_key_set.combine_signatures(mint_sig_shares_ref)?;

        // Form the final output DBCs, with Mint's Signature for each.
        let mut output_dbcs: Vec<Dbc> = self
            .reissue_transaction
            .outputs
            .iter()
            .map(|content| Dbc {
                content: content.clone(),
                transaction: dbc_transaction.clone(),
                transaction_sigs: self
                    .reissue_transaction
                    .inputs
                    .iter()
                    .map(|input| {
                        (
                            input.spend_key(),
                            (mint_public_key_set.public_key(), mint_sig.clone()),
                        )
                    })
                    .collect(),
            })
            .collect();

        // sort outputs by name
        output_dbcs.sort_by_key(Dbc::owner);

        Ok(output_dbcs)
    }
}
