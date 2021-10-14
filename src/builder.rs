use blsttc::{PublicKeySet, SignatureShare};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use curve25519_dalek_ng::scalar::Scalar;

use crate::{
    Amount, AmountSecrets, Dbc, DbcContent, Error, NodeSignature, PublicKey, ReissueRequest,
    ReissueShare, ReissueTransaction, Result, SpendKey, SpentProof, SpentProofShare,
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
/// any number of (input) DBC spent proof shares.
#[derive(Debug)]
pub struct ReissueRequestBuilder {
    pub reissue_transaction: ReissueTransaction,
    pub spent_proof_shares: BTreeMap<SpendKey, HashSet<SpentProofShare>>,
}

impl ReissueRequestBuilder {
    /// Create a new ReissueRequestBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction,
            spent_proof_shares: Default::default(),
        }
    }

    /// Add a SpentProofShare for the given spend_key
    pub fn add_spent_proof_share(mut self, spend_key: SpendKey, share: SpentProofShare) -> Self {
        let shares = self.spent_proof_shares.entry(spend_key).or_default();
        shares.insert(share);

        self
    }

    pub fn build(&self) -> Result<ReissueRequest> {
        let spent_proofs: BTreeMap<SpendKey, SpentProof> = self
            .spent_proof_shares
            .iter()
            .map(|(spend_key, shares)| {
                let any_share = shares
                    .iter()
                    .next()
                    .ok_or(Error::ReissueRequestMissingSpentProofShare(*spend_key))?;

                if shares
                    .iter()
                    .map(SpentProofShare::spentbook_pks)
                    .any(|pks| pks != any_share.spentbook_pks())
                {
                    return Err(Error::ReissueRequestPublicKeySetMismatch);
                }

                let spend_sig = any_share.spend_sig.clone();
                let spentbook_pub_key = any_share.spentbook_public_key();
                let spentbook_sig = any_share.spentbook_pks.combine_signatures(
                    shares
                        .iter()
                        .map(SpentProofShare::spentbook_sig_share)
                        .map(NodeSignature::threshold_crypto),
                )?;

                let spent_proof = SpentProof {
                    spend_sig,
                    spentbook_pub_key,
                    spentbook_sig,
                };

                Ok((*spend_key, spent_proof))
            })
            .collect::<Result<_>>()?;

        let transaction = self.reissue_transaction.clone();

        let rr = ReissueRequest {
            transaction,
            spent_proofs,
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
