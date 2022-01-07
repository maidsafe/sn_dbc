use blst_ringct::ringct::{RingCtMaterial, RingCtTransaction};
pub use blst_ringct::{DecoyInput, MlsagMaterial, Output, RevealedCommitment, TrueInput};
use blstrs::group::Curve;
pub use blstrs::{G1Affine, Scalar};
use blsttc::{PublicKeySet, SignatureShare};
use bulletproofs::PedersenGens;
use rand_core::RngCore;
use std::collections::{BTreeMap, HashSet};

use crate::{
    Amount, AmountSecrets, Dbc, DbcContent, Error, KeyImage, NodeSignature, ReissueRequest,
    ReissueShare, Result, SpentProof, SpentProofShare,
};

#[derive(Default)]
pub struct TransactionBuilder(RingCtMaterial);

impl TransactionBuilder {
    pub fn add_input(mut self, mlsag: MlsagMaterial) -> Self {
        self.0.inputs.push(mlsag);
        self
    }

    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = MlsagMaterial>) -> Self {
        self.0.inputs.extend(inputs);
        self
    }

    pub fn add_input_by_secrets(
        mut self,
        secret_key: Scalar,
        amount_secrets: AmountSecrets,
        decoy_inputs: Vec<DecoyInput>,
        mut rng: impl RngCore,
    ) -> Self {
        let true_input = TrueInput {
            secret_key,
            revealed_commitment: amount_secrets.into(),
        };

        self.0
            .inputs
            .push(MlsagMaterial::new(true_input, decoy_inputs, &mut rng));
        self
    }

    pub fn add_inputs_by_secrets(
        mut self,
        secrets: Vec<(Scalar, AmountSecrets, Vec<DecoyInput>)>,
        mut rng: impl RngCore,
    ) -> Self {
        for (secret_key, amount_secrets, decoy_inputs) in secrets.into_iter() {
            self = self.add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, &mut rng);
        }
        self
    }

    pub fn add_output(mut self, output: Output) -> Self {
        self.0.outputs.push(output);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = Output>) -> Self {
        self.0.outputs.extend(outputs);
        self
    }

    pub fn input_owners(&self) -> Vec<blstrs::G1Affine> {
        self.0.public_keys()
    }

    pub fn inputs_amount_sum(&self) -> Amount {
        self.0
            .inputs
            .iter()
            .map(|m| m.true_input.revealed_commitment.value)
            .sum()
    }

    pub fn outputs_amount_sum(&self) -> Amount {
        self.0.outputs.iter().map(|o| o.amount).sum()
    }

    pub fn build(
        self,
        rng: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(RingCtTransaction, Vec<RevealedCommitment>)> {
        self.0.sign(rng).map_err(|e| e.into())
    }
}

/// Builds a ReissueRequest from a ReissueTransaction and
/// any number of (input) DBC spent proof shares.
#[derive(Debug)]
pub struct ReissueRequestBuilder {
    pub transaction: RingCtTransaction,
    pub spent_proof_shares: BTreeMap<KeyImage, HashSet<SpentProofShare>>,
}

impl ReissueRequestBuilder {
    /// Create a new ReissueRequestBuilder from a RingCtTransaction
    pub fn new(transaction: RingCtTransaction) -> Self {
        Self {
            transaction,
            spent_proof_shares: Default::default(),
        }
    }

    /// Add a SpentProofShare for the given key_image
    pub fn add_spent_proof_share(mut self, key_image: KeyImage, share: SpentProofShare) -> Self {
        let shares = self.spent_proof_shares.entry(key_image).or_default();
        shares.insert(share);

        self
    }

    pub fn build(&self) -> Result<ReissueRequest> {
        let spent_proofs: BTreeMap<KeyImage, SpentProof> = self
            .spent_proof_shares
            .iter()
            .map(|(key_image, shares)| {
                let any_share = shares
                    .iter()
                    .next()
                    .ok_or(Error::ReissueRequestMissingSpentProofShare(*key_image))?;

                if shares
                    .iter()
                    .map(SpentProofShare::spentbook_pks)
                    .any(|pks| pks != any_share.spentbook_pks())
                {
                    return Err(Error::ReissueRequestPublicKeySetMismatch);
                }

                if shares
                    .iter()
                    .map(|s| &s.public_commitments)
                    .any(|pc| *pc != any_share.public_commitments)
                {
                    return Err(Error::ReissueRequestPublicCommitmentMismatch);
                }

                let spentbook_pub_key = any_share.spentbook_public_key();
                let spentbook_sig = any_share.spentbook_pks.combine_signatures(
                    shares
                        .iter()
                        .map(SpentProofShare::spentbook_sig_share)
                        .map(NodeSignature::threshold_crypto),
                )?;

                let public_commitments: Vec<G1Affine> = any_share.public_commitments.clone();

                let index = match self
                    .transaction
                    .mlsags
                    .iter()
                    .position(|m| m.key_image.to_compressed() == *key_image)
                {
                    Some(idx) => idx,
                    None => return Err(Error::SpentProofKeyImageMismatch),
                };

                let spent_proof = SpentProof {
                    index,
                    spentbook_pub_key,
                    spentbook_sig,
                    public_commitments,
                };

                Ok((*key_image, spent_proof))
            })
            .collect::<Result<_>>()?;

        let transaction = self.transaction.clone();

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
    pub transaction: RingCtTransaction,
    pub revealed_commitments: Vec<RevealedCommitment>,
    pub reissue_shares: Vec<ReissueShare>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder from a ReissueTransaction
    pub fn new(
        transaction: RingCtTransaction,
        revealed_commitments: Vec<RevealedCommitment>,
    ) -> Self {
        Self {
            transaction,
            revealed_commitments,
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

            // fixme: binary operation `!=` cannot be applied to type `RingCtTransaction`

            // if self.transaction != rs.transaction {
            //     return Err(Error::ReissueShareDbcTransactionMismatch);
            // }

            // Verify that mint sig count matches input count.
            if rs.mint_node_signatures.len() != self.transaction.mlsags.len() {
                return Err(Error::ReissueShareMintNodeSignaturesLenMismatch);
            }

            // Verify that each input has a NodeSignature

            // todo: what to replace this with?

            // for input in self.reissue_transaction.inputs.iter() {
            //     if rs.mint_node_signatures.get(&input.spend_key()).is_none() {
            //         return Err(Error::ReissueShareMintNodeSignatureNotFoundForInput);
            //     }
            // }
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
        let transaction = &self.reissue_shares[0].transaction;

        // Combine signatures from all the mint nodes to obtain Mint's Signature.
        let mint_sig = mint_public_key_set.combine_signatures(mint_sig_shares_ref)?;

        let pc_gens = PedersenGens::default();
        let output_commitments: Vec<(G1Affine, RevealedCommitment)> = self
            .revealed_commitments
            .iter()
            .map(|r| (r.commit(&pc_gens).to_affine(), *r))
            .collect();

        // Form the final output DBCs, with Mint's Signature for each.
        let output_dbcs: Vec<Dbc> = self
            .transaction
            .outputs
            .iter()
            .map(|proof| {
                let amount_secrets_list: Vec<AmountSecrets> = output_commitments
                    .iter()
                    .filter(|(c, _)| *c == proof.commitment())
                    .map(|(_, r)| AmountSecrets::from(*r))
                    .collect();
                assert!(amount_secrets_list.len() == 1);

                Dbc {
                    content: DbcContent::from((
                        *proof.public_key(),
                        amount_secrets_list[0].clone(),
                    )),
                    transaction: transaction.clone(),
                    transaction_sigs: self
                        .transaction
                        .mlsags
                        .iter()
                        .map(|mlsag| {
                            (
                                mlsag.key_image.to_compressed(),
                                (mint_public_key_set.public_key(), mint_sig.clone()),
                            )
                        })
                        .collect(),
                }
            })
            .collect();

        // sort outputs by name.  todo: is sorting necessary?
        // output_dbcs.sort_by_key(Dbc::owner);

        Ok(output_dbcs)
    }
}
