// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blst_ringct::ringct::{RingCtMaterial, RingCtTransaction};
pub use blst_ringct::{DecoyInput, MlsagMaterial, Output, RevealedCommitment, TrueInput};
use blstrs::group::Curve;
use blsttc::{PublicKeySet, SecretKey, SignatureShare};
use bulletproofs::PedersenGens;
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    Amount, AmountSecrets, Commitment, Dbc, DbcContent, Error, NodeSignature, OwnerOnce,
    PublicKeyBlst, PublicKeyBlstMappable, ReissueRequest, ReissueShare, Result, SecretKeyBlst,
    SpentProof, SpentProofShare,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type OutputOwnerMap = BTreeMap<PublicKeyBlstMappable, OwnerOnce>;

/// A builder to create a RingCt transaction from
/// inputs and outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    material: RingCtMaterial,
    output_owners: OutputOwnerMap,
}

impl TransactionBuilder {
    /// add an input given an MlsagMaterial
    pub fn add_input(mut self, mlsag: MlsagMaterial) -> Self {
        self.material.inputs.push(mlsag);
        self
    }

    /// add an input given an iterator over MlsagMaterial
    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = MlsagMaterial>) -> Self {
        self.material.inputs.extend(inputs);
        self
    }

    /// add an input given a TrueInput and decoy list
    pub fn add_input_by_true_input(
        mut self,
        true_input: TrueInput,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Self {
        self.material
            .inputs
            .push(MlsagMaterial::new(true_input, decoy_inputs, rng));
        self
    }

    /// add an input given a list of TrueInputs and associated decoys
    pub fn add_inputs_by_true_inputs(
        mut self,
        inputs: impl IntoIterator<Item = (TrueInput, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Self {
        for (true_input, decoy_inputs) in inputs.into_iter() {
            self = self.add_input_by_true_input(true_input, decoy_inputs, rng);
        }
        self
    }

    /// add an input given a Dbc, SecretKey and decoy list
    pub fn add_input_dbc<D: AsRef<Dbc>, S: AsRef<SecretKey>>(
        mut self,
        dbc: D,
        base_sk: S,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        self = self.add_input_by_true_input(
            dbc.as_ref().as_true_input(base_sk.as_ref())?,
            decoy_inputs,
            rng,
        );
        Ok(self)
    }

    /// add an input given a list of Dbcs and associated SecretKey and decoys
    pub fn add_inputs_dbc<D: AsRef<Dbc>, S: AsRef<SecretKey>>(
        mut self,
        dbcs: impl IntoIterator<Item = (D, S, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        for (dbc, base_sk, decoy_inputs) in dbcs.into_iter() {
            self = self.add_input_dbc(dbc, base_sk, decoy_inputs, rng)?;
        }
        Ok(self)
    }

    pub fn add_input_dbc_bearer<D: AsRef<Dbc>>(
        mut self,
        dbc: D,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        self =
            self.add_input_by_true_input(dbc.as_ref().as_true_input_bearer()?, decoy_inputs, rng);
        Ok(self)
    }

    pub fn add_inputs_dbc_bearer<D: AsRef<Dbc>>(
        mut self,
        dbcs: impl IntoIterator<Item = (D, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        for (dbc, decoy_inputs) in dbcs.into_iter() {
            self = self.add_input_dbc_bearer(dbc, decoy_inputs, rng)?;
        }
        Ok(self)
    }

    pub fn add_input_by_secrets(
        mut self,
        secret_key: SecretKeyBlst,
        amount_secrets: AmountSecrets,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Self {
        let true_input = TrueInput {
            secret_key,
            revealed_commitment: amount_secrets.into(),
        };

        self.material
            .inputs
            .push(MlsagMaterial::new(true_input, decoy_inputs, rng));
        self
    }

    pub fn add_inputs_by_secrets(
        mut self,
        secrets: Vec<(SecretKeyBlst, AmountSecrets, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Self {
        for (secret_key, amount_secrets, decoy_inputs) in secrets.into_iter() {
            self = self.add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, rng);
        }
        self
    }

    pub fn add_output(mut self, output: Output, owner: OwnerOnce) -> Self {
        self.output_owners.insert(output.public_key().into(), owner);
        self.material.outputs.push(output);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = (Output, OwnerOnce)>) -> Self {
        for (output, owner) in outputs.into_iter() {
            self = self.add_output(output, owner);
        }
        self
    }

    pub fn input_owners(&self) -> Vec<PublicKeyBlst> {
        self.material.public_keys()
    }

    pub fn inputs_amount_sum(&self) -> Amount {
        self.material
            .inputs
            .iter()
            .map(|m| m.true_input.revealed_commitment.value)
            .sum()
    }

    pub fn outputs_amount_sum(&self) -> Amount {
        self.material.outputs.iter().map(|o| o.amount).sum()
    }

    pub fn build(
        self,
        rng: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(
        RingCtTransaction,
        Vec<RevealedCommitment>,
        RingCtMaterial,
        OutputOwnerMap,
    )> {
        let result: Result<(RingCtTransaction, Vec<RevealedCommitment>)> =
            self.material.sign(rng).map_err(|e| e.into());
        let (transaction, revealed_commitments) = result?;
        Ok((
            transaction,
            revealed_commitments,
            self.material,
            self.output_owners,
        ))
    }
}

/// Builds a ReissueRequest from a RingCtTransaction and
/// any number of (input) DBC spent proof shares.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct ReissueRequestBuilder {
    pub transaction: RingCtTransaction,
    pub spent_proof_shares: BTreeMap<usize, HashSet<SpentProofShare>>,
}

impl ReissueRequestBuilder {
    /// Create a new ReissueRequestBuilder from a RingCtTransaction
    pub fn new(transaction: RingCtTransaction) -> Self {
        Self {
            transaction,
            spent_proof_shares: Default::default(),
        }
    }

    /// Add a SpentProofShare for the given input index
    pub fn add_spent_proof_share(mut self, input_index: usize, share: SpentProofShare) -> Self {
        let shares = self.spent_proof_shares.entry(input_index).or_default();
        shares.insert(share);

        self
    }

    /// Add a list of SpentProofShare for the given input index
    pub fn add_spent_proof_shares(
        mut self,
        shares: impl IntoIterator<Item = (usize, SpentProofShare)>,
    ) -> Self {
        for (input_index, share) in shares.into_iter() {
            self = self.add_spent_proof_share(input_index, share);
        }
        self
    }

    pub fn build(&self) -> Result<ReissueRequest> {
        let spent_proofs: BTreeSet<SpentProof> = self
            .spent_proof_shares
            .iter()
            .map(|(input_index, shares)| {
                let any_share = shares
                    .iter()
                    .next()
                    .ok_or(Error::ReissueRequestMissingSpentProofShare(*input_index))?;

                if !shares
                    .iter()
                    .map(SpentProofShare::spentbook_pks)
                    .any(|pks| pks == any_share.spentbook_pks())
                {
                    return Err(Error::ReissueRequestPublicKeySetMismatch);
                }

                if !shares
                    .iter()
                    .map(|s| &s.public_commitments)
                    .any(|pc| *pc == any_share.public_commitments)
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

                let public_commitments: Vec<Commitment> = any_share.public_commitments.clone();

                let spent_proof = SpentProof {
                    key_image: any_share.key_image.clone(),
                    spentbook_pub_key,
                    spentbook_sig,
                    public_commitments,
                };

                Ok(spent_proof)
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct DbcBuilder {
    pub revealed_commitments: Vec<RevealedCommitment>,
    pub output_owners: OutputOwnerMap,

    pub reissue_shares: Vec<ReissueShare>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder
    pub fn new(
        revealed_commitments: Vec<RevealedCommitment>,
        output_owners: OutputOwnerMap,
    ) -> Self {
        Self {
            revealed_commitments,
            output_owners,
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
    pub fn build(self) -> Result<Vec<(Dbc, OwnerOnce, AmountSecrets)>> {
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

            // Verify that mint sig count matches input count.
            if rs.mint_node_signatures.len() != rs.transaction.mlsags.len() {
                return Err(Error::ReissueShareMintNodeSignaturesLenMismatch);
            }

            // Verify that each input has a NodeSignature
            for mlsag in rs.transaction.mlsags.iter() {
                if !rs
                    .mint_node_signatures
                    .keys()
                    .any(|k| *k == mlsag.key_image.into())
                {
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
        // all the ReissueShare match
        let transaction = &self.reissue_shares[0].transaction;
        let spent_proofs = &self.reissue_shares[0].spent_proofs;

        // Combine signatures from all the mint nodes to obtain Mint's Signature.
        let mint_sig = mint_public_key_set.combine_signatures(mint_sig_shares_ref)?;

        let pc_gens = PedersenGens::default();
        let output_commitments: Vec<(Commitment, RevealedCommitment)> = self
            .revealed_commitments
            .iter()
            .map(|r| (r.commit(&pc_gens).to_affine(), *r))
            .collect();

        let owner_once_list: Vec<&OwnerOnce> = transaction
            .outputs
            .iter()
            .map(|output| {
                self.output_owners
                    .get(&(*output.public_key()).into())
                    .ok_or(Error::PublicKeyNotFound)
            })
            .collect::<Result<_>>()?;

        // Form the final output DBCs, with Mint's Signature for each.
        let output_dbcs: Vec<(Dbc, OwnerOnce, AmountSecrets)> = transaction
            .outputs
            .iter()
            .zip(owner_once_list)
            .map(|(output, owner_once)| {
                let amount_secrets_list: Vec<AmountSecrets> = output_commitments
                    .iter()
                    .filter(|(c, _)| *c == output.commitment())
                    .map(|(_, r)| AmountSecrets::from(*r))
                    .collect();
                assert_eq!(amount_secrets_list.len(), 1);

                let dbc = Dbc {
                    content: DbcContent::from((
                        owner_once.owner_base.clone(),
                        owner_once.derivation_index,
                        amount_secrets_list[0].clone(),
                    )),
                    transaction: transaction.clone(),
                    transaction_sigs: transaction
                        .mlsags
                        .iter()
                        .map(|mlsag| {
                            (
                                mlsag.key_image.into(),
                                (mint_public_key_set.public_key(), mint_sig.clone()),
                            )
                        })
                        .collect(),
                    spent_proofs: spent_proofs.clone(),
                };
                (dbc, owner_once.clone(), amount_secrets_list[0].clone())
            })
            .collect();

        // sort outputs by name.  todo: is sorting necessary?
        // output_dbcs.sort_by_key(Dbc::owner);

        Ok(output_dbcs)
    }
}

// note: it is planned that a later commit will introduce a
// feature flag for items in mock module, to include:
// SpentBookNodeMock, SimpleKeyManager, SimpleSigner, GenesisBuilderMock
pub mod mock {
    use crate::{
        Amount, Dbc, GenesisDbcShare, KeyManager, MintNode, Result, SimpleKeyManager, SimpleSigner,
        SpentBookNodeMock, SpentProof, SpentProofShare,
    };
    use blsttc::{SecretKeySet, SignatureShare};
    use std::collections::{BTreeMap, BTreeSet};
    use std::iter::FromIterator;

    /// A builder for initializing a set of N mintnodes, a set
    /// of Y spentbooks, and generating a genesis dbc with amount Z.
    ///
    /// In SafeNetwork terms, the set of MintNodes represents a single
    /// Mint section (a) and the set of SpentBooksNodes represents a
    /// single Spentbook section (b).
    pub struct GenesisBuilderMock {
        pub genesis_amount: Amount,
        pub mint_nodes: Vec<MintNode<SimpleKeyManager>>,
        pub spentbook_nodes: Vec<SpentBookNodeMock>,
    }

    impl From<Amount> for GenesisBuilderMock {
        fn from(genesis_amount: Amount) -> Self {
            Self {
                genesis_amount,
                mint_nodes: Default::default(),
                spentbook_nodes: Default::default(),
            }
        }
    }

    impl GenesisBuilderMock {
        /// generates a list of mint nodes sharing a random SecretKeySet and adds to the builder.
        pub fn gen_mint_nodes(
            mut self,
            num_nodes: usize,
            rng: &mut impl rand::RngCore,
        ) -> Result<Self> {
            let sks = SecretKeySet::try_random(num_nodes - 1, rng)?;
            self = self.gen_mint_nodes_with_sks(num_nodes, &sks);
            Ok(self)
        }

        /// generates a list of mint nodes sharing a provided SecretKeySet and adds to the builder.
        pub fn gen_mint_nodes_with_sks(mut self, num_nodes: usize, sks: &SecretKeySet) -> Self {
            for i in 0..num_nodes {
                self.mint_nodes
                    .push(MintNode::new(SimpleKeyManager::from(SimpleSigner::new(
                        sks.public_keys().clone(),
                        (i as u64, sks.secret_key_share(i).clone()),
                    ))));
            }
            self
        }

        /// generates a list of spentbook nodes sharing a random SecretKeySet and adds to the builder.
        pub fn gen_spentbook_nodes(
            mut self,
            num_nodes: usize,
            rng: &mut impl rand::RngCore,
        ) -> Result<Self> {
            let sks = SecretKeySet::try_random(num_nodes - 1, rng)?;
            self = self.gen_spentbook_nodes_with_sks(num_nodes, &sks);
            Ok(self)
        }

        /// generates a list of spentbook nodes sharing a provided SecretKeySet and adds to the builder.
        pub fn gen_spentbook_nodes_with_sks(
            mut self,
            num_nodes: usize,
            sks: &SecretKeySet,
        ) -> Self {
            for i in 0..num_nodes {
                self.spentbook_nodes
                    .push(SpentBookNodeMock::from(SimpleKeyManager::from(
                        SimpleSigner::new(
                            sks.public_keys().clone(),
                            (i as u64, sks.secret_key_share(i).clone()),
                        ),
                    )));
            }
            self
        }

        /// adds an existing mint node to the builder.
        /// All mint nodes must share the same public key
        pub fn add_mint_node(mut self, mint_node: MintNode<SimpleKeyManager>) -> Self {
            if !self.mint_nodes.is_empty() {
                // we only support a single mock mint section.  pubkeys must match.
                assert_eq!(
                    mint_node.key_manager.public_key_set().unwrap().public_key(),
                    self.mint_nodes[0]
                        .key_manager
                        .public_key_set()
                        .unwrap()
                        .public_key()
                );
            }
            self.mint_nodes.push(mint_node);
            self
        }

        /// adds an existing spentbook node to the builder.
        /// All spentbook nodes must share the same public key
        pub fn add_spentbook_node(mut self, spentbook_node: SpentBookNodeMock) -> Self {
            if !self.spentbook_nodes.is_empty() {
                // we only support a single mock spentbook section.  pubkeys must match.
                assert_eq!(
                    spentbook_node
                        .key_manager
                        .public_key_set()
                        .unwrap()
                        .public_key(),
                    self.spentbook_nodes[0]
                        .key_manager
                        .public_key_set()
                        .unwrap()
                        .public_key()
                );
            }
            self.spentbook_nodes.push(spentbook_node);
            self
        }

        /// builds and returns mintnodes, spentbooks, genesis_dbc_shares, and genesis dbc
        #[allow(clippy::type_complexity)]
        pub fn build(
            self,
            rng8_initial: &mut (impl rand8::RngCore + rand_core::CryptoRng + Clone),
        ) -> Result<(
            Vec<MintNode<SimpleKeyManager>>,
            Vec<SpentBookNodeMock>,
            Vec<GenesisDbcShare>,
            Dbc,
        )> {
            let mut spent_proof_shares: Vec<SpentProofShare> = Default::default();
            let mut genesis_set: Vec<GenesisDbcShare> = Default::default();
            let mut mint_nodes: Vec<MintNode<SimpleKeyManager>> = Default::default();
            let mut spentbook_nodes: Vec<SpentBookNodeMock> = Default::default();

            for mint_node in self.mint_nodes.into_iter() {
                // Each MintNode must start from same random seed when issuing Genesis.
                let mut rng8 = rng8_initial.clone();

                let (mut mint_node, genesis_dbc_share) =
                    mint_node.issue_genesis_dbc(self.genesis_amount, &mut rng8)?;

                // note: for our (mock) purposes, all spentbook nodes are validated to
                // have the same public key.  (in the same section)
                let spentbook_node_arbitrary = &self.spentbook_nodes[0];
                mint_node = mint_node.trust_spentbook_public_key(
                    spentbook_node_arbitrary
                        .key_manager
                        .public_key_set()?
                        .public_key(),
                )?;

                mint_nodes.push(mint_node);
                genesis_set.push(genesis_dbc_share);
            }
            let genesis_dbc_share_arbitrary = &genesis_set[0];

            for mut spentbook_node in self.spentbook_nodes.into_iter() {
                spentbook_node.set_genesis(&genesis_dbc_share_arbitrary.ringct_material);
                spent_proof_shares.push(spentbook_node.log_spent(
                    genesis_dbc_share_arbitrary.input_key_image.clone(),
                    genesis_dbc_share_arbitrary.transaction.clone(),
                )?);
                spentbook_nodes.push(spentbook_node);
            }

            // Make a list of (Index, SignatureShare) for combining sigs.
            let node_sigs: Vec<(u64, &SignatureShare)> = genesis_set
                .iter()
                .map(|g| g.transaction_sig.threshold_crypto())
                .collect();

            let mint_node_arbitrary = &mint_nodes[0];

            let mint_sig = mint_node_arbitrary
                .key_manager
                .public_key_set()?
                .combine_signatures(node_sigs)?;

            let spent_sigs: Vec<(u64, &SignatureShare)> = spent_proof_shares
                .iter()
                .map(|s| s.spentbook_sig_share.threshold_crypto())
                .collect();

            let spent_proof_share_arbitrary = &spent_proof_shares[0];

            let spentbook_sig = spent_proof_share_arbitrary
                .spentbook_pks
                .combine_signatures(spent_sigs)?;

            let spent_proofs = BTreeSet::from_iter([SpentProof {
                key_image: spent_proof_share_arbitrary.key_image.clone(),
                spentbook_pub_key: spent_proof_share_arbitrary.spentbook_pks.public_key(),
                spentbook_sig,
                public_commitments: spent_proof_share_arbitrary.public_commitments.clone(),
            }]);

            // Create the Genesis Dbc
            let genesis_dbc = Dbc {
                content: genesis_dbc_share_arbitrary.dbc_content.clone(),
                transaction: genesis_dbc_share_arbitrary.transaction.clone(),
                transaction_sigs: BTreeMap::from_iter([(
                    genesis_dbc_share_arbitrary.input_key_image.clone(),
                    (
                        mint_node_arbitrary
                            .key_manager
                            .public_key_set()?
                            .public_key(),
                        mint_sig,
                    ),
                )]),
                spent_proofs,
            };

            Ok((mint_nodes, spentbook_nodes, genesis_set, genesis_dbc))
        }

        /// builds and returns mintnodes, spentbooks, genesis_dbc_shares, and genesis dbc
        /// the mintnodes use a shared randomly generated SecretKeySet and
        /// the spentbook nodes use a different randomly generated SecretKeySet
        #[allow(clippy::type_complexity)]
        pub fn init_genesis(
            genesis_amount: Amount,
            num_mint_nodes: usize,
            num_spentbook_nodes: usize,
            rng: &mut impl rand::RngCore,
            rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng + Clone),
        ) -> Result<(
            Vec<MintNode<SimpleKeyManager>>,
            Vec<SpentBookNodeMock>,
            Vec<GenesisDbcShare>,
            Dbc,
        )> {
            Self::from(genesis_amount)
                .gen_mint_nodes(num_mint_nodes, rng)?
                .gen_spentbook_nodes(num_spentbook_nodes, rng)?
                .build(rng8)
        }

        /// builds and returns a single mintnode, single spentbook,
        /// single genesis_dbc_shares, and genesis dbc
        /// the mintnode uses a randomly generated SecretKeySet and
        /// the spentbook node uses a different randomly generated SecretKeySet
        #[allow(clippy::type_complexity)]
        pub fn init_genesis_single(
            genesis_amount: Amount,
            rng: &mut impl rand::RngCore,
            rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng + Clone),
        ) -> Result<(
            MintNode<SimpleKeyManager>,
            SpentBookNodeMock,
            GenesisDbcShare,
            Dbc,
        )> {
            let (mint_nodes, spentbook_nodes, genesis_dbc_shares, genesis_dbc) =
                GenesisBuilderMock::from(genesis_amount)
                    .gen_mint_nodes(1, rng)?
                    .gen_spentbook_nodes(1, rng)?
                    .build(rng8)?;

            // Note: these unwraps are safe because the above call returned Ok.
            // We could (stylistically) avoid the unwrap eg mint_nodes[0].clone()
            // but this is more expensive and it would panic anyway if mint_nodes is empty.
            // For library code we would go further, but this is a Mock for testing,
            // so not worth making a never-used Error variant.
            Ok((
                mint_nodes.into_iter().next().unwrap(),
                spentbook_nodes.into_iter().next().unwrap(),
                genesis_dbc_shares.into_iter().next().unwrap(),
                genesis_dbc,
            ))
        }
    }
}
