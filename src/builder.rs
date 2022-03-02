// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blst_ringct::ringct::{Amount, RingCtMaterial, RingCtTransaction};
pub use blst_ringct::{DecoyInput, MlsagMaterial, Output, RevealedCommitment, TrueInput};
use blstrs::group::Curve;
use blsttc::{PublicKey, SecretKey, SignatureShare};
use bulletproofs::PedersenGens;
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    AmountSecrets, Commitment, Dbc, DbcContent, Error, Hash, IndexedSignatureShare, KeyImage,
    KeyManager, OwnerOnce, ReissueRequest, ReissueShare, Result, SpentProof, SpentProofContent,
    SpentProofShare, TransactionVerifier,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type OutputOwnerMap = BTreeMap<PublicKey, OwnerOnce>;

/// A builder to create a RingCt transaction from
/// inputs and outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    ringct_material: RingCtMaterial,
    output_owner_map: OutputOwnerMap,
}

impl TransactionBuilder {
    /// add an input given an MlsagMaterial
    pub fn add_input(mut self, mlsag: MlsagMaterial) -> Self {
        self.ringct_material.inputs.push(mlsag);
        self
    }

    /// add an input given an iterator over MlsagMaterial
    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = MlsagMaterial>) -> Self {
        self.ringct_material.inputs.extend(inputs);
        self
    }

    /// add an input given a TrueInput and decoy list
    pub fn add_input_by_true_input(
        mut self,
        true_input: TrueInput,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Self {
        self.ringct_material
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
    pub fn add_input_dbc(
        mut self,
        dbc: &Dbc,
        base_sk: &SecretKey,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        self = self.add_input_by_true_input(dbc.as_true_input(base_sk)?, decoy_inputs, rng);
        Ok(self)
    }

    /// add an input given a list of Dbcs and associated SecretKey and decoys
    pub fn add_inputs_dbc(
        mut self,
        dbcs: impl IntoIterator<Item = (Dbc, SecretKey, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        for (dbc, base_sk, decoy_inputs) in dbcs.into_iter() {
            self = self.add_input_dbc(&dbc, &base_sk, decoy_inputs, rng)?;
        }
        Ok(self)
    }

    /// add an input given a bearer Dbc, SecretKey and decoy list
    pub fn add_input_dbc_bearer(
        mut self,
        dbc: &Dbc,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        self = self.add_input_by_true_input(dbc.as_true_input_bearer()?, decoy_inputs, rng);
        Ok(self)
    }

    /// add an input given a list of bearer Dbcs and associated SecretKey and decoys
    pub fn add_inputs_dbc_bearer(
        mut self,
        dbcs: impl IntoIterator<Item = (Dbc, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        for (dbc, decoy_inputs) in dbcs.into_iter() {
            self = self.add_input_dbc_bearer(&dbc, decoy_inputs, rng)?;
        }
        Ok(self)
    }

    /// add an input given a SecretKey, AmountSecrets, and list of decoys
    pub fn add_input_by_secrets(
        mut self,
        secret_key: SecretKey,
        amount_secrets: AmountSecrets,
        decoy_inputs: Vec<DecoyInput>,
        rng: &mut impl RngCore,
    ) -> Self {
        let true_input = TrueInput::new(secret_key, amount_secrets.into());

        self.ringct_material
            .inputs
            .push(MlsagMaterial::new(true_input, decoy_inputs, rng));
        self
    }

    /// add an input given a list of (SecretKey, AmountSecrets, and list of decoys)
    pub fn add_inputs_by_secrets(
        mut self,
        secrets: Vec<(SecretKey, AmountSecrets, Vec<DecoyInput>)>,
        rng: &mut impl RngCore,
    ) -> Self {
        for (secret_key, amount_secrets, decoy_inputs) in secrets.into_iter() {
            self = self.add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, rng);
        }
        self
    }

    /// add an output
    pub fn add_output(mut self, output: Output, owner: OwnerOnce) -> Self {
        self.output_owner_map
            .insert(output.public_key().into(), owner);
        self.ringct_material.outputs.push(output);
        self
    }

    /// add a list of outputs
    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = (Output, OwnerOnce)>) -> Self {
        for (output, owner) in outputs.into_iter() {
            self = self.add_output(output, owner);
        }
        self
    }

    /// get a list of input owners
    pub fn input_owners(&self) -> Vec<PublicKey> {
        self.ringct_material
            .public_keys()
            .iter()
            .map(|pk| {
                let pkg1: blsttc::G1Affine = *pk;
                let pk: PublicKey = pkg1.into();
                pk
            })
            .collect()
    }

    /// get sum of input amounts
    pub fn inputs_amount_sum(&self) -> Amount {
        self.ringct_material
            .inputs
            .iter()
            .map(|m| m.true_input.revealed_commitment.value)
            .sum()
    }

    /// get sum of output amounts
    pub fn outputs_amount_sum(&self) -> Amount {
        self.ringct_material.outputs.iter().map(|o| o.amount).sum()
    }

    /// get inputs
    pub fn inputs(&self) -> &Vec<MlsagMaterial> {
        &self.ringct_material.inputs
    }

    /// get outputs
    pub fn outputs(&self) -> &Vec<Output> {
        &self.ringct_material.outputs
    }

    /// build a RingCtTransaction and associated secrets
    pub fn build(
        self,
        rng: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(ReissueRequestBuilder, DbcBuilder, RingCtMaterial)> {
        let result: Result<(RingCtTransaction, Vec<RevealedCommitment>)> =
            self.ringct_material.sign(rng).map_err(|e| e.into());
        let (transaction, revealed_commitments) = result?;

        Ok((
            ReissueRequestBuilder::new(transaction),
            DbcBuilder::new(revealed_commitments, self.output_owner_map),
            self.ringct_material,
        ))
    }
}

/// Builds a ReissueRequest from a RingCtTransaction and
/// any number of (input) DBC spent proof shares.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

    /// Add a SpentProofShare for the given input index
    pub fn add_spent_proof_share(mut self, share: SpentProofShare) -> Self {
        let shares = self
            .spent_proof_shares
            .entry(*share.key_image())
            .or_default();
        shares.insert(share);
        self
    }

    /// Add a list of SpentProofShare for the given input index
    pub fn add_spent_proof_shares(
        mut self,
        shares: impl IntoIterator<Item = SpentProofShare>,
    ) -> Self {
        for share in shares.into_iter() {
            self = self.add_spent_proof_share(share);
        }
        self
    }

    /// returns Vec of key_image and tx intended for use as inputs
    /// to Spendbook::log_spent().
    pub fn inputs(&self) -> Vec<(KeyImage, RingCtTransaction)> {
        self.transaction
            .mlsags
            .iter()
            .map(|mlsag| (mlsag.key_image.into(), self.transaction.clone()))
            .collect()
    }

    /// build a ReissueRequest
    pub fn build(self) -> Result<ReissueRequest> {
        let spent_proofs: BTreeSet<SpentProof> = self
            .spent_proof_shares
            .iter()
            .map(|(key_image, shares)| {
                let any_share = shares
                    .iter()
                    .next()
                    .ok_or(Error::ReissueRequestMissingSpentProofShare(*key_image))?;

                let spentbook_pub_key = any_share.spentbook_pks().public_key();
                let spentbook_sig = any_share.spentbook_pks.combine_signatures(
                    shares
                        .iter()
                        .map(SpentProofShare::spentbook_sig_share)
                        .map(IndexedSignatureShare::threshold_crypto),
                )?;

                let public_commitments: Vec<Commitment> = any_share.public_commitments().clone();

                let spent_proof = SpentProof {
                    content: SpentProofContent {
                        key_image: *key_image,
                        transaction_hash: Hash::from(self.transaction.hash()),
                        public_commitments,
                    },
                    spentbook_pub_key,
                    spentbook_sig,
                };

                Ok(spent_proof)
            })
            .collect::<Result<_>>()?;

        let rr = ReissueRequest {
            transaction: self.transaction,
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
    pub output_owner_map: OutputOwnerMap,

    pub reissue_shares: Vec<ReissueShare>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder
    pub fn new(
        revealed_commitments: Vec<RevealedCommitment>,
        output_owner_map: OutputOwnerMap,
    ) -> Self {
        Self {
            revealed_commitments,
            output_owner_map,
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
    ///
    /// note: common tx verification logic is shared by MintNode::reissue(),
    /// DbcBuilder::build() and Dbc::verify()
    ///
    /// see TransactionVerifier::verify() for a description of
    /// verifier requirements.
    pub fn build<K: KeyManager>(
        self,
        verifier: &K,
    ) -> Result<Vec<(Dbc, OwnerOnce, AmountSecrets)>> {
        let mut mint_sig_shares: Vec<IndexedSignatureShare> = Default::default();

        // This is a map of ReissueShare that must all be exactly the same
        // *except* for the SignatureShare.
        let mut rs_map: HashMap<Vec<u8>, &ReissueShare> = Default::default();

        for rs in self.reissue_shares.iter() {
            // Make a list of IndexedSignatureShare (sigshare from each Mint Node)
            mint_sig_shares.push(rs.mint_signature_share.clone());

            rs_map.insert(rs.to_common_bytes(), rs);
        }

        if rs_map.len() != 1 {
            return Err(Error::ReissueShareMismatch);
        }
        // note: rs will be the last-inserted ReissueShare.
        let rs = match rs_map.values().into_iter().next() {
            Some(rs) => rs,
            None => return Err(Error::ReissueShareMismatch),
        };

        // note: we use only the fields that have been verified to be
        // the same across mint nodes.
        let ReissueShare {
            transaction,
            spent_proofs,
            mint_public_key_set,
            ..
        } = rs;

        // Transform Vec<IndexedSignatureShare> to Vec<u64, &SignatureShare>
        let mint_sig_shares_ref: Vec<(u64, &SignatureShare)> = mint_sig_shares
            .iter()
            .map(|e| e.threshold_crypto())
            .collect();

        // Combine signatures from all the mint nodes to obtain Mint's Signature.
        let mint_sig = mint_public_key_set.combine_signatures(mint_sig_shares_ref)?;

        // note: all output Dbcs share the same mint_sigs
        let mint_sigs = transaction
            .mlsags
            .iter()
            .map(|mlsag| {
                (
                    mlsag.key_image.into(),
                    (mint_public_key_set.public_key(), mint_sig.clone()),
                )
            })
            .collect();

        // verify the Tx, along with mint sigs and spent proofs.
        // note that we do this just once for entire Tx, not once per output Dbc.
        TransactionVerifier::verify(verifier, transaction, &mint_sigs, spent_proofs)?;

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
                self.output_owner_map
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
                    mint_sigs: mint_sigs.clone(),
                    spent_proofs: spent_proofs.clone(),
                };
                (dbc, owner_once.clone(), amount_secrets_list[0].clone())
            })
            .collect();

        Ok(output_dbcs)
    }
}

// note: it is planned that a later commit will introduce a
// feature flag for items in mock module, to include:
// SpentBookNodeMock, SimpleKeyManager, SimpleSigner, GenesisBuilderMock
pub mod mock {
    use crate::{
        Amount, AmountSecrets, Dbc, GenesisMaterial, KeyManager, MintNode, Result,
        SimpleKeyManager, SimpleSigner, SpentBookNodeMock, TransactionBuilder,
    };
    use blsttc::SecretKeySet;

    /// A builder for initializing a set of N mintnodes, a set
    /// of Y spentbooks, and generating a genesis dbc with amount Z.
    ///
    /// In SafeNetwork terms, the set of MintNodes represents a single
    /// Mint section (a) and the set of SpentBooksNodes represents a
    /// single Spentbook section (b).
    #[derive(Default)]
    pub struct GenesisBuilderMock {
        pub genesis_amount: Amount,
        pub mint_nodes: Vec<MintNode<SimpleKeyManager>>,
        pub spentbook_nodes: Vec<SpentBookNodeMock>,
    }

    impl GenesisBuilderMock {
        /// generates a list of mint nodes sharing a random SecretKeySet and adds to the builder.
        pub fn gen_mint_nodes(
            mut self,
            num_nodes: usize,
            rng: &mut impl rand8::RngCore,
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
            rng: &mut impl rand8::RngCore,
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
            mut self,
            rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng),
        ) -> Result<(
            Vec<MintNode<SimpleKeyManager>>,
            Vec<SpentBookNodeMock>,
            Dbc,
            GenesisMaterial,
            AmountSecrets,
        )> {
            let mut mint_nodes: Vec<MintNode<SimpleKeyManager>> = Default::default();

            // note: rng is necessary for RingCtMaterial::sign().

            let genesis_material = GenesisMaterial::default();
            let (mut rr_builder, mut dbc_builder, _ringct_material) = TransactionBuilder::default()
                .add_input(genesis_material.ringct_material.inputs[0].clone())
                .add_output(
                    genesis_material.ringct_material.outputs[0].clone(),
                    genesis_material.owner_once.clone(),
                )
                .build(rng8)?;

            for (key_image, tx) in rr_builder.inputs() {
                for spentbook_node in self.spentbook_nodes.iter_mut() {
                    rr_builder = rr_builder
                        .add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?);
                }
            }

            let reissue_request = rr_builder.build()?;

            for mint_node in self.mint_nodes.into_iter() {
                // note: for our (mock) purposes, all spentbook nodes are verified to
                // have the same public key.  (in the same section)
                let spentbook_node_arbitrary = &self.spentbook_nodes[0];
                let mint_node = mint_node.trust_spentbook_public_key(
                    spentbook_node_arbitrary
                        .key_manager
                        .public_key_set()?
                        .public_key(),
                )?;

                dbc_builder =
                    dbc_builder.add_reissue_share(mint_node.reissue(reissue_request.clone())?);
                mint_nodes.push(mint_node);
            }

            // note: for our (mock) purposes, all mint nodes are verified to
            // have the same public key.  (in the same section)
            let mint_node_arbitrary = &mint_nodes[0];

            let (genesis_dbc, _owner_once, amount_secrets) = dbc_builder
                .build(mint_node_arbitrary.key_manager())?
                .into_iter()
                .next()
                .unwrap();
            Ok((
                mint_nodes,
                self.spentbook_nodes,
                genesis_dbc,
                genesis_material,
                amount_secrets,
            ))
        }

        /// builds and returns mintnodes, spentbooks, genesis_dbc_shares, and genesis dbc
        /// the mintnodes use a shared randomly generated SecretKeySet and
        /// the spentbook nodes use a different randomly generated SecretKeySet
        #[allow(clippy::type_complexity)]
        pub fn init_genesis(
            num_mint_nodes: usize,
            num_spentbook_nodes: usize,
            rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng),
        ) -> Result<(
            Vec<MintNode<SimpleKeyManager>>,
            Vec<SpentBookNodeMock>,
            Dbc,
            GenesisMaterial,
            AmountSecrets,
        )> {
            Self::default()
                .gen_mint_nodes(num_mint_nodes, rng8)?
                .gen_spentbook_nodes(num_spentbook_nodes, rng8)?
                .build(rng8)
        }

        /// builds and returns a single mintnode, single spentbook,
        /// single genesis_dbc_shares, and genesis dbc
        /// the mintnode uses a randomly generated SecretKeySet and
        /// the spentbook node uses a different randomly generated SecretKeySet
        #[allow(clippy::type_complexity)]
        pub fn init_genesis_single(
            rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng),
        ) -> Result<(
            MintNode<SimpleKeyManager>,
            SpentBookNodeMock,
            Dbc,
            GenesisMaterial,
            AmountSecrets,
        )> {
            let (mint_nodes, spentbook_nodes, genesis_dbc, genesis_material, amount_secrets) =
                Self::default()
                    .gen_mint_nodes(1, rng8)?
                    .gen_spentbook_nodes(1, rng8)?
                    .build(rng8)?;

            // Note: these unwraps are safe because the above call returned Ok.
            // We could (stylistically) avoid the unwrap eg mint_nodes[0].clone()
            // but this is more expensive and it would panic anyway if mint_nodes is empty.
            // For library code we would go further, but this is a Mock for testing,
            // so not worth making a never-used Error variant.
            Ok((
                mint_nodes.into_iter().next().unwrap(),
                spentbook_nodes.into_iter().next().unwrap(),
                genesis_dbc,
                genesis_material,
                amount_secrets,
            ))
        }
    }
}
