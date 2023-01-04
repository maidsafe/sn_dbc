// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::GenesisMaterial;
use crate::{
    mock,
    rand::{CryptoRng, RngCore},
    AmountSecrets, Dbc, Result, TransactionBuilder,
};
use blsttc::SecretKeySet;

/// A builder for initializing a set of N spentbooks and generating a
/// genesis dbc with amount Z.
///
/// In SafeNetwork terms, the set of SpentBooksNodes represents a
/// single Spentbook section.
#[derive(Default)]
pub struct GenesisBuilder {
    pub spentbook_nodes: Vec<mock::SpentBookNode>,
}

impl GenesisBuilder {
    /// generates a list of spentbook nodes sharing a random SecretKeySet and adds to the builder.
    pub fn gen_spentbook_nodes(
        mut self,
        num_nodes: usize,
        rng: &mut impl crate::rand::RngCore,
    ) -> Result<Self> {
        let sks = SecretKeySet::try_random(num_nodes - 1, rng)?;
        self = self.gen_spentbook_nodes_with_sks(num_nodes, &sks);
        Ok(self)
    }

    /// generates a list of spentbook nodes sharing a provided SecretKeySet and adds to the builder.
    pub fn gen_spentbook_nodes_with_sks(mut self, num_nodes: usize, sks: &SecretKeySet) -> Self {
        for i in 0..num_nodes {
            self.spentbook_nodes
                .push(mock::SpentBookNode::from(mock::KeyManager::from(
                    mock::Signer::new(
                        sks.public_keys().clone(),
                        (i as u64, sks.secret_key_share(i).clone()),
                    ),
                )));
        }
        self
    }

    /// adds an existing spentbook node to the builder.
    /// All spentbook nodes must share the same public key
    pub fn add_spentbook_node(mut self, spentbook_node: mock::SpentBookNode) -> Self {
        if !self.spentbook_nodes.is_empty() {
            // we only support a single mock spentbook section.  pubkeys must match.
            assert_eq!(
                spentbook_node.key_manager.public_key_set().public_key(),
                self.spentbook_nodes[0]
                    .key_manager
                    .public_key_set()
                    .public_key()
            );
        }
        self.spentbook_nodes.push(spentbook_node);
        self
    }

    /// builds and returns spentbooks, genesis_dbc_shares, and genesis dbc
    #[allow(clippy::type_complexity)]
    pub fn build(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(
        Vec<mock::SpentBookNode>,
        Dbc,
        GenesisMaterial,
        AmountSecrets,
    )> {
        // note: rng is necessary for RingCtMaterial::sign().

        let genesis_material = GenesisMaterial::default();
        let mut dbc_builder = TransactionBuilder::default()
            .add_input(genesis_material.ringct_material.inputs[0].clone())
            .add_output(
                genesis_material.ringct_material.outputs[0].clone(),
                genesis_material.owner_once.clone(),
            )
            .build(rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            for spentbook_node in self.spentbook_nodes.iter_mut() {
                dbc_builder = dbc_builder
                    .add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?);
            }
            dbc_builder = dbc_builder.add_spent_transaction(tx);
        }

        // note: for our (mock) purposes, all spentbook nodes are verified to
        // have the same public key.  (in the same section)
        let spentbook_node_arbitrary = &self.spentbook_nodes[0];

        let (genesis_dbc, _owner_once, amount_secrets) = dbc_builder
            .build(&spentbook_node_arbitrary.key_manager)?
            .into_iter()
            .next()
            .unwrap();
        Ok((
            self.spentbook_nodes,
            genesis_dbc,
            genesis_material,
            amount_secrets,
        ))
    }

    /// builds and returns spentbooks, genesis_dbc_shares, and genesis dbc
    /// the spentbook nodes use a shared randomly generated SecretKeySet
    #[allow(clippy::type_complexity)]
    pub fn init_genesis(
        num_spentbook_nodes: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(
        Vec<mock::SpentBookNode>,
        Dbc,
        GenesisMaterial,
        AmountSecrets,
    )> {
        Self::default()
            .gen_spentbook_nodes(num_spentbook_nodes, rng)?
            .build(rng)
    }

    /// builds and returns a single spentbook, single genesis_dbc_shares,
    /// and genesis dbc.
    /// the spentbook node uses a shared randomly generated SecretKeySet
    #[allow(clippy::type_complexity)]
    pub fn init_genesis_single(
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, GenesisMaterial, AmountSecrets)> {
        let (spentbook_nodes, genesis_dbc, genesis_material, amount_secrets) =
            Self::default().gen_spentbook_nodes(1, rng)?.build(rng)?;

        // Note: these unwraps are safe because the above call returned Ok.
        // We could (stylistically) avoid the unwrap eg spentbook_nodes[0].clone()
        // but this is more expensive and it would panic anyway if spentbook_nodes is empty.
        // For library code we would go further, but this is a  for testing,
        // so not worth making a never-used Error variant.
        Ok((
            spentbook_nodes.into_iter().next().unwrap(),
            genesis_dbc,
            genesis_material,
            amount_secrets,
        ))
    }
}
