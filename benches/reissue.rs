// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(clippy::from_iter_instead_of_collect)]

use sn_dbc::{
    Amount, Dbc, GenesisBuilderMock, MintNode, Owner, OwnerOnce, Result, SimpleKeyManager,
    SpentBookNodeMock,
};

use blst_ringct::Output;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand8::SeedableRng as SeedableRng8;

const N_OUTPUTS: u32 = 100;

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

    let (mintnode, mut spentbook, starting_dbc) =
        generate_dbc_of_value(N_OUTPUTS as Amount, &mut rng8).unwrap();

    let (mut rr_builder, ..) = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            starting_dbc
                .owner_once_bearer()
                .unwrap()
                .secret_key()
                .unwrap(),
            starting_dbc.amount_secrets_bearer().unwrap(),
            vec![], // never any decoys for genesis
            &mut rng8,
        )
        .add_outputs((0..N_OUTPUTS).into_iter().map(|_| {
            let owner_once =
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);
            (
                Output::new(owner_once.as_owner().public_key(), 1),
                owner_once,
            )
        }))
        .build(&mut rng8)
        .unwrap();

    for (key_image, tx) in rr_builder.inputs() {
        let spent_proof_share = spentbook.log_spent(key_image, tx).unwrap();
        rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
    }
    let rr = rr_builder.build().unwrap();

    c.bench_function(&format!("reissue split 1 to {}", N_OUTPUTS), |b| {
        b.iter(|| {
            mintnode.reissue(black_box(rr.clone())).unwrap();
        })
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
    let num_decoys = 0;

    let (mintnode, mut spentbook, starting_dbc) =
        generate_dbc_of_value(N_OUTPUTS as Amount, &mut rng8).unwrap();

    let (mut rr_builder, mut dbc_builder, ..) = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            starting_dbc
                .owner_once_bearer()
                .unwrap()
                .secret_key()
                .unwrap(),
            starting_dbc.amount_secrets_bearer().unwrap(),
            vec![], // never any decoy inputs for genesis
            &mut rng8,
        )
        .add_outputs((0..N_OUTPUTS).into_iter().map(|_| {
            let owner_once =
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);
            (
                Output::new(owner_once.as_owner().public_key(), 1),
                owner_once,
            )
        }))
        .build(&mut rng8)
        .unwrap();

    for (key_image, tx) in rr_builder.inputs() {
        let spent_proof_share = spentbook.log_spent(key_image, tx).unwrap();
        rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
    }
    let rr = rr_builder.build().unwrap();

    let reissue_share = mintnode.reissue(rr).unwrap();

    dbc_builder = dbc_builder.add_reissue_share(reissue_share);
    let dbcs = dbc_builder.build(mintnode.key_manager()).unwrap();

    let output_owner_once =
        OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);

    let (mut merge_rr_builder, ..) = sn_dbc::TransactionBuilder::default()
        .add_inputs_by_secrets(
            dbcs.into_iter()
                .map(|(_dbc, owner_once, amount_secrets)| {
                    (
                        owner_once.as_owner().secret_key().unwrap(),
                        amount_secrets,
                        spentbook.random_decoys(num_decoys, &mut rng8),
                    )
                })
                .collect(),
            &mut rng8,
        )
        .add_output(
            Output::new(
                output_owner_once.as_owner().public_key(),
                N_OUTPUTS as Amount,
            ),
            output_owner_once,
        )
        .build(&mut rng8)
        .unwrap();

    for (key_image, tx) in merge_rr_builder.inputs() {
        let spent_proof_share = spentbook.log_spent(key_image, tx).unwrap();
        merge_rr_builder = merge_rr_builder.add_spent_proof_share(spent_proof_share);
    }
    let merge_rr = merge_rr_builder.build().unwrap();

    c.bench_function(&format!("reissue merge {} to 1", N_OUTPUTS), |b| {
        b.iter(|| {
            mintnode.reissue(black_box(merge_rr.clone())).unwrap();
        })
    });
}

fn generate_dbc_of_value(
    amount: Amount,
    rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng),
) -> Result<(MintNode<SimpleKeyManager>, SpentBookNodeMock, Dbc)> {
    let (mint_node, mut spentbook_node, genesis_dbc, _genesis_material, _amount_secrets) =
        GenesisBuilderMock::init_genesis_single(rng8)?;

    let output_amounts = vec![amount, sn_dbc::GenesisMaterial::GENESIS_AMOUNT - amount];

    let (mut rr_builder, mut dbc_builder, _material) = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            genesis_dbc.owner_once_bearer()?.secret_key()?,
            genesis_dbc.amount_secrets_bearer()?,
            vec![], // never any decoys for genesis
            rng8,
        )
        .add_outputs(output_amounts.into_iter().map(|amount| {
            let owner_once = OwnerOnce::from_owner_base(Owner::from_random_secret_key(rng8), rng8);
            (
                Output::new(owner_once.as_owner().public_key(), amount),
                owner_once,
            )
        }))
        .build(rng8)?;

    // Build ReissuRequest
    for (key_image, tx) in rr_builder.inputs() {
        let spent_proof_share = spentbook_node.log_spent(key_image, tx)?;
        rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
    }
    let rr = rr_builder.build()?;

    let reissue_share = mint_node.reissue(rr)?;
    dbc_builder = dbc_builder.add_reissue_share(reissue_share);
    let (starting_dbc, ..) = dbc_builder
        .build(mint_node.key_manager())?
        .into_iter()
        .next()
        .unwrap();

    Ok((mint_node, spentbook_node, starting_dbc))
}

criterion_group! {
    name = reissue;
    config = Criterion::default().sample_size(10);
    targets = bench_reissue_1_to_100, bench_reissue_100_to_1
}

criterion_main!(reissue);
