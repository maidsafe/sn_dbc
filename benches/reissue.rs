#![allow(clippy::from_iter_instead_of_collect)]

use sn_dbc::{
    Amount, DbcBuilder, GenesisBuilderMock, KeyImage, Owner, OwnerOnce, ReissueRequestBuilder,
    SpentProofShare,
};

use blst_ringct::Output;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::SeedableRng;
use rand8::SeedableRng as SeedableRng8;

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

    let n_outputs: u32 = 100;
    let (mintnode, mut spentbook, _genesis_dbc_share, genesis_dbc) =
        GenesisBuilderMock::init_genesis_single(n_outputs as u64, &mut rng, &mut rng8).unwrap();

    let (reissue_tx, _revealed_commitments, _material, _output_owners) =
        sn_dbc::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis_dbc
                    .owner_once_bearer()
                    .unwrap()
                    .secret_key_blst()
                    .unwrap(),
                genesis_dbc.amount_secrets_bearer().unwrap(),
                vec![], // never any decoys for genesis
                &mut rng8,
            )
            .add_outputs((0..n_outputs).into_iter().map(|_| {
                let owner_once =
                    OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);
                (
                    Output {
                        amount: 1,
                        public_key: owner_once.as_owner().public_key_blst(),
                    },
                    owner_once,
                )
            }))
            .build(&mut rng8)
            .unwrap();

    let genesis_key_image: KeyImage = reissue_tx.mlsags[0].key_image.into();
    let spent_proof_share = spentbook
        .log_spent(genesis_key_image, reissue_tx.clone())
        .unwrap();

    let rr = ReissueRequestBuilder::new(reissue_tx)
        .add_spent_proof_share(0, spent_proof_share)
        .build()
        .unwrap();

    c.bench_function(&format!("reissue split 1 to {}", n_outputs), |b| {
        b.iter(|| {
            mintnode.reissue(black_box(rr.clone())).unwrap();
        })
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let num_decoys = 0;

    let n_outputs: u32 = 100;
    let (mintnode, mut spentbook, _genesis_dbc_share, genesis_dbc) =
        GenesisBuilderMock::init_genesis_single(n_outputs as u64, &mut rng, &mut rng8).unwrap();

    let (reissue_tx, revealed_commitments, _material, output_owners) =
        sn_dbc::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis_dbc
                    .owner_once_bearer()
                    .unwrap()
                    .secret_key_blst()
                    .unwrap(),
                genesis_dbc.amount_secrets_bearer().unwrap(),
                vec![], // never any decoy inputs for genesis
                &mut rng8,
            )
            .add_outputs((0..n_outputs).into_iter().map(|_| {
                let owner_once =
                    OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);
                (
                    Output {
                        amount: 1,
                        public_key: owner_once.as_owner().public_key_blst(),
                    },
                    owner_once,
                )
            }))
            .build(&mut rng8)
            .unwrap();

    let genesis_key_image: KeyImage = reissue_tx.mlsags[0].key_image.into();
    let spent_proof_share = spentbook
        .log_spent(genesis_key_image, reissue_tx.clone())
        .unwrap();

    let rr = ReissueRequestBuilder::new(reissue_tx)
        .add_spent_proof_share(0, spent_proof_share)
        .build()
        .unwrap();

    let reissue_share = mintnode.reissue(rr).unwrap();

    let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
    dbc_builder = dbc_builder.add_reissue_share(reissue_share);
    let dbcs = dbc_builder.build().unwrap();

    let output_owner_once =
        OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);

    let (merge_tx, _revealed_commitments, _material, _output_owners) =
        sn_dbc::TransactionBuilder::default()
            .add_inputs_by_secrets(
                dbcs.into_iter()
                    .map(|(_dbc, owner_once, amount_secrets)| {
                        (
                            owner_once.as_owner().secret_key_blst().unwrap(),
                            amount_secrets,
                            spentbook.random_decoys(num_decoys, &mut rng8),
                        )
                    })
                    .collect(),
                &mut rng8,
            )
            .add_output(
                Output {
                    amount: n_outputs as Amount,
                    public_key: output_owner_once.as_owner().public_key_blst(),
                },
                output_owner_once,
            )
            .build(&mut rng8)
            .unwrap();

    let spent_proof_shares: Vec<(usize, SpentProofShare)> = merge_tx
        .mlsags
        .iter()
        .enumerate()
        .map(|(i, m)| {
            (
                i,
                spentbook
                    .log_spent(m.key_image.into(), merge_tx.clone())
                    .unwrap(),
            )
        })
        .collect();

    let merge_rr = ReissueRequestBuilder::new(merge_tx)
        .add_spent_proof_shares(spent_proof_shares)
        .build()
        .unwrap();

    c.bench_function(&format!("reissue merge {} to 1", n_outputs), |b| {
        b.iter(|| {
            mintnode.reissue(black_box(merge_rr.clone())).unwrap();
        })
    });
}

criterion_group! {
    name = reissue;
    config = Criterion::default().sample_size(10);
    targets = bench_reissue_1_to_100, bench_reissue_100_to_1
}

criterion_main!(reissue);
