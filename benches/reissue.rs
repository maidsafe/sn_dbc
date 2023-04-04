// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(clippy::from_iter_instead_of_collect)]

use sn_dbc::{
    mock,
    rand::{CryptoRng, RngCore},
    random_derivation_index, rng, Dbc, DbcIdSource, Hash, MainKey, Result, Token,
    TransactionVerifier,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::BTreeMap;

const N_OUTPUTS: u64 = 100;

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let mut rng = rng::from_seed([0u8; 32]);

    let (mut spentbook, (starting_dbc, starting_main_key)) =
        generate_dbc_of_value(Token::from_nano(N_OUTPUTS), &mut rng).unwrap();

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            starting_dbc.derived_key(&starting_main_key).unwrap(),
            starting_dbc.revealed_amount(&starting_main_key).unwrap(),
        )
        .add_outputs((0..N_OUTPUTS).map(|_| {
            (
                Token::from_nano(1),
                MainKey::random_from_rng(&mut rng).random_dbc_id_src(&mut rng),
            )
        }))
        .build(&mut rng)
        .unwrap();

    for (public_key, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook
            .log_spent(public_key, tx, Hash::default())
            .unwrap();
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let spent_proofs = dbc_builder.spent_proofs().unwrap();
    let tx = &dbc_builder.transaction;

    c.bench_function(&format!("reissue split 1 to {N_OUTPUTS}"), |b| {
        #[cfg(unix)]
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(&spentbook.key_manager, black_box(tx), &spent_proofs)
                .unwrap();
        });

        #[cfg(unix)]
        if let Ok(report) = guard.report().build() {
            let file =
                std::fs::File::create(format!("reissue_split_1_to_{N_OUTPUTS}.svg")).unwrap();
            report.flamegraph(file).unwrap();
        };
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let mut rng = rng::from_seed([0u8; 32]);

    let (mut spentbook_node, (starting_dbc, starting_main_key)) =
        generate_dbc_of_value(Token::from_nano(N_OUTPUTS), &mut rng).unwrap();

    let outputs: BTreeMap<_, _> = (0..N_OUTPUTS)
        .map(|_| {
            let main_key = MainKey::random_from_rng(&mut rng);
            let derivation_index = random_derivation_index(&mut rng);
            let dbc_id = main_key.derive_key(&derivation_index).dbc_id();
            (dbc_id, (main_key, derivation_index, Token::from_nano(1)))
        })
        .collect();

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            starting_dbc.derived_key(&starting_main_key).unwrap(),
            starting_dbc.revealed_amount(&starting_main_key).unwrap(),
        )
        .add_outputs(
            outputs
                .iter()
                .map(|(_, (main_key, derivation_index, amount))| {
                    (
                        *amount,
                        DbcIdSource {
                            public_address: main_key.public_address(),
                            derivation_index: *derivation_index,
                        },
                    )
                }),
        )
        .build(&mut rng)
        .unwrap();

    for (public_key, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook_node
            .log_spent(public_key, tx, Hash::default())
            .unwrap();
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }
    let dbcs = dbc_builder.build(&spentbook_node.key_manager).unwrap();

    let main_key = MainKey::random_from_rng(&mut rng);
    let derivation_index = random_derivation_index(&mut rng);

    let mut merge_dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_inputs_by_secrets(
            dbcs.into_iter()
                .map(|(dbc, revealed_amount)| {
                    let (main_key, _, _) = outputs.get(&dbc.id()).unwrap();
                    (dbc.derived_key(main_key).unwrap(), revealed_amount)
                })
                .collect(),
        )
        .add_output(
            Token::from_nano(N_OUTPUTS),
            DbcIdSource {
                public_address: main_key.public_address(),
                derivation_index,
            },
        )
        .build(&mut rng)
        .unwrap();

    for (public_key, tx) in merge_dbc_builder.inputs() {
        let spent_proof_share = spentbook_node
            .log_spent(public_key, tx, Hash::default())
            .unwrap();
        merge_dbc_builder = merge_dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let spent_proofs = merge_dbc_builder.spent_proofs().unwrap();
    let tx = &merge_dbc_builder.transaction;

    c.bench_function(&format!("reissue merge {N_OUTPUTS} to 1"), |b| {
        #[cfg(unix)]
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(&spentbook_node.key_manager, black_box(tx), &spent_proofs)
                .unwrap();
        });

        #[cfg(unix)]
        if let Ok(report) = guard.report().build() {
            let file =
                std::fs::File::create(format!("reissue_merge_{N_OUTPUTS}_to_1.svg")).unwrap();
            report.flamegraph(file).unwrap();
        };
    });
}

fn generate_dbc_of_value(
    amount: Token,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(mock::SpentBookNode, (Dbc, MainKey))> {
    let (mut spentbook_node, genesis_dbc, genesis_material, _revealed_amount) =
        mock::GenesisBuilder::init_genesis_single(rng)?;

    let output_amounts = vec![
        amount,
        Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount.as_nano()),
    ];

    let main_key = MainKey::random_from_rng(rng);

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_by_secrets(
            genesis_material.derived_key,
            genesis_dbc.revealed_amount(&genesis_material.main_key)?,
        )
        .add_outputs(output_amounts.into_iter().map(|amount| {
            (
                amount,
                DbcIdSource {
                    public_address: main_key.public_address(),
                    derivation_index: random_derivation_index(rng),
                },
            )
        }))
        .build(rng)?;

    for (public_key, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook_node.log_spent(public_key, tx, Hash::default())?;
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let (starting_dbc, ..) = dbc_builder
        .build(&spentbook_node.key_manager)?
        .into_iter()
        .next()
        .unwrap();

    Ok((spentbook_node, (starting_dbc, main_key)))
}

criterion_group! {
    name = reissue;
    config = Criterion::default().sample_size(10);
    targets = bench_reissue_1_to_100, bench_reissue_100_to_1
}

criterion_main!(reissue);
