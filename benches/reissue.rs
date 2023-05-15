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
use std::collections::{BTreeMap, BTreeSet};

const N_OUTPUTS: u64 = 100;

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let mut rng = rng::from_seed([0u8; 32]);

    let (mut spentbook_node, (starting_dbc, starting_main_key)) =
        generate_dbc_of_value(Token::from_nano(N_OUTPUTS), &mut rng).unwrap();

    let derived_key = starting_dbc.derived_key(&starting_main_key).unwrap();
    let dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_dbc(&starting_dbc, &derived_key)
        .unwrap()
        .add_outputs((0..N_OUTPUTS).map(|_| {
            (
                Token::from_nano(1),
                MainKey::random_from_rng(&mut rng).random_dbc_id_src(&mut rng),
            )
        }))
        .build(Hash::default(), &mut rng)
        .unwrap();

    let spent_tx = &dbc_builder.spent_tx;
    for signed_spend in dbc_builder.signed_spends() {
        spentbook_node.log_spent(spent_tx, signed_spend).unwrap();
    }

    let signed_spends: BTreeSet<_> = dbc_builder.signed_spends().into_iter().cloned().collect();

    c.bench_function(&format!("reissue split 1 to {N_OUTPUTS}"), |b| {
        #[cfg(unix)]
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(black_box(spent_tx), &signed_spends).unwrap();
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

    let derived_key = starting_dbc.derived_key(&starting_main_key).unwrap();
    let dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_dbc(&starting_dbc, &derived_key)
        .unwrap()
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
        .build(Hash::default(), &mut rng)
        .unwrap();

    let spent_tx = dbc_builder.spent_tx.clone();
    for signed_spend in dbc_builder.signed_spends() {
        spentbook_node.log_spent(&spent_tx, signed_spend).unwrap();
    }
    let dbcs = dbc_builder.build().unwrap();

    let main_key = MainKey::random_from_rng(&mut rng);
    let derivation_index = random_derivation_index(&mut rng);

    let mut tx_builder = sn_dbc::TransactionBuilder::default();

    for (dbc, _) in dbcs.into_iter() {
        let (main_key, _, _) = outputs.get(&dbc.id()).unwrap();
        let derived_key = dbc.derived_key(main_key).unwrap();
        tx_builder = tx_builder.add_input_dbc(&dbc, &derived_key).unwrap();
    }

    let merge_dbc_builder = tx_builder
        .add_output(
            Token::from_nano(N_OUTPUTS),
            DbcIdSource {
                public_address: main_key.public_address(),
                derivation_index,
            },
        )
        .build(Hash::default(), &mut rng)
        .unwrap();

    let merge_spent_tx = merge_dbc_builder.spent_tx.clone();
    for signed_spend in merge_dbc_builder.signed_spends() {
        spentbook_node
            .log_spent(&merge_spent_tx, signed_spend)
            .unwrap();
    }

    let signed_spends: BTreeSet<_> = merge_dbc_builder
        .signed_spends()
        .into_iter()
        .cloned()
        .collect();

    c.bench_function(&format!("reissue merge {N_OUTPUTS} to 1"), |b| {
        #[cfg(unix)]
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(black_box(&merge_spent_tx), &signed_spends).unwrap();
        });

        #[cfg(unix)]
        if let Ok(report) = guard.report().build() {
            let file =
                std::fs::File::create(format!("reissue_merge_{N_OUTPUTS}_to_1.svg")).unwrap();
            report.flamegraph(file).unwrap();
        };
    });
}

#[allow(clippy::result_large_err)]
fn generate_dbc_of_value(
    amount: Token,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(mock::SpentbookNode, (Dbc, MainKey))> {
    let (mut spentbook_node, genesis_dbc, genesis_material, _revealed_amount) =
        mock::GenesisBuilder::init_genesis_single(rng)?;

    let output_amounts = vec![
        amount,
        Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount.as_nano()),
    ];

    let main_key = MainKey::random_from_rng(rng);

    let derived_key = genesis_dbc.derived_key(&genesis_material.main_key).unwrap();
    let dbc_builder = sn_dbc::TransactionBuilder::default()
        .add_input_dbc(&genesis_dbc, &derived_key)
        .unwrap()
        .add_outputs(output_amounts.into_iter().map(|amount| {
            (
                amount,
                DbcIdSource {
                    public_address: main_key.public_address(),
                    derivation_index: random_derivation_index(rng),
                },
            )
        }))
        .build(Hash::default(), rng)?;

    let tx = dbc_builder.spent_tx.clone();
    for signed_spend in dbc_builder.signed_spends() {
        spentbook_node.log_spent(&tx, signed_spend)?;
    }

    let (starting_dbc, ..) = dbc_builder.build()?.into_iter().next().unwrap();

    Ok((spentbook_node, (starting_dbc, main_key)))
}

criterion_group! {
    name = reissue;
    config = Criterion::default().sample_size(10);
    targets = bench_reissue_1_to_100, bench_reissue_100_to_1
}

criterion_main!(reissue);
