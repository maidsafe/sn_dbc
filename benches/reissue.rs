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
    rng, Dbc, Owner, OwnerOnce, Result, Token, TransactionVerifier,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

const N_OUTPUTS: u64 = 100;

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let mut rng = rng::from_seed([0u8; 32]);

    let (mut spentbook, starting_dbc) =
        generate_dbc_of_value(Token::from_nano(N_OUTPUTS), &mut rng).unwrap();

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .set_require_all_decoys(false) // no decoys!
        .add_input_by_secrets(
            starting_dbc
                .owner_once_bearer()
                .unwrap()
                .secret_key()
                .unwrap(),
            starting_dbc.amount_secrets_bearer().unwrap(),
        )
        .add_outputs_by_amount((0..N_OUTPUTS).into_iter().map(|_| {
            let owner_once =
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);
            (Token::from_nano(1), owner_once)
        }))
        .build(&mut rng)
        .unwrap();

    for (key_image, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook.log_spent(key_image, tx).unwrap();
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let spent_proofs = dbc_builder.spent_proofs().unwrap();
    let tx = &dbc_builder.transaction;

    c.bench_function(&format!("reissue split 1 to {}", N_OUTPUTS), |b| {
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(&spentbook.key_manager, black_box(tx), &spent_proofs)
                .unwrap();
        });

        if let Ok(report) = guard.report().build() {
            let file =
                std::fs::File::create(format!("reissue_split_1_to_{}.svg", N_OUTPUTS)).unwrap();
            report.flamegraph(file).unwrap();
        };
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let mut rng = rng::from_seed([0u8; 32]);

    let (mut spentbook_node, starting_dbc) =
        generate_dbc_of_value(Token::from_nano(N_OUTPUTS), &mut rng).unwrap();

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .set_require_all_decoys(false) // no decoys!
        .add_input_by_secrets(
            starting_dbc
                .owner_once_bearer()
                .unwrap()
                .secret_key()
                .unwrap(),
            starting_dbc.amount_secrets_bearer().unwrap(),
        )
        .add_outputs_by_amount((0..N_OUTPUTS).into_iter().map(|_| {
            let owner_once =
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);
            (Token::from_nano(1), owner_once)
        }))
        .build(&mut rng)
        .unwrap();

    for (key_image, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook_node.log_spent(key_image, tx).unwrap();
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }
    let dbcs = dbc_builder.build(&spentbook_node.key_manager).unwrap();

    let output_owner_once =
        OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

    let mut merge_dbc_builder = sn_dbc::TransactionBuilder::default()
        .set_require_all_decoys(false) // no decoys!
        .add_inputs_by_secrets(
            dbcs.into_iter()
                .map(|(_dbc, owner_once, amount_secrets)| {
                    (owner_once.as_owner().secret_key().unwrap(), amount_secrets)
                })
                .collect(),
        )
        .add_output_by_amount(Token::from_nano(N_OUTPUTS), output_owner_once)
        .build(&mut rng)
        .unwrap();

    for (key_image, tx) in merge_dbc_builder.inputs() {
        let spent_proof_share = spentbook_node.log_spent(key_image, tx).unwrap();
        merge_dbc_builder = merge_dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let spent_proofs = merge_dbc_builder.spent_proofs().unwrap();
    let tx = &merge_dbc_builder.transaction;

    c.bench_function(&format!("reissue merge {} to 1", N_OUTPUTS), |b| {
        let guard = pprof::ProfilerGuard::new(100).unwrap();

        b.iter(|| {
            TransactionVerifier::verify(&spentbook_node.key_manager, black_box(tx), &spent_proofs)
                .unwrap();
        });

        if let Ok(report) = guard.report().build() {
            let file =
                std::fs::File::create(format!("reissue_merge_{}_to_1.svg", N_OUTPUTS)).unwrap();
            report.flamegraph(file).unwrap();
        };
    });
}

fn generate_dbc_of_value(
    amount: Token,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(mock::SpentBookNode, Dbc)> {
    let (mut spentbook_node, genesis_dbc, _genesis_material, _amount_secrets) =
        mock::GenesisBuilder::init_genesis_single(rng)?;

    let output_amounts = vec![
        amount,
        Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount.as_nano()),
    ];

    let mut dbc_builder = sn_dbc::TransactionBuilder::default()
        .set_require_all_decoys(false) // no decoys!
        .add_input_by_secrets(
            genesis_dbc.owner_once_bearer()?.secret_key()?,
            genesis_dbc.amount_secrets_bearer()?,
        )
        .add_outputs_by_amount(output_amounts.into_iter().map(|amount| {
            let owner_once = OwnerOnce::from_owner_base(Owner::from_random_secret_key(rng), rng);
            (amount, owner_once)
        }))
        .build(rng)?;

    for (key_image, tx) in dbc_builder.inputs() {
        let spent_proof_share = spentbook_node.log_spent(key_image, tx)?;
        dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
    }

    let (starting_dbc, ..) = dbc_builder
        .build(&spentbook_node.key_manager)?
        .into_iter()
        .next()
        .unwrap();

    Ok((spentbook_node, starting_dbc))
}

criterion_group! {
    name = reissue;
    config = Criterion::default().sample_size(10);
    targets = bench_reissue_1_to_100, bench_reissue_100_to_1
}

criterion_main!(reissue);
