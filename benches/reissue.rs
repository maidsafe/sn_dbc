use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use sn_dbc::{bls_dkg_id, Dbc, DbcContent, Mint, MintRequest, MintTransaction};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn genesis(amount: u64) -> (Mint, bls_dkg::outcome::Outcome, Dbc) {
    let genesis_owner = bls_dkg_id();
    let (genesis, genesis_dbc) = Mint::genesis(genesis_owner.public_key_set.clone(), amount);

    (genesis, genesis_owner, genesis_dbc)
}

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let n_outputs: u32 = 100;
    let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);

    let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
    let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

    let output_owner = bls_dkg_id();
    let owner_pub_key = output_owner.public_key_set.public_key();
    let outputs = (0..n_outputs)
        .into_iter()
        .map(|i| DbcContent::new(input_hashes.clone(), 1, i, owner_pub_key))
        .collect();

    let transaction = MintTransaction { inputs, outputs };

    let sig_share = genesis_owner
        .secret_key_share
        .sign(&transaction.blinded().hash());

    let sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![(0, &sig_share)])
        .unwrap();

    let mint_request = MintRequest {
        transaction,
        input_ownership_proofs: HashMap::from_iter(vec![(
            genesis_dbc.name(),
            (genesis_owner.public_key_set.public_key(), sig),
        )]),
    };

    let spendbook = genesis.snapshot_spendbook();
    c.bench_function(&format!("reissue split 1 to {}", n_outputs), |b| {
        b.iter(|| {
            genesis.reset_spendbook(spendbook.clone());
            genesis
                .reissue(
                    black_box(mint_request.clone()),
                    black_box(input_hashes.clone()),
                )
                .unwrap();
        })
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let n_outputs: u32 = 100;
    let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);

    let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
    let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

    let owners: Vec<_> = (0..n_outputs).into_iter().map(|_| bls_dkg_id()).collect();
    let outputs = Vec::from_iter((0..n_outputs).into_iter().map(|i| {
        DbcContent::new(
            input_hashes.clone(),
            1,
            i,
            owners[i as usize].public_key_set.public_key(),
        )
    }));

    let transaction = MintTransaction {
        inputs,
        outputs: HashSet::from_iter(outputs.clone()),
    };

    let sig_share = genesis_owner
        .secret_key_share
        .sign(&transaction.blinded().hash());

    let sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![(0, &sig_share)])
        .unwrap();

    let mint_request = MintRequest {
        transaction,
        input_ownership_proofs: HashMap::from_iter(vec![(
            genesis_dbc.name(),
            (genesis_owner.public_key_set.public_key(), sig),
        )]),
    };

    let (transaction, transaction_sigs) = genesis
        .reissue(mint_request.clone(), input_hashes.clone())
        .unwrap();

    let dbcs = Vec::from_iter(outputs.into_iter().map(|content| Dbc {
        content,
        transaction: transaction.clone(),
        transaction_sigs: transaction_sigs.clone(),
    }));

    let merged_output = DbcContent::new(
        BTreeSet::from_iter(dbcs.iter().map(Dbc::name)),
        n_outputs as u64,
        0,
        bls_dkg_id().public_key_set.public_key(),
    );

    let merge_transaction = MintTransaction {
        inputs: HashSet::from_iter(dbcs.clone()),
        outputs: HashSet::from_iter([merged_output]),
    };

    let input_ownership_proofs = HashMap::from_iter(dbcs.iter().enumerate().map(|(i, dbc)| {
        let sig_share = owners[i]
            .secret_key_share
            .sign(merge_transaction.blinded().hash());
        let sig = owners[i]
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();
        (dbc.name(), (owners[i].public_key_set.public_key(), sig))
    }));

    let merge_mint_request = MintRequest {
        transaction: merge_transaction,
        input_ownership_proofs,
    };
    let inputs = merge_mint_request.transaction.blinded().inputs;

    let spendbook = genesis.snapshot_spendbook();
    c.bench_function(&format!("reissue merge {} to 1", n_outputs), |b| {
        b.iter(|| {
            genesis.reset_spendbook(spendbook.clone());
            genesis
                .reissue(
                    black_box(merge_mint_request.clone()),
                    black_box(inputs.clone()),
                )
                .unwrap();
        })
    });
}

criterion_group!(reissue, bench_reissue_1_to_100, bench_reissue_100_to_1);
criterion_main!(reissue);
