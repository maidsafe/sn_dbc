#![allow(clippy::from_iter_instead_of_collect)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use sn_dbc::{
    bls_dkg_id, Dbc, DbcContent, ExposedSigner, KeyManager, Mint, ReissueRequest,
    ReissueTransaction,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn genesis(amount: u64) -> (Mint<ExposedSigner>, bls_dkg::outcome::Outcome, Dbc) {
    let genesis_owner = bls_dkg_id();

    let mut genesis_node = Mint::new(KeyManager::new(
        ExposedSigner::new(
            0,
            genesis_owner.public_key_set.clone(),
            genesis_owner.secret_key_share.clone(),
        ),
        genesis_owner.public_key_set.public_key(),
    ));

    let (content, transaction, (mint_key_set, mint_sig_share)) =
        genesis_node.issue_genesis_dbc(amount).unwrap();

    let mint_sig = mint_key_set
        .combine_signatures(vec![mint_sig_share.threshold_crypto()])
        .unwrap();

    let transaction_sigs = BTreeMap::from_iter(
        transaction
            .inputs
            .iter()
            .map(|in_hash| (*in_hash, (mint_key_set.public_key(), mint_sig.clone()))),
    );

    let genesis_dbc = Dbc {
        content,
        transaction,
        transaction_sigs,
    };

    (genesis_node, genesis_owner, genesis_dbc)
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

    let transaction = ReissueTransaction { inputs, outputs };

    let sig_share = genesis_owner
        .secret_key_share
        .sign(&transaction.blinded().hash());

    let sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![(0, &sig_share)])
        .unwrap();

    let reissue = ReissueRequest {
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
                .reissue(black_box(reissue.clone()), black_box(input_hashes.clone()))
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

    let transaction = ReissueTransaction {
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

    let reissue = ReissueRequest {
        transaction,
        input_ownership_proofs: HashMap::from_iter(vec![(
            genesis_dbc.name(),
            (genesis_owner.public_key_set.public_key(), sig),
        )]),
    };

    let (transaction, transaction_sigs) = genesis.reissue(reissue, input_hashes).unwrap();

    let (mint_key_set, mint_sig_share) = transaction_sigs.values().cloned().next().unwrap();

    let mint_sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![mint_sig_share.threshold_crypto()])
        .unwrap();

    let dbcs = Vec::from_iter(outputs.into_iter().map(|content| Dbc {
        content,
        transaction: transaction.clone(),
        transaction_sigs: BTreeMap::from_iter(vec![(
            genesis_dbc.name(),
            (mint_key_set.public_key(), mint_sig.clone()),
        )]),
    }));

    let merged_output = DbcContent::new(
        BTreeSet::from_iter(dbcs.iter().map(Dbc::name)),
        n_outputs as u64,
        0,
        bls_dkg_id().public_key_set.public_key(),
    );

    let merge_transaction = ReissueTransaction {
        inputs: HashSet::from_iter(dbcs.clone()),
        outputs: HashSet::from_iter(vec![merged_output]),
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

    let merge_reissue = ReissueRequest {
        transaction: merge_transaction,
        input_ownership_proofs,
    };
    let inputs = merge_reissue.transaction.blinded().inputs;

    let spendbook = genesis.snapshot_spendbook();
    c.bench_function(&format!("reissue merge {} to 1", n_outputs), |b| {
        b.iter(|| {
            genesis.reset_spendbook(spendbook.clone());
            genesis
                .reissue(black_box(merge_reissue.clone()), black_box(inputs.clone()))
                .unwrap();
        })
    });
}

criterion_group!(reissue, bench_reissue_1_to_100, bench_reissue_100_to_1);
criterion_main!(reissue);
