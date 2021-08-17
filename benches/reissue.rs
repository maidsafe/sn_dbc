#![allow(clippy::from_iter_instead_of_collect)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use curve25519_dalek_ng::scalar::Scalar;
use sn_dbc::{
    bls_dkg_id, AmountSecrets, Dbc, DbcContent, Error, Mint, ReissueRequest, ReissueTransaction,
    SimpleKeyManager, SimpleSigner, SimpleSpendBook,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn decrypt_amount_secrets(
    owner: &bls_dkg::outcome::Outcome,
    dbcc: &DbcContent,
) -> Result<AmountSecrets, Error> {
    let shares = BTreeMap::from_iter([(0, owner.secret_key_share.clone())]);

    dbcc.amount_secrets_by_secret_key_shares(&owner.public_key_set, &shares)
}

fn genesis(
    amount: u64,
) -> (
    Mint<SimpleKeyManager, SimpleSpendBook>,
    bls_dkg::outcome::Outcome,
    Dbc,
) {
    let genesis_owner = bls_dkg_id();

    let key_manager = SimpleKeyManager::new(
        SimpleSigner::new(
            genesis_owner.public_key_set.clone(),
            (0, genesis_owner.secret_key_share.clone()),
        ),
        genesis_owner.public_key_set.public_key(),
    );
    let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

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

    let inputs = HashSet::from_iter([genesis_dbc.clone()]);
    let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

    let genesis_secrets = decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content).unwrap();

    let output_owner = bls_dkg_id();
    let owner_pub_key = output_owner.public_key_set.public_key();
    let mut outputs_bf_sum: Scalar = Default::default();
    let outputs = (0..n_outputs)
        .into_iter()
        .map(|i| {
            let blinding_factor = DbcContent::calc_blinding_factor(
                i == n_outputs - 1,
                genesis_secrets.blinding_factor,
                outputs_bf_sum,
            );
            outputs_bf_sum += blinding_factor;
            DbcContent::new(input_hashes.clone(), 1, owner_pub_key, blinding_factor)
        })
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

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
        input_ownership_proofs: HashMap::from_iter([(
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
    let genesis_amount_secrets =
        sn_dbc::DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content).unwrap();

    let owners = Vec::from_iter((0..n_outputs).into_iter().map(|_| bls_dkg_id()));

    let (reissue_tx, dbc_owners) = sn_dbc::TransactionBuilder::default()
        .add_input(genesis_dbc.clone(), genesis_amount_secrets)
        .add_outputs(owners.iter().map(|owner| sn_dbc::Output {
            amount: 1,
            owner: owner.public_key_set.public_key(),
        }))
        .build()
        .unwrap();

    let sig_share = genesis_owner
        .secret_key_share
        .sign(&reissue_tx.blinded().hash());

    let sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![(0, &sig_share)])
        .unwrap();

    let input_ownership_proofs = HashMap::from_iter([(
        genesis_dbc.name(),
        (genesis_owner.public_key_set.public_key(), sig),
    )]);

    let reissue = ReissueRequest {
        transaction: reissue_tx,
        input_ownership_proofs,
    };

    let (transaction, transaction_sigs) = genesis
        .reissue(reissue.clone(), BTreeSet::from_iter([genesis_dbc.name()]))
        .unwrap();

    let (mint_key_set, mint_sig_share) = transaction_sigs.values().cloned().next().unwrap();

    let mint_sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![mint_sig_share.threshold_crypto()])
        .unwrap();

    let dbcs = Vec::from_iter(reissue.transaction.outputs.into_iter().map(|content| Dbc {
        content,
        transaction: transaction.clone(),
        transaction_sigs: BTreeMap::from_iter([(
            genesis_dbc.name(),
            (mint_key_set.public_key(), mint_sig.clone()),
        )]),
    }));

    let (merge_tx, _) = sn_dbc::TransactionBuilder::default()
        .add_inputs(dbcs.iter().cloned().map(|dbc| {
            let owner_pk = dbc_owners[&dbc.name()];
            let owner = owners
                .iter()
                .find(|o| o.public_key_set.public_key() == owner_pk)
                .unwrap();
            let amount_secrets =
                sn_dbc::DbcHelper::decrypt_amount_secrets(&owner, &dbc.content).unwrap();
            (dbc, amount_secrets)
        }))
        .add_output(sn_dbc::Output {
            amount: n_outputs as u64,
            owner: bls_dkg_id().public_key_set.public_key(),
        })
        .build()
        .unwrap();

    let input_ownership_proofs = HashMap::from_iter(dbcs.iter().enumerate().map(|(i, dbc)| {
        let sig_share = owners[i].secret_key_share.sign(merge_tx.blinded().hash());
        let sig = owners[i]
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();
        (dbc.name(), (owners[i].public_key_set.public_key(), sig))
    }));

    let merge_reissue = ReissueRequest {
        transaction: merge_tx,
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
