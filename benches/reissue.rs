#![allow(clippy::from_iter_instead_of_collect)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::iter::FromIterator;

use sn_dbc::{
    bls_dkg_id, Amount, AmountSecrets, Dbc, DbcContent, Error, KeyManager, MintNode,
    ReissueRequestBuilder, SimpleKeyManager, SimpleSigner, SpentProof, SpentProofShare,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn decrypt_amount_secrets(
    owner: &bls_dkg::outcome::Outcome,
    dbcc: &DbcContent,
) -> Result<AmountSecrets, Error> {
    let shares = BTreeMap::from_iter([(0, owner.secret_key_share.clone())]);
    AmountSecrets::try_from((&owner.public_key_set, &shares, &dbcc.amount_secrets_cipher))
}

fn genesis(amount: Amount) -> (MintNode<SimpleKeyManager>, bls_dkg::outcome::Outcome, Dbc) {
    let genesis_owner = bls_dkg_id();

    let key_manager = SimpleKeyManager::new(
        SimpleSigner::new(
            genesis_owner.public_key_set.clone(),
            (0, genesis_owner.secret_key_share.clone()),
        ),
        genesis_owner.public_key_set.public_key(),
    );
    let mut genesis_node = MintNode::new(key_manager);

    let genesis = genesis_node.issue_genesis_dbc(amount).unwrap();

    let mint_sig = genesis
        .public_key_set
        .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])
        .unwrap();

    let transaction_sigs = BTreeMap::from_iter(genesis.transaction.inputs.iter().map(|in_hash| {
        (
            *in_hash,
            (genesis.public_key_set.public_key(), mint_sig.clone()),
        )
    }));

    let genesis_dbc = Dbc {
        content: genesis.dbc_content,
        transaction: genesis.transaction,
        transaction_sigs,
    };

    (genesis_node, genesis_owner, genesis_dbc)
}

fn bench_reissue_1_to_100(c: &mut Criterion) {
    let n_outputs: u32 = 100;
    let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);
    let genesis_secrets = decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content).unwrap();

    let output_owner = bls_dkg_id();
    let output_owner_pk = output_owner.public_key_set.public_key();

    let reissue_tx = sn_dbc::TransactionBuilder::default()
        .add_input(genesis_dbc.clone(), genesis_secrets)
        .add_outputs((0..n_outputs).into_iter().map(|_| sn_dbc::Output {
            amount: 1,
            owner: output_owner_pk,
        }))
        .build()
        .unwrap();

    let spent_sig = genesis_owner
        .public_key_set
        .combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(reissue_tx.blinded().hash()),
        )])
        .unwrap();
    let spentbook_pks = genesis.key_manager.public_key_set().unwrap();
    let spentbook_sig_share = genesis
        .key_manager
        .sign(&SpentProof::proof_msg(
            &reissue_tx.blinded().hash(),
            &spent_sig,
        ))
        .unwrap();

    let rr = ReissueRequestBuilder::new(reissue_tx)
        .add_spent_proof_share(
            genesis_dbc.spend_key(),
            SpentProofShare {
                spent_sig,
                spentbook_pks,
                spentbook_sig_share,
            },
        )
        .build()
        .unwrap();

    c.bench_function(&format!("reissue split 1 to {}", n_outputs), |b| {
        b.iter(|| {
            genesis.reissue(black_box(rr.clone())).unwrap();
        })
    });
}

fn bench_reissue_100_to_1(c: &mut Criterion) {
    let n_outputs: u32 = 100;
    let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);
    let genesis_amount_secrets =
        sn_dbc::DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content).unwrap();

    let owners = Vec::from_iter((0..n_outputs).into_iter().map(|_| bls_dkg_id()));

    let reissue_tx = sn_dbc::TransactionBuilder::default()
        .add_input(genesis_dbc.clone(), genesis_amount_secrets)
        .add_outputs(owners.iter().map(|owner| sn_dbc::Output {
            amount: 1,
            owner: owner.public_key_set.public_key(),
        }))
        .build()
        .unwrap();

    let dbc_owners = BTreeMap::from_iter(reissue_tx.outputs.iter().map(|out_dbc| {
        let owner = owners
            .iter()
            .find(|o| o.public_key_set.public_key() == out_dbc.owner)
            .unwrap()
            .clone();
        (out_dbc.owner, owner)
    }));

    let spent_sig = genesis_owner
        .public_key_set
        .combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(reissue_tx.blinded().hash()),
        )])
        .unwrap();
    let spentbook_pks = genesis.key_manager.public_key_set().unwrap();
    let spentbook_sig_share = genesis
        .key_manager
        .sign(&SpentProof::proof_msg(
            &reissue_tx.blinded().hash(),
            &spent_sig,
        ))
        .unwrap();

    let rr = ReissueRequestBuilder::new(reissue_tx)
        .add_spent_proof_share(
            genesis_dbc.spend_key(),
            SpentProofShare {
                spent_sig,
                spentbook_pks,
                spentbook_sig_share,
            },
        )
        .build()
        .unwrap();

    let reissue_share = genesis.reissue(rr.clone()).unwrap();

    let (mint_key_set, mint_sig_share) = reissue_share
        .mint_node_signatures
        .values()
        .cloned()
        .next()
        .unwrap();

    let mint_sig = genesis_owner
        .public_key_set
        .combine_signatures(vec![mint_sig_share.threshold_crypto()])
        .unwrap();

    let dbcs = Vec::from_iter(rr.transaction.outputs.into_iter().map(|content| Dbc {
        content,
        transaction: reissue_share.dbc_transaction.clone(),
        transaction_sigs: BTreeMap::from_iter([(
            genesis_dbc.spend_key(),
            (mint_key_set.public_key(), mint_sig.clone()),
        )]),
    }));

    let merge_tx = sn_dbc::TransactionBuilder::default()
        .add_inputs(dbcs.iter().cloned().map(|dbc| {
            let owner = &dbc_owners[&dbc.owner()];
            let amount_secrets =
                sn_dbc::DbcHelper::decrypt_amount_secrets(owner, &dbc.content).unwrap();
            (dbc, amount_secrets)
        }))
        .add_output(sn_dbc::Output {
            amount: n_outputs as Amount,
            owner: bls_dkg_id().public_key_set.public_key(),
        })
        .build()
        .unwrap();

    let mut rr_builder = ReissueRequestBuilder::new(merge_tx.clone());

    for dbc in dbcs.iter() {
        let owner = &dbc_owners[&dbc.owner()];
        let spent_sig = owner
            .public_key_set
            .combine_signatures([(
                owner.index,
                owner
                    .secret_key_share
                    .derive_child(&dbc.spend_key_index())
                    .sign(&merge_tx.blinded().hash()),
            )])
            .unwrap();
        let spentbook_pks = genesis.key_manager.public_key_set().unwrap();
        let spentbook_sig_share = genesis
            .key_manager
            .sign(&SpentProof::proof_msg(
                &merge_tx.blinded().hash(),
                &spent_sig,
            ))
            .unwrap();

        rr_builder = rr_builder.add_spent_proof_share(
            dbc.spend_key(),
            SpentProofShare {
                spent_sig,
                spentbook_pks,
                spentbook_sig_share,
            },
        )
    }

    let merge_rr = rr_builder.build().unwrap();

    c.bench_function(&format!("reissue merge {} to 1", n_outputs), |b| {
        b.iter(|| {
            genesis.reissue(black_box(merge_rr.clone())).unwrap();
        })
    });
}

criterion_group!(reissue, bench_reissue_1_to_100, bench_reissue_100_to_1);
criterion_main!(reissue);
