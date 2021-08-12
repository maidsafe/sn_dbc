// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Safe Network DBC Mint CLI playground.

use anyhow::{anyhow, Error, Result};
use blsttc::poly::Poly;
use blsttc::serde_impl::SerdeSecret;
use blsttc::{
    PublicKey, PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare, Signature, SignatureShare,
};
use curve25519_dalek_ng::scalar::Scalar;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use serde::{Deserialize, Serialize};
use sn_dbc::{
    Dbc, DbcContent, DbcTransaction, Hash, Mint, MintSignatures, NodeSignature, ReissueRequest,
    ReissueTransaction, SimpleKeyManager as KeyManager, SimpleSigner as Signer,
    SimpleSpendBook as SpendBook,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

#[cfg(unix)]
use std::os::unix::{io::AsRawFd, prelude::RawFd};

#[cfg(unix)]
use termios::{tcsetattr, Termios, ICANON, TCSADRAIN};

/// Holds information about the Mint, which may be comprised
/// of 1 or more nodes.
struct MintInfo {
    mintnodes: Vec<Mint<KeyManager, SpendBook>>,
    genesis: DbcUnblinded,
    secret_key_set: SecretKeySet,
    poly: Poly,
}

impl MintInfo {
    // returns the first mint node.
    fn mintnode(&self) -> Result<&Mint<KeyManager, SpendBook>> {
        self.mintnodes
            .get(0)
            .ok_or_else(|| anyhow!("Mint not yet created"))
    }

    // returns SecretKey
    #[allow(dead_code)]
    fn secret_key(&self) -> SecretKey {
        let mut fr = self.poly.evaluate(0);
        SecretKey::from_mut(&mut fr)
    }
}

/// A Dbc plus the owner's pubkey set
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct DbcUnblinded {
    inner: Dbc,
    owner: PublicKeySet,
}

/// A ReissueTransaction with pubkey set for all the input and output Dbcs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReissueTransactionUnblinded {
    inner: ReissueTransaction,
    inputs_owners: HashMap<Hash, PublicKeySet>,
    outputs_owners: HashMap<Hash, PublicKeySet>,
}

/// A ReissueRequest with pubkey set for all the input and output Dbcs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReissueRequestUnblinded {
    inner: ReissueRequest,
    inputs_owners: HashMap<Hash, PublicKeySet>,
    outputs_owners: HashMap<Hash, PublicKeySet>,
}

/// This type is just for serializing HashMap<Hash, <HashMap<usize, SignatureShare>>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SignatureSharesMap(HashMap<Hash, HashMap<usize, SignatureShare>>);

/// program entry point and interactive command handler.
fn main() -> Result<()> {
    // Disable TTY ICANON.  So readline() can read more than 4096 bytes.
    // termios_old has the previous settings so we can restore before exit.
    #[cfg(unix)]
    let (tty_fd, termios_old) = unset_tty_icanon()?;

    print_logo();
    println!("Type 'help' to get started.\n");

    // Create a default mint with money supply = 1000.
    let mut mintinfo: MintInfo = mk_new_random_mint(0, 1000)?;

    let mut rl = Editor::<()>::new();
    rl.set_auto_add_history(true);
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let mut args = line.trim().split_whitespace();
                let cmd = if let Some(cmd) = args.next() {
                    cmd
                } else {
                    continue;
                };
                let result = match cmd {
                    "newmint" => {
                        mintinfo = newmint()?;
                        Ok(())
                    }
                    "mintinfo" => print_mintinfo_human(&mintinfo),
                    "prepare_tx" => prepare_tx(),
                    "sign_tx" => sign_tx(),
                    "prepare_reissue" => prepare_reissue(),
                    "reissue" => reissue(&mut mintinfo),
                    "reissue_ez" => reissue_ez(&mut mintinfo),
                    "validate" => validate(&mintinfo),
                    "newkey" => newkey(),
                    "decode" => decode_input(),
                    "quit" | "exit" => break,
                    "help" => {
                        println!(
                            "\nCommands:\n  Mint:    [mintinfo, newmint, reissue]\n  Client:  [newkey, prepare_tx, sign_tx, prepare_reissue, reissue_ez, decode, validate]\n  General: [exit, help]\n"
                        );
                        Ok(())
                    }
                    _ => Err(anyhow!("Unknown command")),
                };
                if let Err(msg) = result {
                    println!("\nError: {:?}\n", msg);
                }
            }
            Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => break,
            Err(e) => {
                println!("Error reading line: {}", e);
            }
        }
    }

    // restore original TTY settings.
    #[cfg(unix)]
    tcsetattr(tty_fd, TCSADRAIN, &termios_old)?;

    Ok(())
}

/// handles newmint command to generate a new mint with N nodes.
fn newmint() -> Result<MintInfo> {
    let confirm = readline_prompt(
        "\nThis will erase existing Mint and transactions.  Are you sure? [y/n]: ",
    )?;
    if confirm != "y" {
        return Err(anyhow!("newmint operation cancelled"));
    }

    let amount = loop {
        let amount: u64 = readline_prompt("\nTotal Money Supply Amount: ")?.parse()?;

        if amount == 0 {
            let answer = readline_prompt(
                "\nA mint with supply == 0 can only reissue Dbc worth 0. Change? [y/n]: ",
            )?;
            if answer.to_ascii_lowercase() != "n" {
                continue;
            }
            // note: we allow amount to be 0.  Let sn_dbc validation deal with it (or not).
        }
        break amount;
    };

    // polynomial, from which SecretKeySet is built.
    let poly_input = readline_prompt_nl("\nSecretKeySet Poly Hex, or [r]andom: ")?;

    let mintinfo = match poly_input.as_str() {
        "r" => {
            let threshold = loop {
                let num_signers: usize = readline_prompt("\nHow many signers: ")?.parse()?;

                if num_signers > 0 {
                    break num_signers - 1;
                } else {
                    println!("\nThere must be at least 1 signer\n");
                }
            };
            mk_new_random_mint(threshold, amount)?
        }
        _ => {
            let poly: Poly = from_be_hex(&poly_input)?;
            let secret_key_set = SecretKeySet::from(poly.clone());
            mk_new_mint(secret_key_set, poly, amount)?
        }
    };

    println!("\nMint created!\n");

    Ok(mintinfo)
}

/// creates a new mint using a random seed.
fn mk_new_random_mint(threshold: usize, amount: u64) -> Result<MintInfo> {
    let (poly, secret_key_set) = mk_secret_key_set(threshold)?;
    mk_new_mint(secret_key_set, poly, amount)
}

/// creates a new mint from an existing SecretKeySet that was seeded by poly.
fn mk_new_mint(secret_key_set: SecretKeySet, poly: Poly, amount: u64) -> Result<MintInfo> {
    let genesis_pubkey = secret_key_set.public_keys().public_key();
    let mut mints: Vec<Mint<KeyManager, SpendBook>> = Default::default();

    // Generate each Mint node, and corresponding NodeSignature. (Index + SignatureShare)
    let mut genesis_set: Vec<(DbcContent, DbcTransaction, (PublicKeySet, NodeSignature))> =
        Default::default();
    for i in 0..secret_key_set.threshold() as u64 + 1 {
        let key_manager = KeyManager::new(
            Signer::new(
                secret_key_set.public_keys().clone(),
                (i, secret_key_set.secret_key_share(i).clone()),
            ),
            genesis_pubkey,
        );
        let mut mint = Mint::new(key_manager, SpendBook::new());
        genesis_set.push(mint.issue_genesis_dbc(amount)?);
        mints.push(mint);
    }

    // Make a list of (Index, SignatureShare) for combining sigs.
    let node_sigs: Vec<(u64, &SignatureShare)> = genesis_set
        .iter()
        .map(|e| e.2 .1.threshold_crypto())
        .collect();

    // Todo: in a true multi-node mint, each node would call issue_genesis_dbc(), then the aggregated
    // signatures would be combined here, so this mk_new_mint fn would to be broken apart.
    let genesis_sig = secret_key_set
        .public_keys()
        .combine_signatures(node_sigs)
        .map_err(|e| anyhow!(e))?;

    // Create the Genesis Dbc
    let genesis_dbc = Dbc {
        content: genesis_set[0].0.clone(),
        transaction: genesis_set[0].1.clone(),
        transaction_sigs: BTreeMap::from_iter([(
            sn_dbc::GENESIS_DBC_INPUT,
            (genesis_pubkey, genesis_sig),
        )]),
    };

    // Bob's your uncle.
    Ok(MintInfo {
        mintnodes: mints,
        genesis: DbcUnblinded {
            inner: genesis_dbc,
            owner: secret_key_set.public_keys(),
        },
        secret_key_set,
        poly,
    })
}

/// handles newkey command. generates SecretKeySet from random seed or user-supplied seed.
fn newkey() -> Result<()> {
    let poly_input =
        readline_prompt_nl("\nPoly of existing SecretKeySet (or 'new' to generate new key): ")?;

    // Get poly and SecretKeySet from user, or make new random
    let (poly, sks) = match poly_input.as_str() {
        "new" => {
            let m = loop {
                let m: usize =
                    readline_prompt("\nHow many shares needed to sign (m in m-of-n): ")?.parse()?;

                if m == 0 {
                    println!("m must be greater than 0\n");
                    continue;
                }
                break m;
            };

            mk_secret_key_set(m - 1)?
        }
        _ => {
            let poly: Poly = from_be_hex(&poly_input)?;
            (poly.clone(), SecretKeySet::from(poly))
        }
    };

    println!("\n -- Poly Hex --\n  {}", to_be_hex(&poly)?);

    // poly.commitment() is the same as the PublicKeySet returned from sks.public_keys()
    // println!("Commitment Hex: {}", to_be_hex(&poly.commitment())?);

    println!("\n -- SecretKeyShares --");
    for i in (0..sks.threshold() + 5).into_iter() {
        println!(
            "  {}. {}",
            i,
            encode(&sks_to_bytes(&sks.secret_key_share(i))?)
        );
    }

    println!("\n -- PublicKeyShares --");
    for i in (0..sks.threshold() + 5).into_iter() {
        // the 2nd line matches ian coleman's bls tool output.  but why not the first?
        //        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!(
            "  {}. {}",
            i,
            encode(&sks.public_keys().public_key_share(i).to_bytes())
        );
    }

    println!(
        "\n -- PublicKeySet --\n{}\n",
        to_be_hex(&sks.public_keys())?
    );

    println!(
        "\nSigning Threshold: {}  ({} signers required)\n",
        sks.threshold(),
        sks.threshold() + 1
    );

    Ok(())
}

/// Displays mint information in human readable form
fn print_mintinfo_human(mintinfo: &MintInfo) -> Result<()> {
    println!();

    println!("Number of Mint Nodes: {}\n", mintinfo.mintnodes.len());

    println!("-- Mint Keys --\n");
    println!("SecretKeySet (Poly): {}\n", to_be_hex(&mintinfo.poly)?);

    println!(
        "PublicKeySet: {}\n",
        to_be_hex(&mintinfo.secret_key_set.public_keys())?
    );

    println!("\n   -- SecretKeyShares --");
    for i in (0..mintinfo.secret_key_set.threshold() + 2).into_iter() {
        println!(
            "    {}. {}",
            i,
            encode(&sks_to_bytes(&mintinfo.secret_key_set.secret_key_share(i))?)
        );
    }

    let mut secret_key_shares: BTreeMap<usize, SecretKeyShare> = Default::default();

    println!("\n   -- PublicKeyShares --");
    for i in (0..mintinfo.secret_key_set.threshold() + 2).into_iter() {
        // the 2nd line matches ian coleman's bls tool output.  but why not the first?
        //        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!(
            "    {}. {}",
            i,
            encode(
                &mintinfo
                    .secret_key_set
                    .public_keys()
                    .public_key_share(i)
                    .to_bytes()
            )
        );
        secret_key_shares.insert(i, mintinfo.secret_key_set.secret_key_share(i));
    }

    println!(
        "\n   Required Signers: {}   (Threshold = {})",
        mintinfo.secret_key_set.threshold() + 1,
        mintinfo.secret_key_set.threshold()
    );

    println!("\n-- Genesis DBC --\n");
    print_dbc_human(
        &mintinfo.genesis,
        true,
        Some((&mintinfo.secret_key_set.public_keys(), &secret_key_shares)),
    )?;

    println!("\n");

    println!("-- SpendBook --\n");
    for (dbchash, _tx) in &mintinfo.mintnode()?.spendbook {
        println!("  {}", encode(&dbchash));
    }

    println!();

    Ok(())
}

fn secret_key_set_to_shares(sks: &SecretKeySet) -> (PublicKeySet, BTreeMap<usize, SecretKeyShare>) {
    let mut secret_key_shares: BTreeMap<usize, SecretKeyShare> = Default::default();
    for i in (0..sks.threshold() + 1).into_iter() {
        secret_key_shares.insert(i, sks.secret_key_share(i));
    }
    (sks.public_keys(), secret_key_shares)
}

/// displays Dbc in human readable form
fn print_dbc_human(
    dbc: &DbcUnblinded,
    outputs: bool,
    keys: Option<(&PublicKeySet, &BTreeMap<usize, SecretKeyShare>)>,
) -> Result<()> {
    println!("id: {}\n", encode(dbc.inner.name()));

    match keys {
        Some((public_key_set, secret_key_shares)) => {
            let amount_secrets = dbc
                .inner
                .content
                .amount_secrets_by_secret_key_shares(public_key_set, secret_key_shares)?;
            println!("*** Secrets (decrypted) ***");
            println!("     amount: {}\n", amount_secrets.amount);
            println!(
                "     blinding_factor: {}\n",
                to_be_hex(&amount_secrets.blinding_factor)?
            );
        }
        None => println!("amount: unknown.  SecretKey not available\n"),
    }

    println!("output_number: {}\n", dbc.inner.content.output_number);
    println!("owner: {}\n", to_be_hex(&dbc.owner)?);

    // dbc.content.parents and dbc.transaction.inputs are the same
    // so for now we are just displaying the latter.
    // println!("parents:");
    // for p in &dbc.content.parents {
    //     println!("  {}", encode(p))
    // }

    println!("inputs:");
    for i in &dbc.inner.transaction.inputs {
        println!("  {}", encode(i))
    }

    if outputs {
        println!("\noutputs:");
        for i in &dbc.inner.transaction.outputs {
            println!("  {}", encode(i))
        }
    }

    println!("\nData:");
    println!("{}", to_be_hex(&dbc)?);
    Ok(())
}

/// handles decode command.  
fn decode_input() -> Result<()> {
    let t = readline_prompt("\n[d: DBC, rt: ReissueTransaction, s: SignatureSharesMap, rr: ReissueRequest, pks: PublicKeySet, sks: SecretKeySet]\nType: ")?;
    let input = readline_prompt_nl("\nPaste Data: ")?;
    let bytes = decode(input)?;

    match t.as_str() {
        "d" => {
            let sks_input = readline_prompt_nl("\nSecretKeySet (or \"none\"): ")?;
            match sks_input.as_str() {
                "none" => {
                    println!("\n\n-- Start DBC --\n");
                    print_dbc_human(&from_be_bytes(&bytes)?, true, None)?;
                    println!("-- End DBC --\n");
                }
                _ => {
                    let poly: Poly = from_be_bytes(&decode(sks_input)?)?;
                    let sks = SecretKeySet::from(poly);
                    let keys = secret_key_set_to_shares(&sks);

                    println!("\n\n-- Start DBC --\n");
                    print_dbc_human(&from_be_bytes(&bytes)?, true, Some((&keys.0, &keys.1)))?;
                    println!("-- End DBC --\n");
                }
            }
        }
        "pks" => {
            let pks: PublicKeySet = from_be_bytes(&bytes)?;
            println!("\n\n-- Start PublicKeySet --");
            println!(
                "  threshold: {} ({} signature shares required)\n",
                pks.threshold(),
                pks.threshold() + 1
            );
            println!("  public_key: {}", encode(&pks.public_key().to_bytes()));
            // temporary: the 2nd line matches ian coleman's bls tool output.  but why not the first?
            //            println!("PublicKeyShare[0]: {}", to_be_hex(&pks.public_key_share(0))? );
            println!("\n  PublicKeyShares:");
            for i in 0..pks.threshold() + 1 {
                println!(
                    "    {} : {}",
                    i,
                    encode(&pks.public_key_share(i).to_bytes())
                );
            }
            println!("-- End PublicKeySet --\n");
        }
        "sks" => {
            let poly: Poly = from_be_bytes(&bytes)?;
            let sks = SecretKeySet::from(poly);
            println!("\n\n-- Start SecretKeySet --");
            println!(
                "  threshold: {} ({} signature shares required)\n",
                sks.threshold(),
                sks.threshold() + 1
            );
            println!("\n  SecretKeyShares:");
            for i in 0..sks.threshold() + 1 {
                println!(
                    "    {} : {}",
                    i,
                    encode(sks_to_bytes(&sks.secret_key_share(i))?)
                );
            }
            println!("-- End SecretKeySet --\n");
        }
        "rt" => println!(
            "\n\n-- ReissueTransaction --\n\n{:#?}",
            from_be_bytes::<ReissueTransactionUnblinded>(&bytes)?
        ),
        "s" => println!(
            "\n\n-- SignatureSharesMap --\n\n{:#?}",
            from_be_bytes::<SignatureSharesMap>(&bytes)?
        ),
        "rr" => println!(
            "\n\n-- ReissueRequest --\n\n{:#?}",
            from_be_bytes::<ReissueRequestUnblinded>(&bytes)?
        ),
        _ => println!("Unknown type!"),
    }
    println!();

    Ok(())
}

/// displays a welcome logo/banner for the app.
fn print_logo() {
    println!(
        r#"
 __     _                        
(_  _._|__  |\ | __|_     _ ._|  
__)(_| |(/_ | \|(/_|_\/\/(_)| |< 
 ____  ____   ____   __  __ _       _   
|  _ \| __ ) / ___| |  \/  (_)_ __ | |_ 
| | | |  _ \| |     | |\/| | | '_ \| __|
| |_| | |_) | |___  | |  | | | | | | |_ 
|____/|____/ \____| |_|  |_|_|_| |_|\__|        
  "#
    );
}

/// Implements validate command.  Validates signatures and that a
/// DBC has not been double-spent.  Also checks if spent/unspent.
fn validate(mintinfo: &MintInfo) -> Result<()> {
    let dbc_input = readline_prompt_nl("\nInput DBC, or 'cancel': ")?;
    let dbc: Dbc = if dbc_input == "cancel" {
        println!("\nvalidate cancelled\n");
        return Ok(());
    } else {
        from_be_hex(&dbc_input)?
    };

    match dbc.confirm_valid(mintinfo.mintnode()?.key_manager()) {
        Ok(_) => match mintinfo.mintnode()?.is_spent(dbc.name())? {
            true => println!("\nThis DBC is unspendable.  (valid but has already been spent)\n"),
            false => println!("\nThis DBC is spendable.   (valid and has not been spent)\n"),
        },
        Err(e) => println!("\nInvalid DBC.  {}", e.to_string()),
    }

    Ok(())
}

/// Implements prepare_tx command.
fn prepare_tx() -> Result<()> {
    let mut inputs: HashSet<Dbc> = Default::default();
    let mut inputs_owners: HashMap<Hash, PublicKeySet> = Default::default();
    let mut outputs_owners: HashMap<Hash, PublicKeySet> = Default::default();

    // Get DBC inputs from user
    let mut inputs_total: u64 = 0;
    let mut inputs_bf_total: Scalar = Default::default();
    loop {
        let dbc_input = readline_prompt_nl("\nInput DBC, or 'done': ")?;
        let dbc: DbcUnblinded = if dbc_input == "done" {
            break;
        } else {
            from_be_hex(&dbc_input)?
        };

        let mut secrets: BTreeMap<usize, SecretKeyShare> = Default::default();
        println!(
            "We need {} SecretKeyShare in order to decrypt the input amount.",
            dbc.owner.threshold() + 1
        );
        loop {
            println!(
                "\nWe have {} of {} required SecretKeyShare",
                secrets.len(),
                dbc.owner.threshold() + 1
            );

            let key = readline_prompt_nl("\nSecretKeyShare, or 'done': ")?;
            let secret: SecretKeyShare = if key == "done" {
                break;
            } else {
                from_be_hex(&key)?
            };
            let idx_input = readline_prompt("\nSecretKeyShare Index: ")?;
            let idx: usize = idx_input.parse()?;

            secrets.insert(idx, secret);

            if secrets.len() > dbc.owner.threshold() {
                break;
            }
        }

        let amount_secrets = dbc
            .inner
            .content
            .amount_secrets_by_secret_key_shares(&dbc.owner, &secrets)?;

        inputs_owners.insert(dbc.inner.name(), dbc.owner);

        inputs_total += amount_secrets.amount;
        inputs_bf_total += amount_secrets.blinding_factor;
        inputs.insert(dbc.inner);
    }

    let input_hashes = inputs.iter().map(|e| e.name()).collect::<BTreeSet<_>>();
    let mut i = 0u32;
    let mut outputs: HashSet<DbcContent> = Default::default();

    // Get outputs from user
    let mut outputs_total = 0u64;
    let mut outputs_bf_sum = Scalar::default();
    // note, we upcast to i128 to allow negative value.
    // This permits unbalanced inputs/outputs to reach sn_dbc layer for validation.
    while inputs_total as i128 - outputs_total as i128 > 0 {
        println!();
        println!("------------");
        println!("Output #{}", i);
        println!("------------\n");

        let remaining = inputs_total - outputs_total;
        println!("Inputs total: {}.  Remaining: {}", inputs_total, remaining);
        let line = readline_prompt("Amount, or 'cancel': ")?;
        let amount: u64 = if line == "cancel" {
            println!("\nprepare_tx cancelled\n");
            break;
        } else {
            line.parse()?
        };
        if amount > remaining || amount == 0 {
            let answer = readline_prompt(&format!(
                "\nThe amount should normally be in the range 1..{}. Change it? [y/n]: ",
                remaining
            ))?;
            if answer.to_ascii_lowercase() != "n" {
                continue;
            }
        }

        let line = readline_prompt_nl("\nPublicKeySet, or 'cancel': ")?;
        let pub_out = if line == "cancel" {
            break;
        } else {
            line
        };

        let pub_out_set: PublicKeySet = from_be_hex(&pub_out)?;

        // If this is the final output we need to calculate the final
        // blinding factor, else generate random.
        let blinding_factor = DbcContent::calc_blinding_factor(
            outputs_total + amount == inputs_total,
            inputs_bf_total,
            outputs_bf_sum,
        );

        let dbc_content = DbcContent::new(
            input_hashes.clone(),     // parents
            amount,                   // amount
            i,                        // output_number
            pub_out_set.public_key(), // public_key
            blinding_factor,
        )?;
        outputs_owners.insert(dbc_content.hash(), pub_out_set);

        outputs_total += amount;
        outputs_bf_sum += blinding_factor;
        outputs.insert(dbc_content);
        i += 1;
    }

    println!("\n\nThank-you.   Preparing ReissueTransaction...\n\n");

    let transaction = ReissueTransactionUnblinded {
        inner: ReissueTransaction { inputs, outputs },
        inputs_owners,
        outputs_owners,
    };

    println!("\n-- ReissueTransaction --");
    println!("{}", to_be_hex(&transaction)?);
    println!("-- End ReissueTransaction --\n");

    Ok(())
}

/// Implements sign_tx command.
fn sign_tx() -> Result<()> {
    let tx_input = readline_prompt_nl("\nReissueTransaction: ")?;
    let tx: ReissueTransactionUnblinded = from_be_hex(&tx_input)?;

    let mut inputs: HashMap<Dbc, HashMap<usize, SecretKeyShare>> = Default::default();

    // Get from user: (index, SecretKeyShare) for each input Dbc
    for (i, dbc) in tx.inner.inputs.iter().enumerate() {
        println!("-----------------");
        println!(
            "Input #{} [id: {}, amount: ???  (encrypted)]",
            i,
            encode(dbc.name()),
        );
        println!("-----------------");

        let pubkeyset = tx
            .inputs_owners
            .get(&dbc.name())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;

        let mut secrets: HashMap<usize, SecretKeyShare> = Default::default();
        loop {
            println!(
                "\nWe have {} of {} required SecretKeyShare",
                secrets.len(),
                pubkeyset.threshold() + 1
            );

            let key = readline_prompt_nl("\nSecretKeyShare, or 'done': ")?;
            let secret: SecretKeyShare = if key == "done" {
                break;
            } else {
                from_be_hex(&key)?
            };
            let idx_input = readline_prompt("\nSecretKeyShare Index: ")?;
            let idx: usize = idx_input.parse()?;

            secrets.insert(idx, secret);

            if secrets.len() > pubkeyset.threshold() {
                break;
            }
        }
        inputs.insert(dbc.clone(), secrets);
    }

    println!("\n\nThank-you.   Preparing SignatureSharesMap...\n\n");

    let mut sig_shares: SignatureSharesMap = Default::default();
    for (dbc, secrets) in inputs.iter() {
        let mut sigs: HashMap<usize, SignatureShare> = Default::default();
        for (idx, secret) in secrets.iter() {
            let sig_share = secret.sign(&tx.inner.blinded().hash());
            sigs.insert(*idx, sig_share);
        }
        sig_shares.0.insert(dbc.name(), sigs);
    }

    println!("\n-- SignatureSharesMap --");
    println!("{}", to_be_hex(&sig_shares)?);
    println!("-- End SignatureSharesMap --\n");

    Ok(())
}

/// Implements prepare_reissue command.
fn prepare_reissue() -> Result<()> {
    let tx_input = readline_prompt_nl("\nReissueTransaction: ")?;
    let tx: ReissueTransactionUnblinded = from_be_hex(&tx_input)?;
    let mut sig_shares_by_input: HashMap<Hash, BTreeMap<usize, SignatureShare>> =
        Default::default();

    // Get from user: SignatureSharesMap(s) for each tx input
    //                until required # of SignatureShare obtained.
    for dbc in tx.inner.inputs.iter() {
        println!("-----------------");
        println!(
            "Input #{} [id: {}, amount: {}]",
            dbc.content.output_number,
            encode(dbc.name()),
            0 // fixme: dbc.content.amount
        );
        println!("-----------------");

        let pubkeyset = tx
            .inputs_owners
            .get(&dbc.name())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;

        let mut num_shares = 0usize;
        while num_shares < pubkeyset.threshold() + 1 {
            let ssm_input = readline_prompt_nl("\nSignatureSharesMap, or 'cancel': ")?;
            let shares_map: SignatureSharesMap = if ssm_input == "cancel" {
                println!("\nprepare_reissue cancelled.\n");
                return Ok(());
            } else {
                from_be_hex(&ssm_input)?
            };
            for (name, shares) in shares_map.0.iter() {
                for (idx, share) in shares.iter() {
                    let list = sig_shares_by_input
                        .entry(*name)
                        .or_insert_with(BTreeMap::default);
                    (*list).insert(*idx, share.clone());
                    num_shares += 1;
                }
            }
        }
    }

    let mut proofs: HashMap<Hash, (PublicKey, Signature)> = Default::default();
    for dbc in tx.inner.inputs.iter() {
        let shares = match sig_shares_by_input.get(&dbc.name()) {
            Some(s) => s,
            None => {
                return Err(anyhow!(
                    "Signature Shares not found for input Dbc {}",
                    encode(&dbc.name())
                ))
            }
        };
        let pubkeyset = tx
            .inputs_owners
            .get(&dbc.name())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;

        let sig = pubkeyset
            .combine_signatures(shares)
            .map_err(|e| Error::msg(format!("{}", e)))?;
        proofs.insert(dbc.name(), (pubkeyset.public_key(), sig));
    }

    println!("\n\nThank-you.   Preparing ReissueRequest...\n\n");

    let reissue_request = ReissueRequestUnblinded {
        inner: ReissueRequest {
            transaction: tx.inner.clone(),
            input_ownership_proofs: proofs,
        },
        inputs_owners: tx.inputs_owners.clone(),
        outputs_owners: tx.outputs_owners,
    };

    println!("\n-- ReissueRequest --");
    println!("{}", to_be_hex(&reissue_request)?);
    println!("-- End ReissueRequest --\n");

    Ok(())
}

/// Implements reissue command.
fn reissue(mintinfo: &mut MintInfo) -> Result<()> {
    let mr_input = readline_prompt_nl("\nReissueRequest: ")?;
    let reissue_request: ReissueRequestUnblinded = from_be_hex(&mr_input)?;

    println!("\n\nThank-you.   Generating DBC(s)...\n\n");

    let input_hashes = reissue_request
        .inner
        .transaction
        .inputs
        .iter()
        .map(|e| e.name())
        .collect::<BTreeSet<_>>();

    reissue_exec(
        mintinfo,
        &reissue_request.inner,
        &input_hashes,
        &reissue_request.outputs_owners,
    )
}

/// Implements reissue_ez command.
fn reissue_ez(mintinfo: &mut MintInfo) -> Result<()> {
    let mut inputs: HashMap<DbcUnblinded, BTreeMap<usize, SecretKeyShare>> = Default::default();
    let mut inputs_total: u64 = 0;
    let mut inputs_bf_sum: Scalar = Default::default();

    // Get from user: input DBC(s) and required # of SecretKeyShare+index for each.
    loop {
        println!("--------------");
        println!("Input DBC #{}", inputs.len());
        println!("--------------\n");

        let dbc_input = readline_prompt_nl("\nDBC Data, or 'done': ")?;
        let dbc: DbcUnblinded = if dbc_input == "done" {
            break;
        } else {
            from_be_hex(&dbc_input)?
        };

        println!(
            "We need {} SecretKeyShare in order to decrypt the input amount.",
            dbc.owner.threshold() + 1
        );

        let mut secrets: BTreeMap<usize, SecretKeyShare> = Default::default();
        while secrets.len() < dbc.owner.threshold() + 1 {
            let key = readline_prompt_nl("\nSecretKeyShare, or 'cancel': ")?;
            let secret = if key == "cancel" {
                println!("\nreissue_ez cancelled\n");
                return Ok(());
            } else {
                from_be_hex(&key)?
            };
            let idx_input = readline_prompt("\nSecretKeyShare Index: ")?;
            let idx: usize = idx_input.parse()?;

            secrets.insert(idx, secret);
        }
        let amount_secrets = dbc
            .inner
            .content
            .amount_secrets_by_secret_key_shares(&dbc.owner, &secrets)?;
        inputs_total += amount_secrets.amount;
        inputs_bf_sum += amount_secrets.blinding_factor;

        inputs.insert(dbc, secrets);
    }

    let input_hashes = inputs
        .iter()
        .map(|(dbc, _)| dbc.inner.name())
        .collect::<BTreeSet<_>>();

    //    let inputs_total: u64 = inputs.iter().map(|(dbc, _)| dbc.inner.content.amount).sum();
    //    let inputs_bf_sum: Scalar = inputs.iter().map(|(dbc, _)| dbc.inner.content.blinding_factor).sum();
    let mut i = 0u32;
    let mut outputs: HashSet<DbcContent> = Default::default();

    let mut outputs_pks: HashMap<Hash, PublicKeySet> = Default::default();
    let mut outputs_total = 0u64;
    let mut outputs_bf_sum = Scalar::default();

    // Get from user: Amount and PublicKeySet for each output DBC
    // note, we upcast to i128 to allow negative value.
    // This permits unbalanced inputs/outputs to reach sn_dbc layer for validation.
    while inputs_total as i128 - outputs_total as i128 > 0 {
        println!();
        println!("------------");
        println!("Output #{}", i);
        println!("------------\n");

        let remaining = inputs_total - outputs_total;
        println!("Inputs total: {}.  Remaining: {}", inputs_total, remaining);
        let line = readline_prompt("Amount, or 'cancel': ")?;
        let amount: u64 = if line == "cancel" {
            println!("\nreissue_ez cancelled\n");
            return Ok(());
        } else {
            line.parse()?
        };
        if amount > remaining || amount == 0 {
            let answer = readline_prompt(&format!(
                "\nThe amount should normally be in the range 1..{}. Change it? [y/n]: ",
                remaining
            ))?;
            if answer.to_ascii_lowercase() != "n" {
                continue;
            }
        }

        let line = readline_prompt_nl("\nPublicKeySet, or 'cancel': ")?;
        let pub_out = if line == "cancel" {
            break;
        } else {
            line
        };

        let pub_out_set: PublicKeySet = from_be_hex(&pub_out)?;

        let blinding_factor = DbcContent::calc_blinding_factor(
            outputs_total + amount == inputs_total,
            inputs_bf_sum,
            outputs_bf_sum,
        );

        let dbc_content = DbcContent::new(
            input_hashes.clone(),     // parents
            amount,                   // amount
            i,                        // output_number
            pub_out_set.public_key(), // owner
            blinding_factor,
        )?;

        outputs_pks.insert(dbc_content.hash(), pub_out_set.clone());

        outputs_total += amount;
        outputs_bf_sum += blinding_factor;
        outputs.insert(dbc_content);
        i += 1;
    }

    println!("\n\nThank-you.   Generating DBC(s)...\n\n");

    let tx_inputs: HashSet<Dbc> = inputs.keys().map(|d| d.inner.clone()).collect();
    let transaction = ReissueTransaction {
        inputs: tx_inputs,
        outputs,
    };

    // for each input Dbc, combine owner's SignatureShare(s) to obtain owner's Signature
    let mut proofs: HashMap<Hash, (PublicKey, Signature)> = Default::default();
    for (dbc, secrets) in inputs.iter() {
        let mut sig_shares: BTreeMap<usize, SignatureShare> = Default::default();
        for (idx, secret) in secrets.iter() {
            let sig_share = secret.sign(&transaction.blinded().hash());
            sig_shares.insert(*idx, sig_share.clone());
        }
        let sig = dbc
            .owner
            .combine_signatures(&sig_shares)
            .map_err(|e| anyhow!(e))?;
        proofs.insert(dbc.inner.name(), (dbc.owner.public_key(), sig));
    }

    let reissue_request = ReissueRequest {
        transaction,
        //        input_ownership_proofs: HashMap::from_iter([(mintinfo.genesis.name(), sig)]),
        input_ownership_proofs: proofs,
    };

    reissue_exec(mintinfo, &reissue_request, &input_hashes, &outputs_pks)
}

/// Performs reissue
fn reissue_exec(
    mintinfo: &mut MintInfo,
    reissue_request: &ReissueRequest,
    input_hashes: &BTreeSet<Hash>,
    outputs_pks: &HashMap<Hash, PublicKeySet>,
) -> Result<()> {
    let mut results: Vec<(DbcTransaction, MintSignatures)> = Default::default();
    let mut mint_sig_shares: Vec<NodeSignature> = Default::default();

    // Mint is multi-node.  So each mint node must execute Mint::reissue() and
    // provide its SignatureShare, which the client must then combine together
    // to form the mint's Signature.  This loop would exec on the client.
    for mint in mintinfo.mintnodes.iter_mut() {
        // here we pretend the client has made a network request to a single mint node
        // so this mint.reissue() execs on the Mint node and returns data to client.
        let (transaction, transaction_sigs) =
            mint.reissue(reissue_request.clone(), input_hashes.clone())?;

        // and now we are back to client code.

        // Verify transaction returned to us by the Mint matches our request
        assert_eq!(reissue_request.transaction.blinded(), transaction);

        // Make a list of NodeSignature (sigshare from each Mint Node)
        let mut node_shares: Vec<NodeSignature> =
            transaction_sigs.iter().map(|e| e.1 .1.clone()).collect();
        mint_sig_shares.append(&mut node_shares);

        // Verify signatures corespond to each input
        let (pubkey, sig) = transaction_sigs
            .values()
            .cloned()
            .next()
            .ok_or_else(|| anyhow!("Signature not found"))?;
        for input in reissue_request.transaction.inputs.iter() {
            assert_eq!(
                transaction_sigs.get(&input.name()),
                Some(&(pubkey.clone(), sig.clone()))
            );
        }
        assert_eq!(transaction_sigs.len(), transaction.inputs.len());

        results.push((transaction, transaction_sigs));
    }

    // Transform Vec<NodeSignature> to Vec<u64, &SignatureShare>
    let mint_sig_shares_ref: Vec<(u64, &SignatureShare)> = mint_sig_shares
        .iter()
        .map(|e| e.threshold_crypto())
        .collect();

    // Combine signatures from all the mint nodes to obtain Mint's Signature.
    let mint_sig = mintinfo
        .secret_key_set
        .public_keys()
        .combine_signatures(mint_sig_shares_ref)
        .map_err(|e| anyhow!(e))?;

    // Obtain a copy of the tx and sigs from the first MintNode results.
    let (transaction, transaction_sigs) = results
        .get(0)
        .ok_or_else(|| anyhow!("Signature not found"))?;

    // Form the final output DBCs, with Mint's Signature for each.
    let mut output_dbcs: Vec<Dbc> = reissue_request
        .transaction
        .outputs
        .iter()
        .map(|content| Dbc {
            content: content.clone(),
            transaction: transaction.clone(),
            transaction_sigs: transaction_sigs
                .iter()
                .map(|(input, _)| {
                    (
                        *input,
                        (mintinfo.genesis.owner.public_key(), mint_sig.clone()),
                    )
                })
                .collect(),
        })
        .collect();

    // sort outputs by output_number
    output_dbcs.sort_by_key(|d| d.content.output_number);

    // for each output, construct DbcUnblinded and display
    for dbc in output_dbcs.iter() {
        let pubkeyset = outputs_pks
            .get(&dbc.content.hash())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;
        let dbc_owned = DbcUnblinded {
            inner: dbc.clone(),
            owner: pubkeyset.clone(),
        };

        println!("\n-- Begin DBC --");
        print_dbc_human(&dbc_owned, false, None)?;
        println!("-- End DBC --\n");
    }

    Ok(())
}

/// Makes a new random SecretKeySet
fn mk_secret_key_set(threshold: usize) -> Result<(Poly, SecretKeySet)> {
    let mut rng = rand::thread_rng();
    let poly = Poly::try_random(threshold, &mut rng).map_err(|e| anyhow!(e))?;
    Ok((poly.clone(), SecretKeySet::from(poly)))
}

/// Serialize a SecretKeyShare as big endian bytes
fn sks_to_bytes(sk: &SecretKeyShare) -> Result<Vec<u8>> {
    bincode::serialize(&SerdeSecret(&sk))
        .map(bincode_bytes_to_big_endian_bytes)
        .map_err(|e| anyhow!(e))
}

/// Serialize anything serializable as big endian bytes
fn to_be_bytes<T: Serialize>(sk: &T) -> Result<Vec<u8>> {
    bincode::serialize(&sk)
        .map(bincode_bytes_to_big_endian_bytes)
        .map_err(|e| anyhow!(e))
}

/// Serialize anything serializable as big endian bytes, hex encoded.
fn to_be_hex<T: Serialize>(sk: &T) -> Result<String> {
    Ok(encode(to_be_bytes(sk)?))
}

/// Deserialize anything deserializable from big endian bytes
fn from_be_bytes<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T> {
    let bb = big_endian_bytes_to_bincode_bytes(b.to_vec());
    bincode::deserialize(&bb).map_err(|e| anyhow!(e))
}

/// Deserialize anything deserializable from big endian bytes, hex encoded.
fn from_be_hex<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    from_be_bytes(&decode(s)?)
}

/// Prompts for input and reads the input.
/// Re-prompts in a loop if input is empty.
fn readline_prompt(prompt: &str) -> Result<String> {
    use std::io::Write;
    loop {
        print!("{}", prompt);
        std::io::stdout().flush()?;
        let line = readline()?;
        if !line.is_empty() {
            return Ok(line);
        }
    }
}

/// Prompts for input and reads the input.
/// Re-prompts in a loop if input is empty.
fn readline_prompt_nl(prompt: &str) -> Result<String> {
    loop {
        println!("{}", prompt);
        let line = readline()?;
        if !line.is_empty() {
            return Ok(line);
        }
    }
}

/// Reads stdin to end of line, and strips newline
fn readline() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?; // including '\n'
    Ok(line.trim().to_string())
}

/// Hex encode bytes
fn encode<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data)
}

/// Hex decode to bytes
fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>> {
    hex::decode(data).map_err(|e| anyhow!(e))
}

// borrowed from: https://github.com/iancoleman/threshold_crypto_ui/blob/master/src/lib.rs
//
// bincode is little endian encoding, see
// https://docs.rs/bincode/1.3.2/bincode/config/trait.Options.html#options
// but SecretKey.reveal() gives big endian hex
// and all other bls implementations specify bigendian.
// Also see
// https://safenetforum.org/t/simple-web-based-tool-for-bls-keys/32339/37
// so to deserialize a big endian bytes using bincode
// we must convert to little endian bytes
fn big_endian_bytes_to_bincode_bytes(mut beb: Vec<u8>) -> Vec<u8> {
    beb.reverse();
    beb
}

/// converts from bincode serialized bytes to big endian bytes.
fn bincode_bytes_to_big_endian_bytes(mut bb: Vec<u8>) -> Vec<u8> {
    bb.reverse();
    bb
}

/// Unsets TTY ICANON.  So readline() can read more than 4096 bytes.
///
/// returns FD of our input TTY and the previous settings
#[cfg(unix)]
fn unset_tty_icanon() -> Result<(RawFd, Termios)> {
    let tty_fd = std::io::stdin().as_raw_fd();
    let termios_old = Termios::from_fd(tty_fd).unwrap();
    let mut termios_new = termios_old;
    termios_new.c_lflag &= !ICANON;
    tcsetattr(tty_fd, TCSADRAIN, &termios_new)?;
    Ok((tty_fd, termios_old))
}
