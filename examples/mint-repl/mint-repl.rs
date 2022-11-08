// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Safe Network DBC Mint CLI playground.
#![allow(clippy::from_iter_instead_of_collect)]

use anyhow::{anyhow, Result};

use rustyline::{config::Configurer, error::ReadlineError, Editor};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

use sn_dbc::{
    blsttc::{
        poly::Poly, serde_impl::SerdeSecret, PublicKey, PublicKeySet, SecretKey, SecretKeySet,
        SecretKeyShare,
    },
    mock,
    rand::{seq::IteratorRandom, Rng},
    rng, Dbc, DbcBuilder, OutputOwnerMap, Owner, OwnerOnce, RevealedCommitment, RingCtMaterial,
    RingCtTransaction, Token, TransactionBuilder,
};

use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;

#[cfg(unix)]
use std::os::unix::{io::AsRawFd, prelude::RawFd};

#[cfg(unix)]
use termios::{tcsetattr, Termios, ICANON, TCSADRAIN};

const STD_DECOYS_TO_FETCH: usize = 1000; // how many decoys to fetch from spentbook (if available)
const STD_DECOYS_PER_INPUT: usize = 3; // how many decoys to use per input (when available)

/// Holds information about the Mint, which may be comprised
/// of 1 or more nodes.
struct MintInfo {
    spentbook_nodes: Vec<mock::SpentBookNode>,
    genesis: Dbc,
    secret_key_set: SecretKeySet,
    poly: Poly,
    reissue_auto: ReissueAuto,
}

impl MintInfo {
    // returns the first spentbook node.
    fn spentbook(&self) -> Result<&mock::SpentBookNode> {
        self.spentbook_nodes
            .get(0)
            .ok_or_else(|| anyhow!("Spentbook not yet created"))
    }
}

/// A RingCtTransaction with pubkey set for all the input and output Dbcs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RingCtTransactionRevealed {
    inner: RingCtTransaction,
    revealed_commitments: Vec<RevealedCommitment>,
    ringct_material: RingCtMaterial,
    output_owner_map: OutputOwnerMap,
}

/// program entry point and interactive command handler.
fn main() -> Result<()> {
    // Disable TTY ICANON.  So readline() can read more than 4096 bytes.
    // termios_old has the previous settings so we can restore before exit.
    #[cfg(unix)]
    let (tty_fd, termios_old) = unset_tty_icanon()?;

    print_logo();
    println!("Type 'help' to get started.\n");

    // Create a default mint with money supply = 1000.
    let mut mintinfo: MintInfo = mk_new_random_mint(0)?;

    let mut rl = Editor::<()>::new()?;
    rl.set_auto_add_history(true);
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let mut args = line.split_whitespace();
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

                    // Not necessary until multisig Dbc owner is supported
                    // "prepare_tx" => prepare_tx_cli(&mintinfo),
                    // "sign_tx" => sign_tx_cli(),
                    // "prepare_reissue" => prepare_reissue_cli(&mut mintinfo),
                    // "reissue_prepared" => reissue_prepared_cli(&mut mintinfo),
                    "reissue" => reissue_cli(&mut mintinfo),
                    "reissue_auto" => reissue_auto_cli(&mut mintinfo),
                    "verify" => verify(&mintinfo),
                    "newkey" => newkey(),
                    "newkeys" => newkeys(),
                    "decode" => decode_input(),
                    "quit" | "exit" => break,
                    "help" => {
                        println!(
                            "\nCommands:\n  Mint:    [mintinfo, newmint]\n  Client:  [newkey, newkeys, reissue, reissue_auto, decode, verify]\n  General: [exit, help]\n"
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
            mk_new_random_mint(threshold)?
        }
        _ => {
            let poly: Poly = from_be_hex(&poly_input)?;
            let secret_key_set = SecretKeySet::from(poly.clone());
            mk_new_mint(secret_key_set, poly)?
        }
    };

    println!("\nMint created!\n");

    Ok(mintinfo)
}

/// creates a new mint using a random seed.
fn mk_new_random_mint(threshold: usize) -> Result<MintInfo> {
    let (poly, secret_key_set) = mk_secret_key_set(threshold)?;
    mk_new_mint(secret_key_set, poly)
}

/// creates a new mint from an existing SecretKeySet that was seeded by poly.
fn mk_new_mint(sks: SecretKeySet, poly: Poly) -> Result<MintInfo> {
    let mut rng = rng::from_seed([0u8; 32]);

    let num_spentbook_nodes = sks.threshold() + 1;

    let (spentbook_nodes, genesis_dbc, _genesis, _amount_secrets) = mock::GenesisBuilder::default()
        .gen_spentbook_nodes_with_sks(num_spentbook_nodes, &sks)
        .build(&mut rng)?;

    let reissue_auto = ReissueAuto::from(vec![genesis_dbc.clone()]);

    // Bob's your uncle.
    Ok(MintInfo {
        spentbook_nodes,
        genesis: genesis_dbc,
        secret_key_set: sks,
        poly,
        reissue_auto,
    })
}

/// handles newkey command. generates SecretKeySet from random seed or user-supplied seed.
fn newkey() -> Result<()> {
    let poly_input =
        readline_prompt_nl("\nPoly of existing SecretKeySet (or [n]ew to generate new key): ")?;

    // Get poly and SecretKeySet from user, or make new random
    let (poly, sks) = match poly_input.as_str() {
        "n" => {
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

    println!("\n -- SecretKeyShares --");
    for i in 0..sks.threshold() + 5 {
        println!(
            "  {}. {}",
            i,
            encode(sks_to_bytes(&sks.secret_key_share(i))?)
        );
    }

    println!("\n -- PublicKeyShares --");
    for i in 0..sks.threshold() + 5 {
        // the 2nd line matches ian coleman's bls tool output.  but why not the first?
        //        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!(
            "  {}. {}",
            i,
            encode(sks.public_keys().public_key_share(i).to_bytes())
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

    println!("SecretKey: {}", to_be_hex(&SerdeSecret(sks.secret_key()))?);
    println!("PublicKey: {}", to_be_hex(&sks.public_keys().public_key())?);

    println!("\n");

    Ok(())
}

/// handles newkeys command. generates N random keypairs
fn newkeys() -> Result<()> {
    let num: usize = readline_prompt("\nHow many keys to generate? ")?.parse()?;

    let num_signers = 1;
    assert!(num_signers > 0);

    for idx in 1..=num {
        println!("\n");
        let (_poly, sks) = mk_secret_key_set(num_signers - 1)?;

        println!("-- KeyPair #{} --", idx);
        println!(
            "  SecretKey: {}",
            to_be_hex(&SerdeSecret(sks.secret_key()))?
        );
        println!(
            "  PublicKey: {}",
            to_be_hex(&sks.public_keys().public_key())?
        );
    }

    println!("\n");

    Ok(())
}

/// Displays mint information in human readable form
fn print_mintinfo_human(mintinfo: &MintInfo) -> Result<()> {
    println!();

    println!(
        "Number of Spentbook Nodes: {}\n",
        mintinfo.spentbook_nodes.len()
    );

    println!("-- Spentbook Keys --\n");
    println!("SecretKeySet (Poly): {}\n", to_be_hex(&mintinfo.poly)?);

    println!(
        "PublicKeySet: {}\n",
        to_be_hex(&mintinfo.secret_key_set.public_keys())?
    );

    println!(
        "PublicKey: {}\n",
        to_be_hex(&mintinfo.secret_key_set.public_keys().public_key())?
    );

    println!("\n   -- SecretKeyShares --");
    for i in 0..mintinfo.secret_key_set.threshold() + 2 {
        println!(
            "    {}. {}",
            i,
            encode(sks_to_bytes(&mintinfo.secret_key_set.secret_key_share(i))?)
        );
    }

    let mut secret_key_shares: BTreeMap<usize, SecretKeyShare> = Default::default();

    println!("\n   -- PublicKeyShares --");
    for i in 0..mintinfo.secret_key_set.threshold() + 2 {
        // the 2nd line matches ian coleman's bls tool output.  but why not the first?
        //        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!(
            "    {}. {}",
            i,
            encode(
                mintinfo
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
    print_dbc_human(&mintinfo.genesis, true, None)?;

    for (i, spentbook) in mintinfo.spentbook_nodes.iter().enumerate() {
        println!("\n-- SpentBook Node {} --\n", i);
        for (key_image, _tx) in spentbook.iter() {
            println!("  {}", encode(key_image.to_bytes()));
        }
    }

    println!();

    Ok(())
}

/// displays Dbc in human readable form
fn print_dbc_human(dbc: &Dbc, outputs: bool, secret_key_base: Option<SecretKey>) -> Result<()> {
    println!("hash: {}\n", encode(dbc.hash()));

    let result = match secret_key_base {
        // use base SecretKey from input param if available.
        Some(key_base) => Some((dbc.owner_once(&key_base)?, dbc.amount_secrets(&key_base)?)),

        // use base SecretKey from dbc if available (bearer)
        None if dbc.is_bearer() => Some((dbc.owner_once_bearer()?, dbc.amount_secrets_bearer()?)),

        // Otherwise, have only the pubkey
        _ => None,
    };

    match result {
        Some((ref _owner_once, ref amount_secrets)) => {
            println!("*** Secrets (decrypted) ***");
            println!("     amount: {}\n", amount_secrets.amount());
            println!(
                "     blinding_factor: {}\n",
                to_be_hex(&amount_secrets.blinding_factor())?
            );
        }
        None => {
            println!("amount: unknown.  SecretKey not available\n");
        }
    }

    println!(
        "owner_base_public_key: {}\n",
        to_be_hex(&dbc.owner_base().public_key())?
    );
    println!(
        "owner_one_time_public_key: {}\n",
        match result {
            Some((owner_once, _)) => to_be_hex::<PublicKey>(&owner_once.public_key())?,
            None => "SecretKey not available".to_string(),
        }
    );
    println!("is_bearer: {:?}\n", dbc.is_bearer());

    println!("inputs:");
    for i in &dbc.transaction.mlsags {
        println!("  {}", encode(i.to_bytes()))
    }

    if outputs {
        println!("\noutputs:");
        for i in &dbc.transaction.outputs {
            println!("  {}", encode(i.to_bytes()))
        }
    }

    println!("\nData:");
    println!("{}", to_be_hex(&dbc)?);
    Ok(())
}

/// handles decode command.
fn decode_input() -> Result<()> {
    let t = readline_prompt(
        "\n[d: DBC, rt: RingCtTransaction, pks: PublicKeySet, sks: SecretKeySet]\nType: ",
    )?;
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

                    println!("\n\n-- Start DBC --\n");
                    print_dbc_human(&from_be_bytes(&bytes)?, true, Some(sks.secret_key()))?;
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
            println!("  public_key: {}", encode(pks.public_key().to_bytes()));
            // temporary: the 2nd line matches ian coleman's bls tool output.  but why not the first?
            //            println!("PublicKeyShare[0]: {}", to_be_hex(&pks.public_key_share(0))? );
            println!("\n  PublicKeyShares:");
            for i in 0..pks.threshold() + 1 {
                println!("    {i} : {}", encode(pks.public_key_share(i).to_bytes()));
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
            "\n\n-- RingCtTransaction --\n\n{:#?}",
            from_be_bytes::<RingCtTransactionRevealed>(&bytes)?
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

/// Implements verify command.  Validates signatures and that a
/// DBC has not been double-spent.  Also checks if spent/unspent.
fn verify(mintinfo: &MintInfo) -> Result<()> {
    let dbc_input = readline_prompt_nl("\nInput DBC, or '[c]ancel': ")?;
    let dbc: Dbc = if dbc_input == "c" {
        println!("\nVerify cancelled\n");
        return Ok(());
    } else {
        from_be_hex(&dbc_input)?
    };

    let secret_key = match dbc.owner_base() {
        Owner::SecretKey(sk) => sk.inner().clone(),
        Owner::PublicKey(_pk) => {
            let sk_input = readline_prompt_nl("\nSecret Key, or '[c]ancel': ")?;
            let sk: SecretKey = if dbc_input == "c" {
                println!("\nVerify cancelled\n");
                return Ok(());
            } else {
                from_be_hex(&sk_input)?
            };
            sk
        }
    };

    match dbc.verify(&secret_key, &mintinfo.spentbook()?.key_manager) {
        Ok(_) => match mintinfo.spentbook()?.is_spent(&dbc.key_image(&secret_key)?) {
            true => println!("\nThis DBC is unspendable.  (valid but has already been spent)\n"),
            false => println!("\nThis DBC is spendable.   (valid and has not been spent)\n"),
        },
        Err(e) => println!("\nInvalid DBC.  {}", e),
    }

    Ok(())
}

/// Implements prepare_tx command.
fn prepare_tx(mintinfo: &MintInfo) -> Result<DbcBuilder> {
    let decoy_inputs = mintinfo
        .spentbook()?
        .random_decoys(STD_DECOYS_TO_FETCH, &mut rng::thread_rng());

    let mut tx_builder = TransactionBuilder::default()
        .set_decoys_per_input(STD_DECOYS_PER_INPUT)
        .set_require_all_decoys(false)
        .add_decoy_inputs(decoy_inputs);

    // Get DBC inputs from user
    loop {
        let dbc_input = readline_prompt_nl("\nInput DBC, or '[d]one': ")?;
        let dbc: Dbc = if dbc_input == "d" {
            break;
        } else {
            from_be_hex(&dbc_input)?
        };

        let base_secret_key = match dbc.owner_base() {
            Owner::SecretKey(sk) => sk.inner().clone(),
            Owner::PublicKey(_) => {
                println!("We need a SecretKey in order to decrypt the input amount.");
                loop {
                    let key = readline_prompt_nl("\nSecretKey: ")?;
                    let secret: SecretKey = match from_be_hex(&key) {
                        Ok(k) => k,
                        Err(_e) => {
                            println!("Invalid key");
                            continue;
                        }
                    };
                    break secret;
                }
            }
        };

        tx_builder = tx_builder.add_input_dbc(&dbc, &base_secret_key)?;
    }

    let mut i = 0u32;

    // Get outputs from user
    // note, we upcast to i128 to allow negative value.
    // This permits unbalanced inputs/outputs to reach sn_dbc layer for verification.
    let inputs_amount_sum = tx_builder.inputs_amount_sum();
    while let Some(remaining) = inputs_amount_sum.checked_sub(tx_builder.outputs_amount_sum()) {
        println!();
        println!("------------");
        println!("Output #{}", i);
        println!("------------\n");

        println!(
            "Inputs total: {}.  Remaining: {}",
            inputs_amount_sum, remaining
        );
        let line = readline_prompt("Token, or '[c]ancel': ")?;
        let amount: Token = if line == "c" {
            println!("\nprepare_tx cancelled\n");
            break;
        } else {
            line.parse()?
        };
        if amount > remaining || amount == Token::zero() {
            let answer = readline_prompt(&format!(
                "\nThe amount should normally be in the range 1..{}. Change it? [y/n]: ",
                remaining
            ))?;
            if answer.to_ascii_lowercase() != "n" {
                continue;
            }
        }

        let owner_base = loop {
            let result =
                match readline_prompt_nl("\n[b]earer, [o]wned, [r]andom bearer, or [c]ancel: ")?
                    .as_str()
                {
                    "b" => match readline_prompt_nl("\nSecretKey, or '[c]ancel': ")?.as_str() {
                        "c" => return Err(anyhow!("Cancelled")),
                        line => {
                            let secret_key: SecretKey = from_be_hex(line)?;
                            Some(Owner::from(secret_key))
                        }
                    },
                    "o" => match readline_prompt_nl("\nPublicKey, or '[c]ancel': ")?.as_str() {
                        "c" => return Err(anyhow!("Cancelled")),
                        line => {
                            let public_key: PublicKey = from_be_hex(line)?;
                            Some(Owner::from(public_key))
                        }
                    },
                    "r" => Some(Owner::from_random_secret_key(&mut rng::thread_rng())),
                    "c" => return Err(anyhow!("Cancelled")),
                    _ => None,
                };
            if let Some(ob) = result {
                break ob;
            }
        };

        let owner_once = OwnerOnce::from_owner_base(owner_base, &mut rng::thread_rng());

        tx_builder = tx_builder.add_output_by_amount(amount, owner_once);

        i += 1;
    }

    println!("\n\nPreparing RingCtTransaction...\n\n");

    let dbc_builder = tx_builder.build(rng::thread_rng())?;

    Ok(dbc_builder)
}

fn write_to_spentbook(mintinfo: &mut MintInfo, mut dbc_builder: DbcBuilder) -> Result<DbcBuilder> {
    println!("\nWriting to Spentbook...\n\n");
    for (key_image, tx) in dbc_builder.inputs() {
        for (sp_idx, sb_node) in mintinfo.spentbook_nodes.iter_mut().enumerate() {
            println!("logging input {:?}, spentbook {}", key_image, sp_idx);
            dbc_builder =
                dbc_builder.add_spent_proof_share(sb_node.log_spent(key_image, tx.clone())?);
        }
        dbc_builder = dbc_builder.add_spent_transaction(tx);
    }
    Ok(dbc_builder)
}

struct ReissueAuto {
    pub(crate) unspent_dbcs: HashMap<[u8; 32], Dbc>,
}

impl From<Vec<Dbc>> for ReissueAuto {
    fn from(unspent_dbcs: Vec<Dbc>) -> Self {
        Self {
            unspent_dbcs: HashMap::from_iter(unspent_dbcs.into_iter().map(|d| (d.hash(), d))),
        }
    }
}

fn reissue_auto_cli(mintinfo: &mut MintInfo) -> Result<()> {
    let mut rng = rng::thread_rng();

    let num_reissues: usize =
        readline_prompt_default("\nHow many reissues to perform [10]: ", "10")?.parse()?;

    let min_inputs: usize =
        readline_prompt_default("\nMin (if available) number of inputs [1]: ", "1")?.parse()?;

    let max_inputs: usize =
        readline_prompt_default("\nMax number of inputs [2]: ", "2")?.parse()?;

    let max_outputs: usize =
        readline_prompt_default("\nMax number of outputs [2]: ", "2")?.parse()?;

    let max_decoys: usize =
        readline_prompt_default("\nMax number of decoys [10]: ", "10")?.parse()?;

    println!(
        "\ninputs to outputs.  value                  wallet     sb::random_decoys  sb::log_spent  total"
    );

    for _i in 1..=num_reissues {
        let iter_time_start = SystemTime::now();

        let max_inputs = std::cmp::min(mintinfo.reissue_auto.unspent_dbcs.len(), max_inputs);
        let min_inputs = std::cmp::min(min_inputs, max_inputs);
        let num_inputs = rng.gen_range(min_inputs..max_inputs + 1);

        // subset of unspent_dbcs become the inputs for next reissue.
        let input_dbcs: Vec<Dbc> = mintinfo
            .reissue_auto
            .unspent_dbcs
            .iter()
            .choose_multiple(&mut rng, num_inputs)
            .iter()
            .map(|(_, d)| (*d).clone())
            .collect();

        let random_decoys_start = SystemTime::now();
        let decoy_inputs = mintinfo
            .spentbook()?
            .random_decoys(STD_DECOYS_TO_FETCH, &mut rng);
        let random_decoys_duration = random_decoys_start.elapsed().unwrap();

        let mut tx_builder = TransactionBuilder::default()
            .set_decoys_per_input(max_decoys)
            .set_require_all_decoys(false)
            .add_decoy_inputs(decoy_inputs);

        for dbc in input_dbcs.iter() {
            let base_sk = dbc.owner_base().secret_key()?;
            tx_builder = tx_builder.add_input_dbc(dbc, &base_sk)?;
        }

        let inputs_sum = tx_builder.inputs_amount_sum();

        while tx_builder.outputs_amount_sum() < inputs_sum || tx_builder.outputs().is_empty() {
            let amount = if tx_builder.outputs().len() >= max_outputs - 1 {
                inputs_sum.as_nano() - tx_builder.outputs_amount_sum().as_nano()
            } else {
                // randomize output amount
                let diff = inputs_sum.as_nano() - tx_builder.outputs_amount_sum().as_nano();

                let is_last = rng.gen_range(0..max_outputs + 1) == max_outputs;
                if is_last {
                    diff
                } else {
                    let range_max = if diff == u64::MAX { diff } else { diff + 1 };
                    rng.gen_range(0..range_max)
                }
            };

            let owner_once =
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

            tx_builder = tx_builder.add_output_by_amount(Token::from_nano(amount), owner_once);
        }

        let mut dbc_builder = tx_builder.build(&mut rng)?;

        let mut log_spent_duration = Duration::new(0, 0);
        for (key_image, tx) in dbc_builder.inputs() {
            for spentbook_node in mintinfo.spentbook_nodes.iter_mut() {
                let log_spent_start = SystemTime::now();
                let spent_proof_share = spentbook_node.log_spent(key_image, tx.clone())?;
                log_spent_duration += log_spent_start.elapsed().unwrap();
                dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
            }
        }
        let outputs = dbc_builder.build(&mintinfo.spentbook()?.key_manager)?;
        let output_dbcs: Vec<Dbc> = outputs.into_iter().map(|(dbc, ..)| dbc).collect();

        for dbc in input_dbcs.iter() {
            mintinfo.reissue_auto.unspent_dbcs.remove(&dbc.hash());
        }

        let iter_duration = iter_time_start.elapsed().unwrap();
        let wallet_duration = iter_duration - log_spent_duration - random_decoys_duration;

        println!(
            "{:>6} -> {:<8}  {:<22} {:<10} {:<10}         {:<10}     {:<10}",
            input_dbcs.len(),
            output_dbcs.len(),
            inputs_sum,
            fd(wallet_duration),
            fd(random_decoys_duration),
            fd(log_spent_duration),
            fd(iter_duration),
        );

        mintinfo
            .reissue_auto
            .unspent_dbcs
            .extend(output_dbcs.iter().map(|d| (d.hash(), d.clone())));
    }

    Ok(())
}

// format a Duration into secs.millis.
fn fd(duration: Duration) -> String {
    format!("{}.{}", duration.as_secs(), duration.subsec_millis())
}

/// Implements reissue command.
fn reissue_cli(mintinfo: &mut MintInfo) -> Result<()> {
    let dbc_builder = prepare_tx(mintinfo)?;
    let dbc_builder = write_to_spentbook(mintinfo, dbc_builder)?;
    reissue(mintinfo, dbc_builder)
}

/// Performs reissue
fn reissue(mintinfo: &mut MintInfo, dbc_builder: DbcBuilder) -> Result<()> {
    let output_dbcs = dbc_builder.build(&mintinfo.spentbook_nodes[0].key_manager)?;

    // for each output, construct Dbc and display
    for (dbc, _owner_once, _amount_secrets) in output_dbcs.iter() {
        println!("\n-- Begin DBC --");
        print_dbc_human(dbc, false, None)?;
        println!("-- End DBC --\n");
    }

    Ok(())
}

/// Makes a new random SecretKeySet
fn mk_secret_key_set(threshold: usize) -> Result<(Poly, SecretKeySet)> {
    let poly = Poly::try_random(threshold, &mut rng::thread_rng()).map_err(|e| anyhow!(e))?;
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

fn readline_prompt_default(prompt: &str, default: &str) -> Result<String> {
    use std::io::Write;
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let line = readline()?;
    match line.is_empty() {
        true => Ok(default.to_string()),
        false => Ok(line),
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

#[allow(dead_code)]
fn readline_prompt_nl_default(prompt: &str, default: &str) -> Result<String> {
    println!("{}", prompt);
    let line = readline()?;
    match line.is_empty() {
        true => Ok(default.to_string()),
        false => Ok(line),
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
