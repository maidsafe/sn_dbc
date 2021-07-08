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
use blsttc::{PublicKey, PublicKeySet, SecretKeySet, SecretKeyShare, Signature, SignatureShare};
use serde::{Deserialize, Serialize};
use serde_derive as sd;
use serde_json as json;
use sn_dbc::{
    Dbc, DbcContent, DbcTransaction, Hash, Mint, MintSignatures, NodeSignature, ReissueRequest,
    ReissueTransaction, SimpleKeyManager as KeyManager, SimpleSigner as Signer,
    SimpleSpendBook as SpendBook,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;
use structopt::StructOpt;

use preferences_ron::{AppInfo, Preferences};

/// For preferences file
const APP_INFO: AppInfo = AppInfo {
    name: "mint-cli",
    author: "Safe Network",
};

/// For obtaining a DBC output from the user via CLI arg.
#[derive(Debug)]
struct DbcOutput {
    public_key_set: PublicKeySet,
    amount: u64,
}

impl std::str::FromStr for DbcOutput {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        let parts: Vec<&str> = str.split(',').collect();

        let public_key_set: PublicKeySet = from_be_hex(parts[0])?;
        let amount: u64 = parts[1].parse()?;
        Ok(Self {
            public_key_set,
            amount,
        })
    }
}

/// For obtaining a Poly (SecretKeySet seed) from the user via CLI arg.
#[derive(Debug, Clone)]
struct PolyInput {
    inner: Poly,
}

impl std::str::FromStr for PolyInput {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        Ok(Self {
            inner: from_be_hex(str)?,
        })
    }
}

/// For obtaining a SecretKeyShare+input idx+key idx from the user via CLI arg.
#[derive(Debug)]
struct SecretKeyShareInput {
    input_index: usize,
    key_index: usize,
    sks: SecretKeyShare,
}

impl std::str::FromStr for SecretKeyShareInput {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        let parts: Vec<&str> = str.split(':').collect();
        let input_index: usize = parts[0].parse()?;
        let key_index: usize = parts[1].parse()?;
        let sks: SecretKeyShare = from_be_hex(parts[2])?;
        Ok(Self {
            input_index,
            key_index,
            sks,
        })
    }
}

/// For obtaining a DBC and secret key shares from the user via CLI arg.
#[derive(Debug)]
struct DbcSecretKeyShareInput {
    dbc: DbcUnblinded,
    secret_key_shares: BTreeMap<usize, SecretKeyShare>,
}

impl std::str::FromStr for DbcSecretKeyShareInput {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        let parts: Vec<&str> = str.splitn(2, ':').collect();
        let dbc: DbcUnblinded = from_be_hex(parts[0])?;
        let mut secret_key_shares: BTreeMap<usize, SecretKeyShare> = Default::default();
        for share in parts[1].split(':') {
            let s: Vec<&str> = share.split(',').collect();
            let sks = from_be_hex(s[0])?;
            let idx = s[1].parse::<usize>()?;
            secret_key_shares.insert(idx, sks);
        }

        Ok(Self {
            dbc,
            secret_key_shares,
        })
    }
}

/// Available CLI commands
#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(name = "help")]
    /// Help
    Help,
    #[structopt(name = "prepare-tx")]
    /// Prepare Tx
    PrepareTx {
        #[structopt(short, long, required(true))]
        /// Input DBC(s)
        input: Vec<DbcUnblinded>,
        #[structopt(short, long, required(true))]
        /// Output(s) format: PublicKeySet,Amount
        output: Vec<DbcOutput>,
    },
    #[structopt(name = "sign-tx")]
    /// Sign Tx
    SignTx {
        #[structopt(short, long, required(true))]
        /// ReissueTransaction, from prepare_tx
        tx: ReissueTransactionUnblinded,
        #[structopt(short, long, required(true))]
        /// SecretKeyShare(s).  format: DbcIndex:ShareIndex:SecretKeyShare
        secret_key_share: Vec<SecretKeyShareInput>,
    },
    #[structopt(name = "prepare-reissue")]
    /// Prepare Reissue
    PrepareReissue {
        #[structopt(short, long, required(true))]
        /// ReissueTransaction, from prepare_tx
        tx: ReissueTransactionUnblinded,
        #[structopt(short, long, required(true))]
        /// SignatureShareMap, from sign_tx
        signature_share_map: Vec<SignatureSharesMap>,
    },
    #[structopt(name = "reissue")]
    /// reissue
    Reissue {
        /// ReissueRequest, from prepare-reissue
        reissue_request: ReissueRequestUnblinded,
    },
    #[structopt(name = "reissue-ez")]
    /// reissue-ez
    ReissueEz {
        #[structopt(short, long, required(true))]
        /// Input(s). format: Dbc:SecretKeyShare,ShareIndex[:SecretKeyShare,ShareIndex]...
        input: Vec<DbcSecretKeyShareInput>,
        #[structopt(short, long, required(true))]
        /// Output(s). format: PublicKeySet,Amount
        output: Vec<DbcOutput>,
    },
    #[structopt(name = "decode")]
    /// decode
    Decode {
        #[structopt(name = "data-type")]
        /// one of: [d: Dbc, rt: ReissueTransaction, s: SignatureSharesMap, rr: ReissueRequest, pks: PublicKeySet, sks: SecretKeySet]
        data_type: String,
        /// The data to decode
        data: String,
    },
    #[structopt(name = "mintinfo")]
    /// mintinfo
    MintInfo,
    #[structopt(name = "newmint")]
    /// Creates a new mint.  Danger: This will erase old mint and spendbook.
    NewMint {
        /// Total money supply of the mint
        money_supply: u64,
        #[structopt(short, long)]
        /// Polynomial of an existing SecretKeySet.  omit to generate a new SecretKeySet
        poly: Option<PolyInput>,
        #[structopt(short, long)]
        /// Number of Mint nodes (and SecretKeySet signers).  ignored if --poly present.
        num_nodes: Option<usize>,
    },
    #[structopt(name = "newkey")]
    /// newkey
    NewKey {
        #[structopt(name = "num-signers")]
        /// number of required signatures
        num_signers: usize,
    },
    /// Validate a DBC
    Validate {
        /// DBC to be validated
        dbc: DbcUnblinded,
    },
}

/// All available cli arguments
#[derive(Debug, StructOpt)]
#[structopt(global_settings(&[structopt::clap::AppSettings::ColoredHelp]))]
struct CliArgs {
    #[structopt(subcommand)]
    command: Option<Command>,
}

/// Holds information about the Mint, which may be comprised
/// of 1 or more nodes.
#[derive(sd::Serialize, sd::Deserialize, Debug)]
struct MintInfo {
    mintnodes: Vec<Mint<KeyManager, SpendBook>>,
    genesis: DbcUnblinded,
    poly: Poly,
}

impl MintInfo {
    // returns the first mint node.
    fn mintnode(&self) -> Result<&Mint<KeyManager, SpendBook>> {
        self.mintnodes
            .get(0)
            .ok_or_else(|| anyhow!("Mint not yet created"))
    }

    fn secret_key_set(&self) -> SecretKeySet {
        SecretKeySet::from(self.poly.clone())
    }
}

/// A Dbc plus the owner's pubkey set
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct DbcUnblinded {
    inner: Dbc,
    owner: PublicKeySet,
}

impl std::str::FromStr for DbcUnblinded {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        from_be_hex(str)
    }
}

/// A ReissueTransaction with pubkey set for all the input and output Dbcs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReissueTransactionUnblinded {
    inner: ReissueTransaction,
    inputs_owners: HashMap<Hash, PublicKeySet>,
    outputs_owners: HashMap<Hash, PublicKeySet>,
}

impl std::str::FromStr for ReissueTransactionUnblinded {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        from_be_hex(str)
    }
}

/// A ReissueRequest with pubkey set for all the input and output Dbcs
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReissueRequestUnblinded {
    inner: ReissueRequest,
    inputs_owners: HashMap<Hash, PublicKeySet>,
    outputs_owners: HashMap<Hash, PublicKeySet>,
}

impl std::str::FromStr for ReissueRequestUnblinded {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        from_be_hex(str)
    }
}

/// This type is just for serializing HashMap<Hash, <HashMap<usize, SignatureShare>>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SignatureSharesMap(HashMap<Hash, HashMap<usize, SignatureShare>>);

impl std::str::FromStr for SignatureSharesMap {
    type Err = anyhow::Error;
    fn from_str(str: &str) -> Result<Self> {
        from_be_hex(str)
    }
}

/// program entry point and interactive command handler.
fn main() -> Result<()> {
    let prefs_key = "mint";

    // Load prefs from disk, or create new prefs
    let mut mintinfo = match MintInfo::load(&APP_INFO, prefs_key) {
        Ok(p) => p,
        Err(_) => mk_new_random_mint(0, 1000)?,
    };

    // Parse and exec command
    let opt = CliArgs::from_args();
    if let Some(ref cmd) = opt.command {
        match cmd {
            Command::PrepareTx { input, output } => {
                prepare_tx_cli(input, output)?;
            }
            Command::SignTx {
                tx,
                secret_key_share,
            } => {
                sign_tx_cli(tx, secret_key_share)?;
            }
            Command::PrepareReissue {
                tx,
                signature_share_map,
            } => {
                prepare_reissue_cli(tx, signature_share_map)?;
            }
            Command::Reissue { reissue_request } => {
                reissue_cli(&mut mintinfo, reissue_request)?;
                mintinfo.save(&APP_INFO, prefs_key)?;
            }
            Command::ReissueEz { input, output } => {
                reissue_ez_cli(&mut mintinfo, input, output)?;
                mintinfo.save(&APP_INFO, prefs_key)?;
            }
            Command::MintInfo => {
                mintinfo_cli(&mintinfo)?;
            }
            Command::NewMint {
                money_supply,
                poly,
                num_nodes,
            } => {
                mintinfo = newmint_cli(*money_supply, (*poly).clone(), *num_nodes)?;
                mintinfo.save(&APP_INFO, prefs_key)?;
            }
            Command::NewKey { num_signers } => {
                newkey_cli(*num_signers)?;
            }
            Command::Decode { data_type, data } => {
                decode_cli(data_type, data)?;
            }
            Command::Validate { dbc } => {
                validate_cli(&mintinfo, dbc)?;
            }
            _ => {
                println!("Command unimplemented.");
                println!("{:?}", opt);
            }
        }
    }

    // println!("Mint saved to: {:?}", preferences_ron::prefs_base_dir().unwrap());

    Ok(())
}

/// handles newmint command to generate a new mint with N nodes.
fn newmint_cli(
    money_supply: u64,
    poly: Option<PolyInput>,
    num_nodes: Option<usize>,
) -> Result<MintInfo> {
    let mintinfo = match poly {
        None => {
            let nodes = num_nodes.unwrap_or(1);
            mk_new_random_mint(nodes - 1, money_supply)?
        }
        Some(p) => {
            let secret_key_set = SecretKeySet::from(p.inner.clone());
            mk_new_mint(secret_key_set, p.inner, money_supply)?
        }
    };

    let json = json::json!({
        "success": true,
        "msg": "Mint created",
    });

    println!("{}", json::to_string_pretty(&json)?);

    Ok(mintinfo)
}

/// handles newkey command. generates SecretKeySet from random seed or user-supplied seed.
fn newkey_cli(num_signers: usize) -> Result<()> {
    // Get poly and SecretKeySet from user, or make new random
    let (poly, sks) = mk_secret_key_set(num_signers - 1)?;

    let sks_val = secret_key_set_to_json(&sks, &poly, false)?;
    let pks_val = public_key_set_to_json(&sks.public_keys())?;

    let mut root = json::Map::new();
    root.insert("secret_key_set".to_string(), sks_val);
    root.insert("public_key_set".to_string(), pks_val);

    let json = jmap(root);
    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// Displays mint information as json
fn mintinfo_cli(mintinfo: &MintInfo) -> Result<()> {
    let sks_val = secret_key_set_to_json(&mintinfo.secret_key_set(), &mintinfo.poly, false)?;
    let pks_val = public_key_set_to_json(&mintinfo.secret_key_set().public_keys())?;

    let mut spendbook: Vec<json::Value> = Default::default();

    for (dbchash, _tx) in &mintinfo.mintnode()?.spendbook {
        spendbook.push(jstr(encode(&dbchash)));
    }

    let mut root = json::Map::new();
    root.insert("mint_nodes".to_string(), jusize(mintinfo.mintnodes.len()));
    root.insert("secret_key_set".to_string(), sks_val);
    root.insert("public_key_set".to_string(), pks_val);
    root.insert(
        "genesis_dbc".to_string(),
        dbc_to_json(&mintinfo.genesis, true)?,
    );
    root.insert("spendbook".to_string(), jvec(spendbook));

    let json = jmap(root);
    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// handles decode command.  
fn decode_cli(data_type: &str, data: &str) -> Result<()> {
    let bytes = decode(data)?;

    let jval = match data_type {
        "d" => dbc_to_json(&from_be_bytes(&bytes)?, true)?,
        "pks" => {
            let pks: PublicKeySet = from_be_bytes(&bytes)?;
            public_key_set_to_json(&pks)?
        }
        "sks" => {
            let poly: Poly = from_be_bytes(&bytes)?;
            let sks = SecretKeySet::from(poly.clone());
            secret_key_set_to_json(&sks, &poly, true)?
        }
        "rt" => jstr(format!(
            "{:#?}",
            from_be_bytes::<ReissueTransactionUnblinded>(&bytes)?
        )),
        "s" => jstr(format!(
            "{:#?}",
            from_be_bytes::<SignatureSharesMap>(&bytes)?
        )),
        "rr" => jstr(format!(
            "{:#?}",
            from_be_bytes::<ReissueRequestUnblinded>(&bytes)?
        )),
        _ => jstr("Unknown type!".to_string()),
    };

    println!("{}", json::to_string_pretty(&jval)?);

    Ok(())
}

/// Implements validate command.  Validates signatures and that a
/// DBC has not been double-spent.  Also checks if spent/unspent.
fn validate_cli(mintinfo: &MintInfo, dbc: &DbcUnblinded) -> Result<()> {
    let (status, desc) = match dbc.inner.confirm_valid(mintinfo.mintnode()?.key_manager()) {
        Ok(_) => match mintinfo.mintnode()?.is_spent(dbc.inner.name())? {
            true => ("spent", "valid but has already been spent".to_string()),
            false => ("spendable", "valid and has not been spent".to_string()),
        },
        Err(e) => ("invalid", e.to_string()),
    };

    let json = json::json!({
        "status": status,
        "desc": desc,
    });

    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// Implements prepare_tx command.
fn prepare_tx_cli(inputs_cli: &[DbcUnblinded], outputs_cli: &[DbcOutput]) -> Result<()> {
    //    let mut inputs: HashSet<Dbc> = Default::default();
    //    let mut inputs_owners: HashMap<Hash, PublicKeySet> = Default::default();

    let inputs: HashSet<Dbc> = inputs_cli.iter().map(|d| d.inner.clone()).collect();
    let inputs_owners = inputs_cli
        .iter()
        .map(|d| (d.inner.name(), d.owner.clone()))
        .collect();
    let inputs_total: u64 = inputs_cli.iter().map(|d| d.inner.amount()).sum();

    let input_hashes = inputs.iter().map(|e| e.name()).collect::<BTreeSet<_>>();

    let v: Vec<(DbcContent, (Hash, PublicKeySet))> = outputs_cli
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let content = DbcContent::new(
                input_hashes.clone(),          // parents
                o.amount,                      // amount
                i as u32,                      // output_number
                o.public_key_set.public_key(), // public_key
            );
            (content.clone(), (content.hash(), o.public_key_set.clone()))
        })
        .collect();

    let outputs: HashSet<DbcContent> = v.iter().map(|e| e.0.clone()).collect();
    let outputs_owners: HashMap<Hash, PublicKeySet> = v.iter().map(|e| e.1.clone()).collect();
    let outputs_total: u64 = outputs.iter().map(|o| o.amount).sum();

    if outputs.is_empty() {
        return Err(anyhow!("No outputs specified.  Cancelling."));
    }
    if inputs_total - outputs_total != 0 {
        return Err(anyhow!("Input DBC(s) not fully spent."));
    }

    let transaction = ReissueTransactionUnblinded {
        inner: ReissueTransaction { inputs, outputs },
        inputs_owners,
        outputs_owners,
    };

    let json = json::json!({
        "data_type": "ReissueTransaction",
        "data": to_be_hex(&transaction)?,
    });

    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// Implements sign-tx command.
fn sign_tx_cli(
    tx: &ReissueTransactionUnblinded,
    secret_key_shares: &[SecretKeyShareInput],
) -> Result<()> {
    let mut inputs: HashMap<Dbc, HashMap<usize, SecretKeyShare>> = Default::default();

    // Get from cli arg: (index, SecretKeyShare) for each input Dbc
    for (i, dbc) in tx.inner.inputs.iter().enumerate() {
        let pubkeyset = tx
            .inputs_owners
            .get(&dbc.name())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;

        let mut secrets: HashMap<usize, SecretKeyShare> = Default::default();
        for sks in secret_key_shares.iter() {
            if sks.input_index == i {
                secrets.insert(sks.key_index, sks.sks.clone());
            }
        }

        if secrets.len() < pubkeyset.threshold() + 1 {
            return Err(anyhow!(
                "Input DBC #{} requires {} SecretKeyShare but {} provided",
                i,
                pubkeyset.threshold() + 1,
                secrets.len()
            ));
        }

        inputs.insert(dbc.clone(), secrets);
    }

    let mut sig_shares: SignatureSharesMap = Default::default();
    for (dbc, secrets) in inputs.iter() {
        let mut sigs: HashMap<usize, SignatureShare> = Default::default();
        for (idx, secret) in secrets.iter() {
            let sig_share = secret.sign(&tx.inner.blinded().hash());
            sigs.insert(*idx, sig_share);
        }
        sig_shares.0.insert(dbc.name(), sigs);
    }

    let json = json::json!({
        "data_type": "SignatureSharesMap",
        "data": to_be_hex(&sig_shares)?,
    });

    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// Implements prepare-reissue (cli) command.
fn prepare_reissue_cli(
    tx: &ReissueTransactionUnblinded,
    ss_maps: &[SignatureSharesMap],
) -> Result<()> {
    let mut sig_shares_by_input: HashMap<Hash, BTreeMap<usize, SignatureShare>> =
        Default::default();

    // Get from user: SignatureSharesMap(s) for each tx input
    //                until required # of SignatureShare obtained.
    for (i, dbc) in tx.inner.inputs.iter().enumerate() {
        let pubkeyset = tx
            .inputs_owners
            .get(&dbc.name())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;

        for shares_map in ss_maps.iter() {
            for (name, shares) in shares_map.0.iter() {
                if *name == dbc.name() {
                    for (idx, share) in shares.iter() {
                        let list = sig_shares_by_input
                            .entry(*name)
                            .or_insert_with(BTreeMap::default);
                        (*list).insert(*idx, share.clone());
                    }
                }
            }
        }
        let found = match sig_shares_by_input.get(&dbc.name()) {
            Some(list) => list.len(),
            None => 0,
        };

        if found < pubkeyset.threshold() + 1 {
            return Err(anyhow!(
                "Input DBC #{} requires {} SignatureShare but {} provided",
                i,
                pubkeyset.threshold() + 1,
                found
            ));
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

    let reissue_request = ReissueRequestUnblinded {
        inner: ReissueRequest {
            transaction: tx.inner.clone(),
            input_ownership_proofs: proofs,
        },
        inputs_owners: tx.inputs_owners.clone(),
        outputs_owners: tx.outputs_owners.clone(),
    };

    let json = json::json!({
        "data_type": "ReissueRequest",
        "data": to_be_hex(&reissue_request)?,
    });

    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
}

/// Implements reissue command.
fn reissue_cli(mintinfo: &mut MintInfo, rr: &ReissueRequestUnblinded) -> Result<()> {
    let input_hashes = rr
        .inner
        .transaction
        .inputs
        .iter()
        .map(|e| e.name())
        .collect::<BTreeSet<_>>();

    reissue_exec(mintinfo, &rr.inner, &input_hashes, &rr.outputs_owners)
}

/// Implements reissue_ez command.
fn reissue_ez_cli(
    mintinfo: &mut MintInfo,
    inputs_cli: &[DbcSecretKeyShareInput],
    outputs_cli: &[DbcOutput],
) -> Result<()> {
    let inputs_total: u64 = inputs_cli.iter().map(|d| d.dbc.inner.amount()).sum();
    let input_hashes = inputs_cli
        .iter()
        .map(|e| e.dbc.inner.name())
        .collect::<BTreeSet<_>>();

    let v: Vec<(DbcContent, (Hash, PublicKeySet))> = outputs_cli
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let content = DbcContent::new(
                input_hashes.clone(),          // parents
                o.amount,                      // amount
                i as u32,                      // output_number
                o.public_key_set.public_key(), // public_key
            );
            (content.clone(), (content.hash(), o.public_key_set.clone()))
        })
        .collect();

    let outputs: HashSet<DbcContent> = v.iter().map(|e| e.0.clone()).collect();
    let outputs_owners: HashMap<Hash, PublicKeySet> = v.iter().map(|e| e.1.clone()).collect();
    let outputs_total: u64 = outputs.iter().map(|o| o.amount).sum();

    if outputs.is_empty() {
        println!("\n\nNo outputs specified.  Cancelling.\n\n");
        return Ok(());
    }
    if inputs_total - outputs_total != 0 {
        println!("\n\nInput DBC(s) not fully spent. Cancelling.\n\n");
        return Ok(());
    }

    let tx_inputs: HashSet<Dbc> = inputs_cli.iter().map(|d| d.dbc.inner.clone()).collect();
    let transaction = ReissueTransaction {
        inputs: tx_inputs,
        outputs,
    };

    // for each input Dbc, combine owner's SignatureShare(s) to obtain owner's Signature
    let mut proofs: HashMap<Hash, (PublicKey, Signature)> = Default::default();
    for input in inputs_cli.iter() {
        let mut sig_shares: BTreeMap<usize, SignatureShare> = Default::default();
        for (index, sks) in input.secret_key_shares.iter() {
            let sig_share = sks.sign(&transaction.blinded().hash());
            sig_shares.insert(*index, sig_share.clone());
        }
        let sig = input
            .dbc
            .owner
            .combine_signatures(&sig_shares)
            .map_err(|e| anyhow!(e))?;
        proofs.insert(input.dbc.inner.name(), (input.dbc.owner.public_key(), sig));
    }

    let reissue_request = ReissueRequest {
        transaction,
        //        input_ownership_proofs: HashMap::from_iter(vec![(mintinfo.genesis.name(), sig)]),
        input_ownership_proofs: proofs,
    };

    reissue_exec(mintinfo, &reissue_request, &input_hashes, &outputs_owners)
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
        .secret_key_set()
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

    let mut jdbcs: Vec<json::Value> = Default::default();

    // for each output, construct DbcUnblinded and display
    for dbc in output_dbcs.iter() {
        let pubkeyset = outputs_pks
            .get(&dbc.content.hash())
            .ok_or_else(|| anyhow!("PubKeySet not found"))?;
        let dbc_owned = DbcUnblinded {
            inner: dbc.clone(),
            owner: pubkeyset.clone(),
        };

        jdbcs.push(dbc_to_json(&dbc_owned, false)?);
    }

    let json = json::json!({
        "desc": "List of output DBCs",
        "outputs": jdbcs,
    });
    println!("{}", json::to_string_pretty(&json)?);

    Ok(())
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
        transaction_sigs: BTreeMap::from_iter(vec![(
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
        poly,
    })
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

/// Converts SecretKeySet to json::Value
fn secret_key_set_to_json(sks: &SecretKeySet, poly: &Poly, show_pks: bool) -> Result<json::Value> {
    let mut map = json::Map::new();

    map.insert("poly".to_string(), jstr(to_be_hex(&poly)?));
    map.insert("threshold".to_string(), jusize(sks.threshold()));
    map.insert("required_signers".to_string(), jusize(sks.threshold() + 1));

    if show_pks {
        map.insert(
            "public_key_set".to_string(),
            jstr(to_be_hex(&sks.public_keys())?),
        );
    }

    map.insert(
        "secret_key_shares".to_string(),
        secret_key_shares_to_json(sks)?,
    );

    Ok(jmap(map))
}

// converts PublicKeySet to json::Value
fn public_key_set_to_json(pks: &PublicKeySet) -> Result<json::Value> {
    let mut map = json::Map::new();

    map.insert("public_key_set".to_string(), jstr(to_be_hex(&pks)?));
    map.insert("threshold".to_string(), jusize(pks.threshold()));
    map.insert("required_signers".to_string(), jusize(pks.threshold() + 1));

    map.insert(
        "public_key_shares".to_string(),
        public_key_shares_to_json(pks)?,
    );

    Ok(jmap(map))
}

// converts SecretKeySet to json::Value representing list of SecretKeyShare
fn secret_key_shares_to_json(sks: &SecretKeySet) -> Result<json::Value> {
    let mut sec_shares = json::Map::new();

    //println!("\n -- PublicKeyShares --");
    for i in (0..sks.threshold() + 5).into_iter() {
        sec_shares.insert(
            i.to_string(),
            jstr(encode(&sks_to_bytes(&sks.secret_key_share(i))?)),
        );
    }
    Ok(jmap(sec_shares))
}

// converts PublicKeySet to json::Value representing list of PublicKeyShare
fn public_key_shares_to_json(pks: &PublicKeySet) -> Result<json::Value> {
    let mut pub_shares = json::Map::new();

    //println!("\n -- PublicKeyShares --");
    for i in (0..pks.threshold() + 5).into_iter() {
        pub_shares.insert(
            i.to_string(),
            jstr(encode(&pks.public_key_share(i).to_bytes())),
        );
    }
    Ok(jmap(pub_shares))
}

/// encodes Dbc as json::Value
fn dbc_to_json(dbc: &DbcUnblinded, outputs: bool) -> Result<json::Value> {
    // dbc.content.parents and dbc.transaction.inputs seem to be the same
    // so for now we are just displaying the latter.
    // println!("parents:");
    // for p in &dbc.content.parents {
    //     println!("  {}", encode(p))
    // }

    let mut inputs = json::Map::new();

    for (i, input) in dbc.inner.transaction.inputs.iter().enumerate() {
        inputs.insert(i.to_string(), jstr(encode(input)));
    }

    let mut root = json::Map::new();

    root.insert("id".to_string(), jstr(encode(dbc.inner.name())));
    root.insert("amount".to_string(), ju64(dbc.inner.content.amount));
    root.insert(
        "output_number".to_string(),
        ju32(dbc.inner.content.output_number),
    );
    root.insert("owner".to_string(), jstr(to_be_hex(&dbc.owner)?));
    root.insert("inputs".to_string(), jmap(inputs));

    if outputs {
        let mut outputs = json::Map::new();
        for (i, output) in dbc.inner.transaction.outputs.iter().enumerate() {
            outputs.insert(i.to_string(), jstr(encode(output)));
        }
        root.insert("outputs".to_string(), jmap(outputs));
    }

    root.insert("data".to_string(), jstr(to_be_hex(&dbc)?));

    Ok(jmap(root))
}

// converts String to json::Value
fn jstr(s: String) -> json::Value {
    json::Value::String(s)
}

// converts u64 to json::Value
fn ju64(n: u64) -> json::Value {
    json::Value::Number(json::Number::from(n))
}

// converts u32 to json::Value
fn ju32(n: u32) -> json::Value {
    json::Value::Number(json::Number::from(n))
}

// converts usize to json::Value
fn jusize(n: usize) -> json::Value {
    json::Value::Number(json::Number::from(n))
}

// converts Vec<json::Value> to json::Value
fn jvec(v: Vec<json::Value>) -> json::Value {
    json::Value::Array(v)
}

// converts Map<String, json::Value> to json::Value
fn jmap(m: json::Map<String, json::Value>) -> json::Value {
    json::Value::Object(m)
}
