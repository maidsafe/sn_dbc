use blsbs::{Envelope, Fr, SignedEnvelopeShare, SlipPreparer};
use blsttc::{PublicKeySet, SignatureShare};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use crate::{
    Amount, Dbc, DbcContent, DbcEnvelope, Denomination, Error, PublicKey, ReissueShare,
    ReissueTransaction, Result, SpendKey,
};

///! Unblinded data for creating sn_dbc::DbcContent
#[derive(Debug, Clone)]
pub struct Output {
    pub denomination: Denomination,
    pub owner: PublicKey,
}

impl Output {
    pub fn outputs_for_amount(owner: blsttc::PublicKey, amount: Amount) -> Vec<Self> {
        Denomination::make_change(amount)
            .iter()
            .map(|d| Self {
                denomination: *d,
                owner,
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct OutputSecret {
    pub slip_preparer: SlipPreparer,
    pub dbc_content: DbcContent,
}

#[derive(Debug, Default)]
pub struct TransactionBuilder {
    pub inputs: HashSet<Dbc>,
    pub outputs: Vec<Output>,
}

impl TransactionBuilder {
    pub fn add_input(mut self, dbc: Dbc) -> Self {
        self.inputs.insert(dbc);
        self
    }

    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = Dbc>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    pub fn add_output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = Output>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    pub fn input_owners(&self) -> BTreeSet<PublicKey> {
        BTreeSet::from_iter(self.inputs.iter().map(Dbc::owner))
    }

    pub fn input_spend_keys(&self) -> BTreeSet<SpendKey> {
        BTreeSet::from_iter(self.inputs.iter().map(Dbc::spend_key))
    }

    pub fn inputs_amount_sum(&self) -> Result<Amount> {
        let amounts = self.inputs.iter().map(|d| d.denomination().amount());
        Amount::checked_sum(amounts)
    }

    pub fn outputs_amount_sum(&self) -> Result<Amount> {
        let amounts = self.outputs.iter().map(|o| o.denomination.amount());
        Amount::checked_sum(amounts)
    }

    // Note: The HashMap result is necessary because DbcBuilder needs a couple things:
    //       1. The DbcContent. Because Envelope, SignedEnvelopeShare do not
    //          contain the Slip itself. Another method would be to encrypt the Slip and
    //          include with Envelope.
    //       2. SlipPreparer.  the preparer's blinding_factor is needed to obtain the
    //          SignatureShare for the Slip after reissue.
    pub fn build(self) -> Result<(ReissueTransaction, HashMap<DbcEnvelope, OutputSecret>)> {
        let outputs_content = self
            .outputs
            .iter()
            .map(|o| DbcContent::new(o.owner, o.denomination))
            .collect::<HashSet<_>>();

        let output_secrets = outputs_content
            .into_iter()
            .map(|c| {
                let slip_preparer = SlipPreparer::new()?;
                let envelope = slip_preparer.place_slip_in_envelope(&c.slip());
                let dbc_envelope = DbcEnvelope {
                    envelope,
                    denomination: c.denomination(),
                };
                let output_secret = OutputSecret {
                    slip_preparer,
                    dbc_content: c,
                };
                Ok((dbc_envelope, output_secret))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let outputs: HashSet<DbcEnvelope> = HashSet::from_iter(output_secrets.keys().cloned());

        let rt = ReissueTransaction {
            inputs: self.inputs,
            outputs,
        };
        Ok((rt, output_secrets))
    }
}

/// A Builder for aggregating ReissueShare (Mint::reissue() results)
/// from multiple mint nodes and combining signatures to
/// generate the final Dbc outputs.
#[derive(Debug)]
pub struct DbcBuilder {
    pub reissue_transaction: ReissueTransaction,
    pub reissue_shares: Vec<ReissueShare>,

    // Note: We need a couple things, included in OutputSecret:
    //       1. The DbcContent. Because Envelope, SignedEnvelopeShare do not
    //          contain the Slip itself. Another method would be to encrypt the Slip and
    //          include with Envelope.
    //       2. SlipPreparer.  the preparer's blinding_factor is needed to obtain the
    //          SignatureShare for the Slip after reissue.
    pub output_secrets: HashMap<DbcEnvelope, OutputSecret>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder from a ReissueTransaction
    pub fn new(reissue_transaction: ReissueTransaction) -> Self {
        Self {
            reissue_transaction,
            reissue_shares: Default::default(),
            output_secrets: Default::default(),
        }
    }

    /// Add an output DbcContent
    pub fn add_output_secret(
        mut self,
        dbc_envelope: DbcEnvelope,
        output_secret: OutputSecret,
    ) -> Self {
        self.output_secrets.insert(dbc_envelope, output_secret);
        self
    }

    /// Add multiple OutputSecret
    pub fn add_output_secrets(
        mut self,
        contents: impl IntoIterator<Item = (DbcEnvelope, OutputSecret)>,
    ) -> Self {
        self.output_secrets.extend(contents);
        self
    }

    /// Add a ReissueShare from Mint::reissue()
    pub fn add_reissue_share(mut self, reissue_share: ReissueShare) -> Self {
        self.reissue_shares.push(reissue_share);
        self
    }

    /// Add multiple ReissueShare from Mint::reissue()
    pub fn add_reissue_shares(mut self, shares: impl IntoIterator<Item = ReissueShare>) -> Self {
        self.reissue_shares.extend(shares);
        self
    }

    /// Build the output DBCs
    pub fn build(self) -> Result<Vec<Dbc>> {
        if self.reissue_shares.is_empty() {
            return Err(Error::NoReissueShares);
        }

        if self.output_secrets.is_empty() {
            return Err(Error::NoOutputSecrets);
        }

        let mut signed_envelope_shares: HashMap<Envelope, Vec<SignedEnvelopeShare>> =
            Default::default();
        let mut pk_set: HashSet<PublicKeySet> = Default::default();

        // walk through ReissueShare from each MintNode and:
        //  - generate a share list per output DBC/envelope.
        //  - aggregate PublicKeySet in order to verify they are all the same.
        //  - perform other validations
        for rs in self.reissue_shares.iter() {
            // Make a list of SignedEnvelopeShare (sigshare from each Mint Node) per DBC
            for share in rs.signed_envelope_shares.iter() {
                // fixme: remove clone.  Envelope could be Hash<Envelope>
                let share_list = signed_envelope_shares
                    .entry(share.envelope.clone())
                    .or_insert_with(Vec::new);
                (*share_list).push(share.clone())
            }

            let pub_key_sets: HashSet<PublicKeySet> =
                HashSet::from_iter([rs.public_key_set.clone()]);

            // add pubkeyset to HashSet, so we can verify there is only one distinct PubKeySet
            pk_set = &pk_set | &pub_key_sets; // union the sets together.

            // Verify transaction returned to us by the Mint matches our request
            if self.reissue_transaction.blinded() != rs.dbc_transaction {
                return Err(Error::ReissueShareDbcTransactionMismatch);
            }

            // Verify that mint sig count matches output count.
            if rs.signed_envelope_shares.len() != self.reissue_transaction.outputs.len() {
                return Err(Error::ReissueShareMintNodeSignaturesLenMismatch);
            }

            // Verify that each output DbcEnvelope has a corresponding output SignedEnvelopeShare
            for dbc_envelope in self.reissue_transaction.outputs.iter() {
                // todo: do this in a more rusty way.
                let mut found = false;
                for ses in rs.signed_envelope_shares.iter() {
                    if ses.envelope == dbc_envelope.envelope {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(Error::ReissueShareMintNodeSignatureNotFoundForInput);
                }
            }
        }

        // verify that PublicKeySet for all Dbc in all ReissueShare match.
        if pk_set.len() != 1 {
            return Err(Error::ReissueSharePublicKeySetMismatch);
        }
        let mint_root_public_key_set = match pk_set.iter().next() {
            Some(pks) => pks,
            None => return Err(Error::ReissueSharePublicKeySetMismatch),
        };

        // Generate final output Dbcs
        let mut output_dbcs: Vec<Dbc> = Default::default();
        for (dbc_envelope, output_secret) in self.output_secrets.into_iter() {
            // Transform Vec<SignedEnvelopeShare> to BTreeMap<Fr, SignatureShare>
            let mut mint_sig_shares: BTreeMap<Fr, SignatureShare> = Default::default();
            for ses in signed_envelope_shares
                .get(&dbc_envelope.envelope)
                .unwrap()
                .iter()
            {
                mint_sig_shares.insert(
                    ses.signature_share_index(),
                    ses.signature_share_for_slip(output_secret.slip_preparer.blinding_factor())?,
                );
            }

            // Combine signatures from all the mint nodes to obtain Mint's Signature.
            let mint_signature = mint_root_public_key_set
                .derive_child(&dbc_envelope.denomination.to_bytes())
                .combine_signatures(&mint_sig_shares)?;

            // Form the final output DBCs, with Mint's Signature for each.
            let dbc = Dbc {
                content: output_secret.dbc_content,
                mint_root_public_key: mint_root_public_key_set.public_key(),
                mint_signature,
            };

            output_dbcs.push(dbc);
        }

        // sort outputs by name
        output_dbcs.sort_by_key(Dbc::spend_key);

        Ok(output_dbcs)
    }
}
