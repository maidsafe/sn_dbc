// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use blsttc::{PublicKey, PublicKeySet, SecretKeySet, DecryptionShare, SecretKey, SecretKeyShare, Ciphertext};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use bulletproofs::{PedersenGens, RangeProof, BulletproofGens};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand8::rngs::OsRng;
use std::convert::TryInto;
use std::collections::BTreeMap;
use slice_as_array::*;

use crate::{DbcContentHash, Error, Hash};

pub(crate) const RANGE_PROOF_BITS: usize = 64;  // note: Range Proof max-bits is 64. allowed are: 8, 16, 32, 64 (only)
                                         //       This limits our amount field to 64 bits also.
pub(crate) const MERLIN_TRANSCRIPT_LABEL: &[u8] = b"SN_DBC";

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct BlindedOwner(Hash);

impl BlindedOwner {
    pub fn new(
        owner: &PublicKey,
        parents: &BTreeSet<DbcContentHash>,
        output_number: u32,
    ) -> Self {
        let mut sha3 = Sha3::v256();

        for parent in parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&output_number.to_be_bytes());
        sha3.update(&owner.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Self(Hash(hash))
    }
}

/// Contains amount and Pedersen Commitment blinding factor which
/// must be kept secret (encrypted) in the DBC.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct AmountSecrets {
    pub amount: u64,
    pub blinding_factor: Scalar,
}

impl AmountSecrets {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(&self.amount.to_le_bytes());
        v.extend(&self.blinding_factor.to_bytes());
        v
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let amount = u64::from_le_bytes( *slice_as_array!(&bytes[0..8], [u8; 8]).ok_or(Error::AmountSecretsBytesInvalid)?);
        let blinding_factor = Scalar::from_bytes_mod_order( *slice_as_array!(&bytes[8..], [u8; 32]).ok_or(Error::AmountSecretsBytesInvalid)?);
        Ok(Self {amount, blinding_factor})
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Parent DBC's, acts as a nonce
    pub amount_secrets_cipher: Ciphertext,
    pub commitment: CompressedRistretto,
    pub range_proof_bytes: Vec<u8>,  // RangeProof::to_bytes() -> (2 lg n + 9) 32-byte elements, where n is # of secret bits, or 64 in our case. Gives 21 32-byte elements.
    pub output_number: u32,
    pub owner: BlindedOwner,
}

impl DbcContent {
    // Create a new DbcContent for signing.
    pub fn new(
        parents: BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u32,
        owner_key: PublicKey,
        blinding_factor: Scalar,
    ) -> Result<Self, Error> {
        let owner = BlindedOwner::new(&owner_key, &parents, output_number);
        let secret = amount;

        let ped_commits = PedersenGens::default();
        let bullet_gens = BulletproofGens::new(RANGE_PROOF_BITS, 1);
        let mut prover_ts = Transcript::new(MERLIN_TRANSCRIPT_LABEL);
        let (proof, commitment) = RangeProof::prove_single( &bullet_gens,&ped_commits,&mut prover_ts,secret,&blinding_factor, RANGE_PROOF_BITS,)?;

        let amount_secrets = AmountSecrets{ amount, blinding_factor };
        let amount_secrets_cipher = owner_key.encrypt( amount_secrets.to_bytes().as_slice() );

        Ok(DbcContent {
            parents,
            amount_secrets_cipher,
            output_number,
            owner,
            commitment,
            range_proof_bytes: proof.to_bytes(),
        })
    }

    pub fn random_blinding_factor() -> Scalar {
        let mut csprng: OsRng = OsRng::default();
        Scalar::random(&mut csprng)
    }

    pub fn validate_unblinding(&self, owner_key: &PublicKey) -> Result<(), Error> {
        let blinded = BlindedOwner::new(owner_key, &self.parents, self.output_number);
        if blinded == self.owner {
            Ok(())
        } else {
            Err(Error::FailedUnblinding)
        }
    }

    pub fn hash(&self) -> DbcContentHash {
        let mut sha3 = Sha3::v256();

        for parent in self.parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&self.amount_secrets_cipher.to_bytes());
        sha3.update(&self.output_number.to_be_bytes());
        sha3.update(&self.owner.0);

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    /// Decrypt AmountSecrets using a SecretKey
    pub fn amount_secret_by_secret_key(&self, secret_key: &SecretKey) -> Result<AmountSecrets, Error> {
        match secret_key.decrypt(&self.amount_secrets_cipher) {
            Some(bytes_vec) => {
                let bytes: Vec<u8> = bytes_vec.try_into()?;
                Ok(AmountSecrets::from_bytes(&bytes)?)
            },
            None => Err(Error::DecryptionBySecretKeyFailed),
        }
    }

    /// Decrypt AmountSecrets using a SecretKeySet
    pub fn amount_secrets_by_secret_key_set(&self, secret_key_set: &SecretKeySet) -> Result<AmountSecrets, Error> {
        // todo: change impl to this once blsttc::SecretKeySet::secret_key() is made pub
        // self.amount_secret_by_secret_key(&secret_key_set.secret_key())

        let mut shares: BTreeMap<usize, SecretKeyShare> = Default::default();
        for i in 0..secret_key_set.threshold()+1 {
            shares.insert(i, secret_key_set.secret_key_share(i));
        }
        self.amount_secrets_by_secret_key_shares(&secret_key_set.public_keys(), &shares)
    }

    /// Decrypt AmountSecrets using threshold+1 SecretKeyShares
    pub fn amount_secrets_by_secret_key_shares(&self, public_key_set: &PublicKeySet, secret_key_shares: &BTreeMap<usize, SecretKeyShare>) -> Result<AmountSecrets, Error> {
        let mut decryption_shares: BTreeMap<usize, DecryptionShare> = Default::default();
        for (idx, sec_share) in secret_key_shares.iter() {
            let share = sec_share.decrypt_share_no_verify(&self.amount_secrets_cipher);
            decryption_shares.insert(*idx, share);
        }
        self.amount_secrets_by_decryption_shares(public_key_set, &decryption_shares)
    }

    /// Decrypt AmountSecrets using threshold+1 DecryptionShares
    /// 
    /// This fn should be used when keys (SecretKeyShare) are distributed across multiple parties.
    /// In which case each party will need to call SecretKeyShare::decrypt_share() or 
    /// decrypt_share_no_verify() to generate a DecryptionShare and one party will need to 
    /// obtain/aggregate all the shares together somehow.
    pub fn amount_secrets_by_decryption_shares(&self, public_key_set: &PublicKeySet, decryption_shares: &BTreeMap<usize, DecryptionShare>) -> Result<AmountSecrets, Error> {
        let bytes_vec = public_key_set.decrypt(decryption_shares, &self.amount_secrets_cipher)?;
        let bytes: Vec<u8> = bytes_vec.try_into()?;

        Ok(AmountSecrets::from_bytes(&bytes)?)
    }
}
