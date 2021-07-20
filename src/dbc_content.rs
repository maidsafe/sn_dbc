// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use blsttc::{PublicKey, PublicKeySet, DecryptionShare, SecretKey, SecretKeyShare, Ciphertext};
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct BlindedOwner(Hash);

impl BlindedOwner {
    pub fn new(
        owner: &PublicKey,
        parents: &BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u32,
    ) -> Self {
        let mut sha3 = Sha3::v256();

        for parent in parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&amount.to_be_bytes());
        sha3.update(&output_number.to_be_bytes());
        sha3.update(&owner.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Self(Hash(hash))
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct AmountSecrets {
    pub amount: u64,
    pub blinding_factor: Scalar,
}

impl AmountSecrets {
    fn to_bytes(&self) -> Vec<u8> {
        let a = self.amount.to_le_bytes();
        let b = self.blinding_factor.to_bytes();

        let mut v: Vec<u8> = Default::default();
        for c in a {
            v.push(c);
        }
        for c in b {
            v.push(c);
        }
        v
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        println!("bytes: {:?}", bytes);
        let amount = u64::from_le_bytes( *slice_as_array!(&bytes[0..8], [u8; 8]).unwrap() );
        let blinding_factor = Scalar::from_bytes_mod_order( *slice_as_array!(&bytes[8..], [u8; 32]).unwrap());
        Self {amount, blinding_factor}
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Parent DBC's, acts as a nonce
    pub amount: u64,
    pub amount_secrets_cipher: Ciphertext,
//    pub blinding_factor: Scalar,
    pub commitment: CompressedRistretto,
//    pub range_proof_bytes: [u8; 32*21],  // RangeProof::to_bytes() -> (2 lg n + 9) 32-byte elements, where n is # of secret bits, or 64 in our case. Gives 21 32-byte elements.
    pub range_proof_bytes: Vec<u8>,  // RangeProof::to_bytes() -> (2 lg n + 9) 32-byte elements, where n is # of secret bits, or 64 in our case. Gives 21 32-byte elements.
    pub output_number: u32,
    pub owner: BlindedOwner,
}

impl DbcContent {
    // Create a new DbcContent for signing. TODO: blind the owner from the mint
    pub fn new(
        parents: BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u32,
        owner_key: PublicKey,
        blinding_factor: Scalar,
    ) -> Self {
        let owner = BlindedOwner::new(&owner_key, &parents, amount, output_number);
        let secret = amount;
        let nbits = 64;

        let ped_commits = PedersenGens::default();
        let bullet_gens = BulletproofGens::new(64, 1);
        let mut prover_ts = Transcript::new("Test".as_bytes());
        let (proof, commitment) = RangeProof::prove_single( &bullet_gens,&ped_commits,&mut prover_ts,secret,&blinding_factor, nbits,).expect("Oops!");

        let amount_secrets = AmountSecrets{ amount, blinding_factor };
        let amount_secrets_cipher = owner_key.encrypt( amount_secrets.to_bytes().as_slice() );

        println!("in DbcContent::new()");
        println!("amount: {}\ncommitment: {:?}\n\n", amount, commitment);

        DbcContent {
            parents,
            amount,
            amount_secrets_cipher,
            output_number,
            owner,
            commitment,
            range_proof_bytes: proof.to_bytes(),
        }
    }

    pub fn random_blinding_factor() -> Scalar {
        let mut csprng: OsRng = OsRng::default();
        Scalar::random(&mut csprng)
    }

    pub fn validate_unblinding(&self, owner_key: &PublicKey) -> Result<(), Error> {
        let blinded = BlindedOwner::new(owner_key, &self.parents, self.amount, self.output_number);
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

        sha3.update(&self.amount.to_be_bytes());
        sha3.update(&self.output_number.to_be_bytes());
        sha3.update(&self.owner.0);

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    pub fn amount_secrets(&self, secret_key: &SecretKey) -> Result<AmountSecrets, Error> {
        match secret_key.decrypt(&self.amount_secrets_cipher) {
            Some(bytes_vec) => {
                let bytes: Vec<u8> = bytes_vec.try_into().map_err(|_e| Error::AmountDecryptionFailed)?;
                Ok(AmountSecrets::from_bytes(&bytes))
            },
            None => Err(Error::AmountDecryptionFailed),
        }
    }

    pub fn amount_secrets_by_shares(&self, public_key_set: &PublicKeySet, secret_key_shares: &BTreeMap<usize, SecretKeyShare>) -> Result<AmountSecrets, Error> {

        let mut decryption_shares: BTreeMap<usize, DecryptionShare> = Default::default();
        for (idx, sec_share) in secret_key_shares.iter() {
            let share = sec_share.decrypt_share_no_verify(&self.amount_secrets_cipher);
            decryption_shares.insert(*idx, share);
        }

        match public_key_set.decrypt(&decryption_shares, &self.amount_secrets_cipher) {
            Ok(bytes_vec) => {
                let bytes: Vec<u8> = bytes_vec.try_into().map_err(|_e| Error::AmountDecryptionFailed)?;
                Ok(AmountSecrets::from_bytes(&bytes))
            },
            Err(_e) => Err(Error::AmountDecryptionFailed),
        }
    }
}
