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

/*
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct AmountEnc {
    amount: u64,
    blinding_factor: Scalar,
}

impl AmountEnc {
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
}
*/

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Parent DBC's, acts as a nonce
    pub amount: u64,
    pub amount_enc: Ciphertext,
    pub blinding_factor: Scalar,
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
        blinding_factor: Option<Scalar>,
    ) -> Self {
        let owner = BlindedOwner::new(&owner_key, &parents, amount, output_number);
        let secret = amount;
        let nbits = 64;

        let ped_commits = PedersenGens::default();
        let bullet_gens = BulletproofGens::new(64, 1);
        let bfactor = match blinding_factor {
            Some(b) => b,
            None => {
                let mut csprng: OsRng = OsRng::default();
                Scalar::random(&mut csprng)
            }
        };
//        let blinding_factor = Scalar::random(&mut csprng);
//        let blinding_factor = Scalar::default();
        let mut prover_ts = Transcript::new("Test".as_bytes());
        let (proof, commitment) = RangeProof::prove_single( &bullet_gens,&ped_commits,&mut prover_ts,secret,&bfactor, nbits,).expect("Oops!");

        let amount_enc = owner_key.encrypt( &amount.to_le_bytes() );

        println!("in DbcContent::new()");
        println!("amount: {}\ncommitment: {:?}\n\n", amount, commitment);

        DbcContent {
            parents,
            amount,
            amount_enc,
            output_number,
            owner,
            commitment,
            range_proof_bytes: proof.to_bytes(),
            blinding_factor: bfactor,
        }
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

    pub fn amount(&self, secret_key: &SecretKey) -> Result<u64, Error> {
        match secret_key.decrypt(&self.amount_enc) {
            Some(bytes_vec) => {
                let bytes = bytes_vec.try_into().map_err(|_e| Error::AmountDecryptionFailed)?;
                Ok(u64::from_le_bytes(bytes))
            },
            None => Err(Error::AmountDecryptionFailed),
        }
    }

    pub fn amount_by_shares(&self, public_key_set: &PublicKeySet, secret_key_shares: &BTreeMap<usize, SecretKeyShare>) -> Result<u64, Error> {

        let mut decryption_shares: BTreeMap<usize, DecryptionShare> = Default::default();
        for (idx, sec_share) in secret_key_shares.iter() {
            let share = sec_share.decrypt_share_no_verify(&self.amount_enc);
            decryption_shares.insert(*idx, share);
        }

        match public_key_set.decrypt(&decryption_shares, &self.amount_enc) {
            Ok(bytes_vec) => {
                let bytes = bytes_vec.try_into().map_err(|_e| Error::AmountDecryptionFailed)?;
                Ok(u64::from_le_bytes(bytes))
            },
            Err(_e) => Err(Error::AmountDecryptionFailed),
        }
    }
}
