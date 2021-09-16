// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use blsttc::{
    Ciphertext, DecryptionShare, IntoFr, PublicKey, PublicKeySet, SecretKey, SecretKeySet,
    SecretKeyShare,
};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand8::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tiny_keccak::{Hasher, Sha3};

use crate::{Error, Hash, SpendKey};

pub(crate) const RANGE_PROOF_BITS: usize = 64; // note: Range Proof max-bits is 64. allowed are: 8, 16, 32, 64 (only)
                                               //       This limits our amount field to 64 bits also.
pub(crate) const RANGE_PROOF_PARTIES: usize = 1; // The maximum number of parties that can produce an aggregated proof
pub(crate) const MERLIN_TRANSCRIPT_LABEL: &[u8] = b"SN_DBC";

const AMT_SIZE: usize = 8; // Amount size: 8 bytes (u64)
const BF_SIZE: usize = 32; // Blinding factor size: 32 bytes (Scalar)

pub type Amount = u64;

/// Contains amount and Pedersen Commitment blinding factor which
/// must be kept secret (encrypted) in the DBC.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub struct AmountSecrets {
    pub amount: Amount,
    pub blinding_factor: Scalar,
}

impl AmountSecrets {
    /// Convert to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(&self.amount.to_le_bytes());
        v.extend(&self.blinding_factor.to_bytes());
        v
    }

    /// build AmountSecrets from fixed size byte array.
    pub fn from_bytes(bytes: [u8; AMT_SIZE + BF_SIZE]) -> Self {
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let blinding_factor = Scalar::from_bytes_mod_order({
            let mut b = [0u8; BF_SIZE];
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });
        Self {
            amount,
            blinding_factor,
        }
    }

    /// build AmountSecrets from byte array reference
    pub fn from_bytes_ref(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != AMT_SIZE + BF_SIZE {
            return Err(Error::AmountSecretsBytesInvalid);
        }
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let blinding_factor = Scalar::from_bytes_mod_order({
            let mut b = [0u8; BF_SIZE];
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });
        Ok(Self {
            amount,
            blinding_factor,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<SpendKey>, // Parent DBC's, acts as a nonce
    pub amount_secrets_cipher: Ciphertext,
    pub commitment: CompressedRistretto,
    pub range_proof_bytes: Vec<u8>, // RangeProof::to_bytes() -> (2 lg n + 9) 32-byte elements, where n is # of secret bits, or 64 in our case. Gives 21 32-byte elements.
    pub owner: PublicKey,
}

/// Represents the content of a DBC.
impl DbcContent {
    // Create a new DbcContent for signing.
    pub fn new(
        parents: BTreeSet<SpendKey>,
        amount: Amount,
        owner: PublicKey,
        blinding_factor: Scalar,
    ) -> Result<Self, Error> {
        let secret = amount;

        let pc_gens = PedersenGens::default();
        let bullet_gens = BulletproofGens::new(RANGE_PROOF_BITS, RANGE_PROOF_PARTIES);
        let mut prover_ts = Transcript::new(MERLIN_TRANSCRIPT_LABEL);
        let (proof, commitment) = RangeProof::prove_single(
            &bullet_gens,
            &pc_gens,
            &mut prover_ts,
            secret,
            &blinding_factor,
            RANGE_PROOF_BITS,
        )?;

        let amount_secrets = AmountSecrets {
            amount,
            blinding_factor,
        };
        let amount_secrets_cipher = owner.encrypt(amount_secrets.to_bytes().as_slice());

        Ok(DbcContent {
            parents,
            amount_secrets_cipher,
            owner,
            commitment,
            range_proof_bytes: proof.to_bytes(),
        })
    }

    pub fn random_blinding_factor() -> Scalar {
        let mut csprng: OsRng = OsRng::default();
        Scalar::random(&mut csprng)
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();

        for parent in self.parents.iter() {
            sha3.update(&parent.0.to_bytes());
        }

        sha3.update(&self.amount_secrets_cipher.to_bytes());
        sha3.update(&self.owner.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    /// Decrypt AmountSecrets using a SecretKey
    pub fn amount_secret_by_secret_key(
        &self,
        secret_key: &SecretKey,
    ) -> Result<AmountSecrets, Error> {
        let bytes_vec = secret_key
            .decrypt(&self.amount_secrets_cipher)
            .ok_or(Error::DecryptionBySecretKeyFailed)?;
        AmountSecrets::from_bytes_ref(&bytes_vec)
    }

    /// Decrypt AmountSecrets using a SecretKeySet
    pub fn amount_secrets_by_secret_key_set(
        &self,
        secret_key_set: &SecretKeySet,
    ) -> Result<AmountSecrets, Error> {
        self.amount_secret_by_secret_key(&secret_key_set.secret_key())
    }

    /// Decrypt AmountSecrets using threshold+1 SecretKeyShares
    pub fn amount_secrets_by_secret_key_shares<I: IntoFr + Ord>(
        &self,
        public_key_set: &PublicKeySet,
        secret_key_shares: &BTreeMap<I, SecretKeyShare>,
    ) -> Result<AmountSecrets, Error> {
        let mut decryption_shares: BTreeMap<I, DecryptionShare> = Default::default();
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
    pub fn amount_secrets_by_decryption_shares<I: IntoFr + Ord>(
        &self,
        public_key_set: &PublicKeySet,
        decryption_shares: &BTreeMap<I, DecryptionShare>,
    ) -> Result<AmountSecrets, Error> {
        let bytes_vec = public_key_set.decrypt(decryption_shares, &self.amount_secrets_cipher)?;
        AmountSecrets::from_bytes_ref(&bytes_vec)
    }

    /// Verifies range proof, ie that the committed amount is a non-negative u64.
    pub fn verify_range_proof(&self) -> Result<(), Error> {
        let bullet_gens = BulletproofGens::new(RANGE_PROOF_BITS, RANGE_PROOF_PARTIES);
        let pc_gens = PedersenGens::default();

        let mut verifier_ts = Transcript::new(MERLIN_TRANSCRIPT_LABEL);
        let proof = RangeProof::from_bytes(&self.range_proof_bytes)?;

        Ok(proof.verify_single(
            &bullet_gens,
            &pc_gens,
            &mut verifier_ts,
            &self.commitment,
            RANGE_PROOF_BITS,
        )?)
    }

    /// Checks if the secret (encrypted) amount matches the amount commitment.
    /// returns true if they match, false if not, or an error if decryption fails.
    pub fn confirm_amount_matches_commitment(
        &self,
        public_key_set: &PublicKeySet,
        decryption_shares: &BTreeMap<usize, DecryptionShare>,
    ) -> Result<bool, Error> {
        let secrets =
            self.amount_secrets_by_decryption_shares(public_key_set, decryption_shares)?;
        Ok(self.confirm_provided_amount_matches_commitment(&secrets))
    }

    /// Checks if the provided AmountSecrets matches the amount commitment.
    /// note that both the amount and blinding_factor must be correct.
    pub fn confirm_provided_amount_matches_commitment(&self, amount: &AmountSecrets) -> bool {
        let commitment =
            PedersenGens::default().commit(Scalar::from(amount.amount), amount.blinding_factor);
        self.commitment == commitment.compress()
    }

    /// Calculates the blinding factor for the next output, typically used inside a loop.
    ///
    /// is_last: must be true if this is the last output, else false.
    /// inputs_bf_sum: sum of blinding factors for all transaction inputs.
    /// outputs_bf_sum: sum of blinding factors for preceding transaction outputs.
    pub fn calc_blinding_factor(
        is_last: bool,
        inputs_bf_sum: Scalar,
        outputs_bf_sum: Scalar,
    ) -> Scalar {
        match is_last {
            true => inputs_bf_sum - outputs_bf_sum,
            false => DbcContent::random_blinding_factor(),
        }
    }
}
