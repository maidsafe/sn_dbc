// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use crate::dbc_id::DerivedKeySet;
use crate::rand::RngCore;
use crate::{BlindedAmount, BlindingFactor, DerivedKey};
use crate::{Error, Result};

use blsttc::{
    rand::CryptoRng, Ciphertext, DecryptionShare, IntoFr, PublicKey, PublicKeySet, SecretKeyShare,
};
use bulletproofs::PedersenGens;
use std::{collections::BTreeMap, convert::TryFrom};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const AMT_SIZE: usize = std::mem::size_of::<u64>(); // Amount size: 8 bytes (u64)
const BF_SIZE: usize = std::mem::size_of::<BlindingFactor>(); // Blinding factor size: 32 bytes (BlindingFactor)

/// Represents a Dbc's value.
pub type Amount = u64;

/// A RevealedAmount is a plain text value and a
/// blinding factor, which together can create a `BlindedAmount`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct RevealedAmount {
    pub value: Amount,
    pub blinding_factor: BlindingFactor,
}

impl RevealedAmount {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.value.to_le_bytes());
        v.extend(self.blinding_factor.to_bytes());
        v
    }

    /// Construct a RevealedAmount instance from an amount, generating a random blinding factor.
    pub fn from_amount(amount: Amount, mut rng: impl RngCore + CryptoRng) -> Self {
        Self {
            value: amount,
            blinding_factor: BlindingFactor::random(&mut rng),
        }
    }

    pub fn blinded_amount(&self, pc_gens: &PedersenGens) -> BlindedAmount {
        pc_gens.commit(BlindingFactor::from(self.value), self.blinding_factor)
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding_factor(&self) -> BlindingFactor {
        self.blinding_factor
    }

    /// Encrypt this instance to given public key, producing `Ciphertext`.
    pub fn encrypt(&self, public_key: &PublicKey) -> Ciphertext {
        public_key.encrypt(self.to_bytes())
    }

    /// Build RevealedAmount from fixed size byte array.
    pub fn from_bytes(bytes: [u8; AMT_SIZE + BF_SIZE]) -> Self {
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let mut b = [0u8; BF_SIZE];
        let blinding_factor = BlindingFactor::from_bytes_mod_order({
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });

        Self {
            value: amount,
            blinding_factor,
        }
    }

    /// Build RevealedAmount from byte array reference.
    pub fn from_bytes_ref(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AMT_SIZE + BF_SIZE {
            return Err(Error::InvalidRevealedAmountBytes);
        }
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let mut b = [0u8; BF_SIZE];
        let blinding_factor = BlindingFactor::from_bytes_mod_order({
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });

        Ok(Self {
            value: amount,
            blinding_factor,
        })
    }
}

impl From<(Amount, BlindingFactor)> for RevealedAmount {
    /// Create RevealedAmount from an amount and a randomly generated blinding factor.
    fn from(params: (Amount, BlindingFactor)) -> Self {
        let (amount, blinding_factor) = params;

        Self {
            value: amount,
            blinding_factor,
        }
    }
}

impl TryFrom<(&DerivedKey, &Ciphertext)> for RevealedAmount {
    type Error = Error;

    /// Decrypt RevealedAmount ciphertext using a DerivedKey.
    fn try_from(params: (&DerivedKey, &Ciphertext)) -> Result<Self> {
        let (derived_key, ciphertext) = params;
        derived_key.decrypt(ciphertext)
    }
}

impl TryFrom<(&DerivedKeySet, &Ciphertext)> for RevealedAmount {
    type Error = Error;

    /// Decrypt RevealedAmount ciphertext using a DerivedKeySet.
    fn try_from(params: (&DerivedKeySet, &Ciphertext)) -> Result<Self> {
        let (derived_key_set, ciphertext) = params;
        Self::try_from((&derived_key_set.derived_key(), ciphertext))
    }
}

impl<I: IntoFr + Ord> TryFrom<(&PublicKeySet, &BTreeMap<I, SecretKeyShare>, &Ciphertext)>
    for RevealedAmount
{
    type Error = Error;

    /// Decrypt RevealedAmount ciphertext using [threshold + 1] SecretKeyShares.
    fn try_from(
        params: (&PublicKeySet, &BTreeMap<I, SecretKeyShare>, &Ciphertext),
    ) -> Result<Self> {
        let (public_key_set, secret_key_shares, ciphertext) = params;

        let mut decryption_shares: BTreeMap<I, DecryptionShare> = Default::default();
        for (idx, sec_share) in secret_key_shares.iter() {
            let share = sec_share.decrypt_share_no_verify(ciphertext);
            decryption_shares.insert(*idx, share);
        }
        Self::try_from((public_key_set, &decryption_shares, ciphertext))
    }
}

impl<I: IntoFr + Ord> TryFrom<(&PublicKeySet, &BTreeMap<I, DecryptionShare>, &Ciphertext)>
    for RevealedAmount
{
    type Error = Error;

    /// Decrypt RevealedAmount using threshold+1 DecryptionShares.
    ///
    /// This fn should be used when keys (SecretKeyShare) are distributed across multiple parties.
    /// In which case each party will need to call SecretKeyShare::decrypt_share() or
    /// decrypt_share_no_verify() to generate a DecryptionShare and one party will need to
    /// obtain/aggregate all the shares together somehow.
    fn try_from(
        params: (&PublicKeySet, &BTreeMap<I, DecryptionShare>, &Ciphertext),
    ) -> Result<Self> {
        let (public_key_set, decryption_shares, ciphertext) = params;
        let bytes_vec = public_key_set.decrypt(decryption_shares, ciphertext)?;
        Self::from_bytes_ref(&bytes_vec)
    }
}
