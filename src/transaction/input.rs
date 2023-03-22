// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use blsttc::{PublicKey, SecretKey, Signature};
use bulletproofs::PedersenGens;

#[cfg(feature = "serde")]
use serde::{self, Deserialize, Serialize};

use super::{Error, Result, RevealedAmount};
use crate::BlindedAmount;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevealedInput {
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    pub secret_key: SecretKey,
    pub revealed_amount: RevealedAmount,
}

impl RevealedInput {
    pub fn new<S: Into<SecretKey>>(secret_key: S, revealed_amount: RevealedAmount) -> Self {
        Self {
            secret_key: secret_key.into(),
            revealed_amount,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }

    pub fn revealed_amount(&self) -> &RevealedAmount {
        &self.revealed_amount
    }

    pub fn blinded_amount(&self, pc_gens: &PedersenGens) -> BlindedAmount {
        self.revealed_amount.blinded_amount(pc_gens)
    }

    pub fn sign(&self, msg: &[u8], pc_gens: &PedersenGens) -> Input {
        let public_key = self.public_key();
        let blinded_amount = self.blinded_amount(pc_gens);
        let signature = self.secret_key.sign(msg);

        Input {
            public_key,
            blinded_amount,
            signature,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Input {
    pub public_key: PublicKey,
    pub blinded_amount: BlindedAmount,
    pub signature: Signature,
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.public_key.to_bytes().as_ref());
        v.extend(self.blinded_amount.compress().as_bytes());
        v.extend(self.signature.to_bytes().as_ref());
        v
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Verify if a blinded amount you know of, is the same as the one in the input,
    /// and that the bytes passed in, are what the signature of this input was made over,
    /// and that the public key of this input was the signer.
    pub fn verify(&self, msg: &[u8], blinded_amount: BlindedAmount) -> Result<()> {
        if self.blinded_amount != blinded_amount {
            return Err(Error::InvalidInputBlindedAmount);
        }

        // check the signature
        if !self.public_key.verify(&self.signature, msg) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }
}
