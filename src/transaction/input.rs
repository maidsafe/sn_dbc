// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use blsttc::{PublicKey, SecretKey, Signature};
use bulletproofs::PedersenGens;

#[cfg(feature = "serde")]
use serde::{self, Deserialize, Serialize};

use super::{Error, Result, RevealedCommitment};
use crate::Commitment;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevealedInput {
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    pub secret_key: SecretKey,
    pub revealed_commitment: RevealedCommitment,
}

impl RevealedInput {
    pub fn new<S: Into<SecretKey>>(secret_key: S, revealed_commitment: RevealedCommitment) -> Self {
        Self {
            secret_key: secret_key.into(),
            revealed_commitment,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }

    pub fn revealed_commitment(&self) -> &RevealedCommitment {
        &self.revealed_commitment
    }

    pub fn commitment(&self, pc_gens: &PedersenGens) -> Commitment {
        self.revealed_commitment.commit(pc_gens)
    }

    pub fn sign(&self, msg: &[u8], pc_gens: &PedersenGens) -> Input {
        let public_key = self.public_key();
        let commitment = self.commitment(pc_gens);
        let signature = self.secret_key.sign(msg);

        Input {
            public_key,
            commitment,
            signature,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Input {
    pub public_key: PublicKey,
    pub commitment: Commitment,
    pub signature: Signature,
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.public_key.to_bytes().as_ref());
        v.extend(self.commitment.compress().as_bytes());
        v.extend(self.signature.to_bytes().as_ref());
        v
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn verify(&self, msg: &[u8], public_commitment: Commitment) -> Result<()> {
        // check that the public commitments matches the one in the input
        if self.commitment != public_commitment {
            return Err(Error::InvalidCommitment);
        }

        // check the signature
        if !self.public_key.verify(&self.signature, msg) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }
}
