// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use bls_bulletproofs::{
    blstrs::{G1Affine, G1Projective, G2Affine, Scalar},
    group::{Curve, GroupEncoding},
    rand::RngCore,
    PedersenGens,
};

use super::{Error, Result, RevealedCommitment};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevealedInput {
    pub secret_key: Scalar,
    pub revealed_commitment: RevealedCommitment,
}

impl RevealedInput {
    pub fn new<S: Into<Scalar>>(secret_key: S, revealed_commitment: RevealedCommitment) -> Self {
        Self {
            secret_key: secret_key.into(),
            revealed_commitment,
        }
    }

    pub fn public_key(&self) -> G1Projective {
        super::public_key(self.secret_key)
    }

    pub fn revealed_commitment(&self) -> &RevealedCommitment {
        &self.revealed_commitment
    }

    /// Generate a pseudo-commitment to the input amount
    pub fn random_pseudo_commitment(&self, rng: impl RngCore) -> RevealedCommitment {
        RevealedCommitment::from_value(self.revealed_commitment.value, rng)
    }

    pub fn commitment(&self, pc_gens: &PedersenGens) -> G1Affine {
        self.revealed_commitment.commit(pc_gens).to_affine()
    }

    pub fn sign(
        &self,
        msg: &[u8],
        revealed_pseudo_commitment: &RevealedCommitment,
        pc_gens: &PedersenGens,
    ) -> Input {
        let public_key = self.public_key().to_affine();
        let commitment = self.commitment(pc_gens);
        let pseudo_commitment = revealed_pseudo_commitment.commit(pc_gens).to_affine();
        let signature = super::sign(self.secret_key, msg);

        Input {
            public_key,
            commitment,
            pseudo_commitment,
            signature,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Input {
    pub public_key: G1Affine,
    pub commitment: G1Affine,
    pub pseudo_commitment: G1Affine,
    pub signature: G2Affine,
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.public_key.to_bytes().as_ref());
        v.extend(self.commitment.to_bytes().as_ref());
        v.extend(self.pseudo_commitment.to_bytes().as_ref());
        v.extend(self.signature.to_bytes().as_ref());
        v
    }

    pub fn pseudo_commitment(&self) -> G1Affine {
        self.pseudo_commitment
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key
    }

    pub fn verify(&self, msg: &[u8], public_commitment: G1Affine) -> Result<()> {
        // check that the public commitments matches the one in the input
        if self.commitment != public_commitment {
            return Err(Error::InvalidCommitment);
        }

        // check the signature
        if !super::verify(self.signature, self.public_key, msg) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }
}
