// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use super::{Amount, Error, Result};
use crate::{DbcId, DbcTransaction, DerivedKey};
use blsttc::Signature;
#[cfg(feature = "serde")]
use serde::{self, Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Input {
    pub dbc_id: DbcId,
    pub amount: Amount,
    /// This is the signature of the `DerivedKey`
    /// corresponding to this `dbc_id`
    pub signature: Signature,
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.dbc_id.to_bytes().as_ref());
        v.extend(self.amount.to_bytes());
        v.extend(self.signature.to_bytes().as_ref());
        v
    }

    pub fn dbc_id(&self) -> DbcId {
        self.dbc_id
    }

    /// Verify the Signature
    pub fn verify(&self, msg: &[u8]) -> Result<()> {
        if !self.dbc_id.verify(&self.signature, msg) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct InputIntermediate {
    pub amount: Amount,
    pub derived_key: DerivedKey,
    pub input_src_tx: DbcTransaction,
}

impl InputIntermediate {
    pub fn dbc_id(&self) -> DbcId {
        self.derived_key.dbc_id()
    }

    pub fn sign(&self, msg: &[u8]) -> Input {
        Input {
            dbc_id: self.dbc_id(),
            amount: self.amount,
            signature: self.derived_key.sign(msg),
        }
    }
}
