// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use crate::{Amount, DbcId};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Output {
    pub dbc_id: DbcId,
    pub amount: Amount,
}

impl Output {
    pub fn new(dbc_id: DbcId, amount: u64) -> Self {
        Self {
            dbc_id,
            amount: Amount { value: amount },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.dbc_id.to_bytes().as_ref());
        v.extend(self.amount.to_bytes());
        v
    }

    pub fn dbc_id(&self) -> &DbcId {
        &self.dbc_id
    }
}
