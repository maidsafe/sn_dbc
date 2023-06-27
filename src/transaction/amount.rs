// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use crate::{Error, Result};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const AMT_SIZE: usize = std::mem::size_of::<u64>(); // Amount size: 8 bytes (u64)

/// Represents a Dbc's value.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Amount {
    pub value: u64,
}

impl Amount {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.value.to_le_bytes());
        v
    }

    /// Build Amount from byte array reference.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AMT_SIZE {
            return Err(Error::InvalidAmountBytes);
        }
        let amount = u64::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });

        Ok(Self { value: amount })
    }
}
