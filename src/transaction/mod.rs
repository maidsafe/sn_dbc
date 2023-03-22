// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

mod error;
mod input;
mod output;
mod revealed_amount;

pub(crate) use error::Error;
pub use input::{Input, RevealedInput};
pub use output::{Amount, DbcTransaction, Output, OutputProof, RevealedTransaction};
pub use revealed_amount::RevealedAmount;

type Result<T> = std::result::Result<T, Error>;
