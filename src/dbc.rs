// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeMap;

use crate::{DbcContent, DbcContentHash, DbcTransaction, Error, PubKey, Result, Signature};

pub struct Dbc {
    pub content: DbcContent,
    pub transaction: DbcTransaction,
    pub transaction_sigs: BTreeMap<DbcContentHash, (PubKey, Signature)>,
}

impl Dbc {
    // Check there exists a DbcTransaction with the output containing this Dbc
    // Check there DOES NOT exist a DbcTransaction with this Dbc as parent (already minted)
    pub fn confirm_valid(&self) -> Result<(), Error> {
        todo!();
        // if network.get(self.parent()).await {
        //     return err(Error::DoubleSpend);
        // }
    }
    // Check the output values summed are  =< input value
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<DbcTransaction> {
        // self.confirm_valid()?;
        todo!()
    }
}
