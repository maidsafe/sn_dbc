// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{DbcContent, DbcSpent, PubKey, Result, Signature};

pub struct Dbc {
    pub content: DbcContent,
    pub parent_spent: DbcSpent,
    pub mint_key: PubKey,
    pub mint_sig: Signature, // (self.parent_spent),
}

impl Dbc {
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<Vec<Self>> {
        Ok(vec![])
    }
}
