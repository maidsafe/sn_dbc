// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::DbcContentHash;

/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
pub struct DbcSpent {
    pub input: DbcContentHash,
    pub output: Vec<DbcContentHash>,
}

impl DbcSpent {
    fn new(input: DbcContentHash, output: Vec<DbcContentHash>) -> Self {
        Self { input, output }
    }
}
