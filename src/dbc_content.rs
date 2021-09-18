// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use blsbs::Slip;
use blsttc::PublicKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::{Denomination, Hash};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbcContent {
    owner: PublicKey,

    // temporary: to prevent collision if owner key is re-used.
    // todo: remove when forced-one-time keys are added.
    nonce: [u8; 32],

    // DBC recipient(s) must validate with Mint's sig and
    // denonomination.to_bytes() as derivation index of Mint's pubkey.
    denomination: Denomination,
}

impl DbcContent {
    pub fn new(owner: PublicKey, denomination: Denomination) -> Self {
        Self {
            nonce: rand::thread_rng().gen::<[u8; 32]>(),
            owner,
            denomination,
        }
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.owner.to_bytes());
        sha3.update(&self.nonce);
        sha3.update(&self.denomination.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    pub fn slip(&self) -> Slip {
        let mut slip: Slip = Default::default();
        slip.extend(self.owner.to_bytes());
        slip.extend(self.nonce);
        slip.extend(self.denomination.to_bytes());
        slip
    }

    pub fn owner(&self) -> PublicKey {
        self.owner
    }

    pub fn denomination(&self) -> Denomination {
        self.denomination
    }
}
