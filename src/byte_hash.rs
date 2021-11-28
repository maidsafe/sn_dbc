// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Hash;
use tiny_keccak::{Hasher, Sha3};

pub trait ByteHash {
    /// represent as bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// hash
    fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.to_bytes());

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        Hash::from(hash)
    }
}
