// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::transaction::{Amount, Output, RevealedAmount, RevealedInput, RevealedTransaction};
use crate::{Owner, OwnerOnce, PublicKey};
use blsttc::IntoFr;

/// represents all the inputs required to build the Genesis Dbc.
pub struct GenesisMaterial {
    pub revealed_tx: RevealedTransaction,
    pub owner_once: OwnerOnce,
    pub input_public_key: PublicKey,
}

impl GenesisMaterial {
    /// The Genesis DBC will mint all possible tokens.
    pub const GENESIS_AMOUNT: Amount = Amount::MAX; // aka 2^64
}

impl Default for GenesisMaterial {
    /// generate the GenesisMaterial.
    ///
    /// It uses GenesisMaterial::GENESIS_AMOUNT by default
    fn default() -> Self {
        // Make a secret key for the input of Genesis Tx. (fictional Dbc)
        // note that this represents the one-time-use key.
        // (we have no need for the base key)
        let input_sk_seed: u64 = 1234567890;
        let input_sk = blsttc::SecretKey::from_mut(&mut input_sk_seed.into_fr());

        // Make a secret key for the output of Genesis Tx. (The Genesis Dbc)
        // note that this represents the base key, from which one-time-use key is derived.
        let output_sk = blsttc::SecretKey::random();

        // OwnerOnce ties together the base key and one-time-use key.
        let output_owner_once = OwnerOnce {
            owner_base: Owner::from(output_sk.clone()),
            derivation_index: [1; 32],
        };

        // note: we could call output_owner_once.owner().secret_key()
        //       but this way avoids need for an unwrap()
        let output_sk_once = output_sk.derive_child(&output_owner_once.derivation_index);

        // build our TrueInput
        let revealed_input = RevealedInput::new(
            input_sk,
            RevealedAmount {
                value: Self::GENESIS_AMOUNT,
                blinding_factor: 42u32.into(), // just a random number
            },
        );
        let input_public_key: PublicKey = revealed_input.public_key();

        // build the genesis Transaction
        let revealed_tx = RevealedTransaction {
            inputs: vec![revealed_input],
            outputs: vec![Output::new(
                output_sk_once.public_key(),
                Self::GENESIS_AMOUNT,
            )],
        };

        Self {
            revealed_tx,
            owner_once: output_owner_once,
            input_public_key,
        }
    }
}
