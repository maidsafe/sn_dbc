// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dbc_id::DbcIdSource,
    transaction::{Amount, Output, RevealedAmount, RevealedInput, RevealedTransaction},
    DbcId, DerivedKey, MainKey,
};
use blsttc::IntoFr;

/// represents all the inputs required to build the Genesis Dbc.
pub struct GenesisMaterial {
    pub input_dbc_id: DbcId,
    pub genesis_tx: RevealedTransaction,
    pub main_key: MainKey,
    pub derived_key: DerivedKey, // unlocks the genesis dbc
    pub dbc_id_src: DbcIdSource, // genesis dbc id is derived from these
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
        // note that this is the derived key.
        // (we have no need for the main key)
        let input_sk_seed: u64 = 1234567890;
        let input_derived_key =
            DerivedKey::new(blsttc::SecretKey::from_mut(&mut input_sk_seed.into_fr()));

        // Make a secret key for the output of Genesis Tx. (The Genesis Dbc)
        // note that this is the main key, from which we get a derived key.
        let output_main_key = MainKey::random();

        // Derivation index is the link between the DerivedKey and the MainKey.
        let output_derivation_index = [1; 32];
        let output_derived_key = output_main_key.derive_key(&output_derivation_index);

        // build our input
        let revealed_input = RevealedInput::new(
            input_derived_key,
            RevealedAmount {
                value: Self::GENESIS_AMOUNT,
                blinding_factor: 42u32.into(), // just a random number
            },
        );
        let input_dbc_id = revealed_input.dbc_id();

        // build the pre-genesis Transaction
        let genesis_tx = RevealedTransaction {
            inputs: vec![revealed_input],
            outputs: vec![Output::new(
                output_derived_key.dbc_id(),
                Self::GENESIS_AMOUNT,
            )],
        };

        let output_dbc_id_src = DbcIdSource {
            public_address: output_main_key.public_address(),
            derivation_index: output_derivation_index,
        };

        Self {
            input_dbc_id, // the id of the fictional dbc being reissued to genesis dbc
            genesis_tx,   // there genesis dbc was created
            main_key: output_main_key,
            derived_key: output_derived_key, // unlocks genesis
            dbc_id_src: output_dbc_id_src,
        }
    }
}
