// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    builder::InputSrcTx, transaction::Output, DbcId, DbcTransaction, DerivationIndex, DerivedKey,
    FeeOutput, Input, MainKey,
};
use blsttc::IntoFr;

/// Represents all the inputs required to build the Genesis Dbc.
pub struct GenesisMaterial {
    pub input_dbc_id: DbcId,
    pub genesis_tx: (DbcTransaction, DerivedKey, InputSrcTx),
    pub main_key: MainKey,
    pub derivation_index: DerivationIndex,
}

impl GenesisMaterial {
    /// The Genesis DBC will mint all possible tokens.
    pub const GENESIS_AMOUNT: u64 = u64::MAX; // aka 2^64
}

impl Default for GenesisMaterial {
    /// Generate the GenesisMaterial.
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

        // Build the transaction where genesis was created.
        let input = Input::new(input_derived_key.dbc_id(), Self::GENESIS_AMOUNT);
        let output = Output::new(output_derived_key.dbc_id(), Self::GENESIS_AMOUNT);
        let genesis_tx = DbcTransaction {
            inputs: vec![input],
            outputs: vec![output],
            fee: FeeOutput::default(),
        };

        let input_src_tx = DbcTransaction::empty();

        Self {
            input_dbc_id: input_derived_key.dbc_id(), // the id of the fictional dbc being reissued to genesis dbc
            genesis_tx: (genesis_tx, input_derived_key, input_src_tx), // there genesis dbc was created
            main_key: output_main_key,
            derivation_index: output_derivation_index,
        }
    }
}
