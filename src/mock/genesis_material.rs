// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Amount, KeyImage, Owner, OwnerOnce};
use bls_ringct::{
    blstrs::Scalar,
    group::Curve,
    mlsag::{MlsagMaterial, TrueInput},
    ringct::RingCtMaterial,
    {Output, RevealedCommitment},
};
use blsttc::IntoFr;

/// represents all the inputs required to build the Genesis Dbc.
pub struct GenesisMaterial {
    pub ringct_material: RingCtMaterial,
    pub owner_once: OwnerOnce,
    pub input_key_image: KeyImage,
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
        let true_input = TrueInput::new(
            input_sk,
            RevealedCommitment {
                value: Self::GENESIS_AMOUNT,
                blinding: 1000.into(), // just a random number
            },
        );

        // make things a bit easier for our callers.
        let input_key_image: KeyImage = true_input.key_image().to_affine().into();

        // build our MlsagMaterial manually without randomness.
        // note: no decoy inputs because no other DBCs exist prior to genesis DBC.
        let mlsag_material = MlsagMaterial {
            true_input,
            decoy_inputs: vec![],
            pi_base: 0,
            alpha: (Default::default(), Default::default()),
            r: vec![(Scalar::default(), Scalar::default())],
        };

        // build the genesis RingCtMaterial
        let ringct_material = RingCtMaterial {
            inputs: vec![mlsag_material],
            outputs: vec![Output::new(
                output_sk_once.public_key(),
                Self::GENESIS_AMOUNT,
            )],
        };

        Self {
            ringct_material,
            owner_once: output_owner_once,
            input_key_image,
        }
    }
}
