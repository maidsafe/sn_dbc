use crate::{Amount, BlsHelper, KeyImage, Owner, OwnerOnce};
use blst_ringct::mlsag::{MlsagMaterial, TrueInput};
use blst_ringct::ringct::RingCtMaterial;
use blst_ringct::{Output, RevealedCommitment};
use blstrs::group::Curve;
use blstrs::Scalar;
use blsttc::IntoFr;

/// represents all the inputs required to build the Genesis Dbc.
pub struct GenesisMaterial {
    pub ringct_material: RingCtMaterial,
    pub owner_once: OwnerOnce,
    pub input_key_image: KeyImage,
}

impl GenesisMaterial {
    /// The Genesis DBC will mint all possible tokens.
    pub const GENESIS_AMOUNT: Amount = 18446744073709551615; // aka 2^64 aka Amount::MAX
}

impl Default for GenesisMaterial {
    /// generate the GenesisMaterial.
    ///
    /// It is allowed to pass in an amount for local testing purposes.
    /// However, to participate on a public network (mainnet, testnet)
    /// one must use GenesisMaterial::STD_GENESIS_AMOUNT
    ///
    /// todo: implement Network enum {Mainnet, Testnet, ...}
    fn default() -> Self {
        // Make a secret key for the input of Genesis Tx. (fictional Dbc)
        // note that this represents the one-time-use key.
        // (we have no need for the base key)
        // The seed is an homage to bitcoin.  block 0 timestamp (utc).
        let input_sk_seed: u64 = 1231006505;
        let input_sk = blsttc::SecretKey::from_mut(&mut input_sk_seed.into_fr());

        // Make a secret key for the output of Genesis Tx. (The Genesis Dbc)
        // note that this represents the base key, from which one-time-use key is derived.
        // The seed is an homage to monero.  block 1 timestamp (utc).
        // We do not use the block 0 timestamp because it is 0 (1970) which is boring!
        let output_sk_seed: u64 = 1397843393;
        let output_sk = blsttc::SecretKey::from_mut(&mut output_sk_seed.into_fr());

        // OwnerOnce ties together the base key and one-time-use key.
        let output_owner_once = OwnerOnce {
            owner_base: Owner::from(output_sk.clone()),
            derivation_index: [1; 32],
        };

        // note: we could call output_owner_once.owner().secret_key()
        //       but this way avoids need for an unwrap()
        let output_sk_once = output_sk.derive_child(&output_owner_once.derivation_index);

        // build our TrueInput
        let true_input = TrueInput {
            secret_key: BlsHelper::blsttc_to_blstrs_secret_key(input_sk),
            revealed_commitment: RevealedCommitment {
                value: Self::GENESIS_AMOUNT,
                blinding: 1776.into(), // freedom baby!
            },
        };

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

        // onward to RingCtMaterial
        let ringct_material = RingCtMaterial {
            inputs: vec![mlsag_material],
            outputs: vec![Output {
                public_key: BlsHelper::blsttc_to_blstrs_public_key(&output_sk_once.public_key()),
                amount: Self::GENESIS_AMOUNT,
            }],
        };

        // Voila!
        Self {
            ringct_material,
            owner_once: output_owner_once,
            input_key_image,
        }
    }
}
