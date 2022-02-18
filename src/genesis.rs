use crate::{Amount, KeyImage, Owner, OwnerOnce, PublicKeyBlst, SecretKeyBlst};
use blst_ringct::mlsag::{MlsagMaterial, TrueInput};
use blst_ringct::ringct::RingCtMaterial;
use blst_ringct::{Output, RevealedCommitment};
use blstrs::group::prime::PrimeCurveAffine;
use blstrs::group::Curve;
use blstrs::Scalar;
use blsttc::{poly::Poly, SecretKeySet};

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
        // Make a secret key for the input to Genesis Tx.
        let input_poly = Poly::zero();
        let input_secret_key_set = SecretKeySet::from(input_poly);

        // fixme, unwrap.
        // note: this is only temporary until blsttc is impld with blstrs.  At which
        // point the byte conversion and unwrap should not be necessary.
        // Thus, we are not returning a Result from this fn.
        let input_secret_key =
            SecretKeyBlst::from_bytes_be(&input_secret_key_set.secret_key().to_bytes()).unwrap();

        // Make a secret key for the output of Genesis Tx. (The Genesis Dbc)
        let poly = Poly::one();
        let secret_key_set = SecretKeySet::from(poly);

        let owner_once = OwnerOnce {
            owner_base: Owner::from(secret_key_set.secret_key()),
            derivation_index: [1; 32],
        };

        let secret_key_set_derived = secret_key_set.derive_child(&owner_once.derivation_index);

        // create sk and derive pk.
        let secret_key =
            SecretKeyBlst::from_bytes_be(&secret_key_set_derived.secret_key().to_bytes()).unwrap();
        let public_key = (PublicKeyBlst::generator() * secret_key).to_affine();

        let true_input = TrueInput {
            secret_key: input_secret_key,
            revealed_commitment: RevealedCommitment {
                value: Self::GENESIS_AMOUNT,
                blinding: 5.into(), // todo: choose Genesis blinding factor.
            },
        };

        let input_key_image = true_input.key_image().to_affine().into();

        // note: no decoy inputs because no other DBCs exist prior to genesis DBC.
        let decoy_inputs = vec![];

        let ring_len = decoy_inputs.len() + 1;
        let r: Vec<(Scalar, Scalar)> = (0..ring_len)
            .map(|_| (Scalar::default(), Scalar::default()))
            .collect();

        let mlsag_material = MlsagMaterial {
            true_input,
            decoy_inputs,
            pi_base: 0,
            alpha: (Default::default(), Default::default()),
            r,
        };

        let ringct_material = RingCtMaterial {
            inputs: vec![mlsag_material],
            outputs: vec![Output {
                public_key,
                amount: Self::GENESIS_AMOUNT,
            }],
        };

        Self {
            ringct_material,
            owner_once,
            input_key_image,
        }
    }
}
