// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Denomination, Error, Result};
use blsbs::{BlindSignerShare, Envelope, SignatureExaminer, SignedEnvelopeShare, Slip};
use blsttc::{IntoFr, SecretKeyShare};
pub use blsttc::{PublicKey, PublicKeySet, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub trait KeyManager {
    type Error: std::error::Error;

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare, Self::Error>;

    fn public_key_set(&self) -> Result<PublicKeySet, Self::Error>;

    #[allow(clippy::ptr_arg)]
    fn verify_slip(
        &self,
        slip: &Slip,
        derive_idx: &[u8],
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;

    fn verify_envelope(
        &self,
        envelope: &Envelope,
        derive_idx: &[u8],
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;

    fn verify_known_key(&self, key: &PublicKey, derive_idx: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone)]
pub struct SimpleSigner {
    blind_signer_share: BlindSignerShare,
}

#[cfg(feature = "dkg")]
impl From<bls_dkg::outcome::Outcome> for SimpleSigner {
    fn from(outcome: bls_dkg::outcome::Outcome) -> Self {
        Self {
            blind_signer_share: BlindSignerShare::new(
                outcome.secret_key_share,
                outcome.index,
                outcome.public_key_set,
            ),
        }
    }
}

impl SimpleSigner {
    pub fn new<T: IntoFr>(
        public_key_set: PublicKeySet,
        secret_key_share: (T, SecretKeyShare),
    ) -> Self {
        Self {
            blind_signer_share: BlindSignerShare::new(
                secret_key_share.1,
                secret_key_share.0,
                public_key_set,
            ),
        }
    }

    fn public_key_set(&self) -> &PublicKeySet {
        self.blind_signer_share.public_key_set()
    }

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare> {
        #[allow(clippy::redundant_closure)]
        self.blind_signer_share
            .derive_child(&denomination.to_be_bytes())
            .sign_envelope(envelope)
            .map_err(|e| Error::from(e))
    }
}

#[derive(Debug, Clone)]
pub struct SimpleKeyManager {
    signer: SimpleSigner,
    cache: Keys,
}

impl SimpleKeyManager {
    pub fn new(signer: SimpleSigner, genesis_key: PublicKey) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = Keys::default();
        cache.add_known_key(genesis_key);
        cache.add_known_key(public_key_set.public_key());
        Self { signer, cache }
    }
}

impl KeyManager for SimpleKeyManager {
    type Error = crate::Error;

    fn public_key_set(&self) -> Result<PublicKeySet> {
        Ok(self.signer.public_key_set().clone())
    }

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare> {
        self.signer.sign_envelope(envelope, denomination)
    }

    #[allow(clippy::ptr_arg)]
    fn verify_slip(
        &self,
        slip: &Slip,
        derive_idx: &[u8],
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<()> {
        self.cache.verify_slip(slip, derive_idx, key, signature)
    }

    fn verify_envelope(
        &self,
        envelope: &Envelope,
        derive_idx: &[u8],
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<()> {
        self.cache
            .verify_envelope(envelope, derive_idx, key, signature)
    }

    fn verify_known_key(&self, key: &PublicKey, derive_idx: &[u8]) -> Result<()> {
        self.cache.verify_known_key(key, derive_idx)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Keys(HashSet<PublicKey>);

impl From<Vec<PublicKey>> for Keys {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self(keys.into_iter().collect())
    }
}

impl Keys {
    pub fn add_known_key(&mut self, key: PublicKey) {
        self.0.insert(key);
    }

    #[allow(clippy::ptr_arg)]
    fn verify_slip(
        &self,
        slip: &Slip,
        derive_idx: &[u8],
        key: &PublicKey,
        sig: &Signature,
    ) -> Result<()> {
        self.verify_known_key(key, derive_idx)?;
        let is_verified = SignatureExaminer::verify_signature_on_slip(slip, sig, key);
        if is_verified {
            Ok(())
        } else {
            Err(Error::FailedMintSignature)
        }
    }

    fn verify_envelope(
        &self,
        envelope: &Envelope,
        derive_idx: &[u8],
        key: &PublicKey,
        sig: &Signature,
    ) -> Result<()> {
        self.verify_known_key(key, derive_idx)?;
        let is_verified = SignatureExaminer::verify_signature_on_envelope(envelope, sig, key);
        if is_verified {
            Ok(())
        } else {
            Err(Error::FailedMintSignature)
        }
    }

    fn verify_known_key(&self, key: &PublicKey, derive_idx: &[u8]) -> Result<()> {
        // note: if we are caching many keys (eg after many section churns), this could get slow.
        // It would be faster to store/lookup denomination keys for each master key.
        // Alternatively, if we included the mint's derivation root in the DBC, then we
        // could just "know" it.  Though that increases DBC size and wire usage.

        for pk in self.0.iter() {
            if pk.derive_child(derive_idx) == *key {
                return Ok(());
            }
        }

        Err(Error::UnrecognisedAuthority)
    }
}
