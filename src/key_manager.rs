// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Denomination, Error, Hash, Result};
use blsbs::{BlindSignerShare, Envelope, SignatureExaminer, SignedEnvelopeShare, Slip};
use blsttc::{Fr, IntoFr, SecretKeyShare, SignatureShare};
pub use blsttc::{PublicKey, PublicKeySet, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSignature {
    index: Fr,
    sig: SignatureShare,
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for NodeSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        blsttc::FrRepr::from(self.index).0.hash(state);
        self.sig.hash(state)
    }
}

impl NodeSignature {
    pub fn new(index: Fr, sig: SignatureShare) -> Self {
        Self { index, sig }
    }

    pub fn threshold_crypto(&self) -> (Fr, &SignatureShare) {
        (self.index, &self.sig)
    }
}

pub trait KeyManager {
    type Error: std::error::Error;

    fn sign(&self, msg_hash: &Hash) -> Result<NodeSignature, Self::Error>;

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare, Self::Error>;

    fn public_key_set(&self) -> Result<PublicKeySet, Self::Error>;

    fn verify(
        &self,
        msg_hash: &Hash,
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;

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

    fn verify_known_key(&self, key: &PublicKey) -> Result<(), Self::Error>;
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

    fn index(&self) -> Fr {
        self.blind_signer_share.secret_key_share_index()
    }

    fn public_key_set(&self) -> PublicKeySet {
        self.blind_signer_share.public_key_set().clone()
    }

    fn sign<M: AsRef<[u8]>>(&self, msg: M) -> blsttc::SignatureShare {
        self.blind_signer_share.secret_key_share().sign(msg)
    }

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare> {
        #[allow(clippy::redundant_closure)]
        self.blind_signer_share
            .derive_child(&denomination.to_bytes())
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
        Ok(self.signer.public_key_set())
    }

    fn sign_envelope(
        &self,
        envelope: Envelope,
        denomination: Denomination,
    ) -> Result<SignedEnvelopeShare> {
        self.signer.sign_envelope(envelope, denomination)
    }

    fn sign(&self, msg_hash: &Hash) -> Result<NodeSignature> {
        Ok(NodeSignature::new(
            self.signer.index(),
            self.signer.sign(msg_hash),
        ))
    }

    fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify(msg_hash, key, signature)
    }

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

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        self.cache.verify_known_key(key)
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

    fn verify(&self, msg: &Hash, key: &PublicKey, sig: &Signature) -> Result<()> {
        // TODO(drusu): this needs to be implemented once we continue our rebase
        // self.verify_known_key(key)?;
        if key.verify(sig, msg) {
            Ok(())
        } else {
            Err(Error::FailedMintSignature)
        }
    }

    #[allow(clippy::ptr_arg)]
    fn verify_slip(
        &self,
        slip: &Slip,
        derive_idx: &[u8],
        key: &PublicKey,
        sig: &Signature,
    ) -> Result<()> {
        self.verify_known_key(key)?;
        let derived_key = key.derive_child(derive_idx);
        if SignatureExaminer::verify_signature_on_slip(slip, sig, &derived_key) {
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
        self.verify_known_key(key)?;
        let derived_key = key.derive_child(derive_idx);
        let is_verified =
            SignatureExaminer::verify_signature_on_envelope(envelope, sig, &derived_key);
        if is_verified {
            Ok(())
        } else {
            Err(Error::FailedMintSignature)
        }
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        // note: if we are caching many keys (eg after many section churns), this could get slow.
        // It would be faster to store/lookup denomination keys for each master key.
        // Alternatively, if we included the mint's derivation root in the DBC, then we
        // could just "know" it.  Though that increases DBC size and wire usage.

        for pk in self.0.iter() {
            if pk == key {
                return Ok(());
            }
        }

        Err(Error::UnrecognisedAuthority)
    }
}
