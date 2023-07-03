# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [19.1.1](https://github.com/maidsafe/sn_dbc/compare/v19.1.0...v19.1.1) (2023-06-29)


### Bug Fixes

* check for overflow while adding values ([3c27b94](https://github.com/maidsafe/sn_dbc/commit/3c27b94311db585a76cc94369142d50ccdfb61b0))

## [19.1.0](https://github.com/maidsafe/sn_dbc/compare/v19.0.1...v19.1.0) (2023-06-20)


### Features

* include parent tx in spend ([3e8f3bf](https://github.com/maidsafe/sn_dbc/commit/3e8f3bf8ede4d29eb902d5db8af6299a095d0423))

### [19.0.1](https://github.com/maidsafe/sn_dbc/compare/v19.0.0...v19.0.1) (2023-06-12)

## [19.0.0](https://github.com/maidsafe/sn_dbc/compare/v18.1.0...v19.0.0) (2023-05-31)


### ⚠ BREAKING CHANGES

* remove bincode serialisation from Hash hex-encoding

* remove bincode serialisation from Hash hex-encoding ([84312ec](https://github.com/maidsafe/sn_dbc/commit/84312ece1f65fbc51e02974ea5db25af8ca4db13))

## [18.1.0](https://github.com/maidsafe/sn_dbc/compare/v18.0.0...v18.1.0) (2023-05-31)


### Features

* only print dbc_id when printing SignedSpend ([3351dc8](https://github.com/maidsafe/sn_dbc/commit/3351dc8a5efc1b53638e65620261eab326f3eb5d))

## [18.0.0](https://github.com/maidsafe/sn_dbc/compare/v17.0.1...v18.0.0) (2023-05-19)


### ⚠ BREAKING CHANGES

* renames fields and methods in Spend

### Features

* rename spends with better names ([3a608aa](https://github.com/maidsafe/sn_dbc/commit/3a608aa93da224e604a9a95359b64732a68f202f))

### [17.0.1](https://github.com/maidsafe/sn_dbc/compare/v17.0.0...v17.0.1) (2023-05-01)

## [17.0.0](https://github.com/maidsafe/sn_dbc/compare/v16.0.1...v17.0.0) (2023-04-13)


### ⚠ BREAKING CHANGES

* have dbcs take derived key

* have dbcs take derived key ([8a124c9](https://github.com/maidsafe/sn_dbc/commit/8a124c925fed3810dd6c1a7843b0ceed1356757d))

### [16.0.1](https://github.com/maidsafe/sn_dbc/compare/v16.0.0...v16.0.1) (2023-04-12)


### Bug Fixes

* expose the new type taken in api ([ada0dc9](https://github.com/maidsafe/sn_dbc/commit/ada0dc9a2fd61cf1a471340cb70938262add73f0))

## [16.0.0](https://github.com/maidsafe/sn_dbc/compare/v15.1.0...v16.0.0) (2023-04-12)


### ⚠ BREAKING CHANGES

* include spend src tx hash
* update encrypt api to take dbc id

### Features

* expose sign fn for main key ([a94a0ef](https://github.com/maidsafe/sn_dbc/commit/a94a0ef283034efec32fb8b4d919dc48746eb04b))
* expose verify fn for public address ([23c2a8c](https://github.com/maidsafe/sn_dbc/commit/23c2a8c30c0c7b49775cc639ebedf56e0e91169a))
* update encrypt api to take dbc id ([ef6b308](https://github.com/maidsafe/sn_dbc/commit/ef6b308148626f27db8c94c8d55122a7279fe949))


### Bug Fixes

* **txbuilder:** take borrowed mainkey ([3523055](https://github.com/maidsafe/sn_dbc/commit/35230556f51790c0734fbd65ebd4f7f50f508a30))


* include spend src tx hash ([ed9285c](https://github.com/maidsafe/sn_dbc/commit/ed9285c30b821054d76caac5782d38bd288c6180))

## [15.1.0](https://github.com/maidsafe/sn_dbc/compare/v15.0.1...v15.1.0) (2023-04-11)


### Features

* gen rand dbc id src from public address ([6beae69](https://github.com/maidsafe/sn_dbc/commit/6beae69bd23d53536d1f6c8d738ca97d0b6e500f))

### [15.0.1](https://github.com/maidsafe/sn_dbc/compare/v15.0.0...v15.0.1) (2023-04-11)

## [15.0.0](https://github.com/maidsafe/sn_dbc/compare/v14.0.0...v15.0.0) (2023-04-09)


### ⚠ BREAKING CHANGES

* **spend:** include tx instead of only hash

* **spend:** include tx instead of only hash ([8b8089a](https://github.com/maidsafe/sn_dbc/commit/8b8089a651a3d39992f017ba974a4158f7804ed6))

## [14.0.0](https://github.com/maidsafe/sn_dbc/compare/v13.0.0...v14.0.0) (2023-04-08)


### ⚠ BREAKING CHANGES

* remove consensus signatures

### Features

* remove consensus signatures ([4e3b38d](https://github.com/maidsafe/sn_dbc/commit/4e3b38d7c502b6096c60ac4a3b82b4f391104d9e))

## [13.0.0](https://github.com/maidsafe/sn_dbc/compare/v12.0.0...v13.0.0) (2023-04-05)


### ⚠ BREAKING CHANGES

* make bearer a user concern

* make bearer a user concern ([eab9509](https://github.com/maidsafe/sn_dbc/commit/eab950938e01f407622e99d1621a5111bfab73be))

## [12.0.0](https://github.com/maidsafe/sn_dbc/compare/v11.0.1...v12.0.0) (2023-03-27)


### ⚠ BREAKING CHANGES

* **builder:** keep revealedoutputs
* rename Input to BlindedInput
* rename OutputProof to BlindedOutput

* **builder:** keep revealedoutputs ([d3f0c43](https://github.com/maidsafe/sn_dbc/commit/d3f0c430ef9ecd99d25763b3b4a4c18ac6ed2f99))
* rename Input to BlindedInput ([3c9ff69](https://github.com/maidsafe/sn_dbc/commit/3c9ff694380cfcd898093c51a1f817bee8cccf91))
* rename OutputProof to BlindedOutput ([4fc3c9f](https://github.com/maidsafe/sn_dbc/commit/4fc3c9f4a33cb702c1ddf9fb122462265829d546))

### [11.0.1](https://github.com/maidsafe/sn_dbc/compare/v11.0.0...v11.0.1) (2023-03-23)


### Bug Fixes

* **benches:** place unix dep under compiler flag ([3ccac46](https://github.com/maidsafe/sn_dbc/commit/3ccac4647c1c79a5998b637c520d741f4a45d773))

## [11.0.0](https://github.com/maidsafe/sn_dbc/compare/v10.0.0...v11.0.0) (2023-03-22)


### ⚠ BREAKING CHANGES

* rename commitment to blinded amount

* rename commitment to blinded amount ([59c21f8](https://github.com/maidsafe/sn_dbc/commit/59c21f8541abcfad79c1654d162b0e5d14b6793d))

## [10.0.0](https://github.com/maidsafe/sn_dbc/compare/v9.0.0...v10.0.0) (2023-03-15)


### ⚠ BREAKING CHANGES

* changes the API of DBCs

### Features

* add public key and commitment easy access to dbc api ([294431e](https://github.com/maidsafe/sn_dbc/commit/294431e11218a1a5ec111e857da41f474f28f5de))

## [9.0.0](https://github.com/maidsafe/sn_dbc/compare/v8.4.0...v9.0.0) (2023-03-02)


### ⚠ BREAKING CHANGES

* Changes the SpentProofs

### Features

* dbc reasons in SpentProof ([6a6eeea](https://github.com/maidsafe/sn_dbc/commit/6a6eeead49494f6bc76d36d9b31f2560869db209))
* to from hex string for Hash ([f20e23c](https://github.com/maidsafe/sn_dbc/commit/f20e23c5fae065674373f99dad80b239fe6fcdef))


### Bug Fixes

* fix iterator misuse ([1c9d701](https://github.com/maidsafe/sn_dbc/commit/1c9d701518ca5bcb63ccdf23540c3c2f07ce1bdb))
* serde flag ([d309251](https://github.com/maidsafe/sn_dbc/commit/d309251c40f8ae0f5a8e1ef25d7c6527b125a2ce))

## [8.4.0](https://github.com/maidsafe/sn_dbc/compare/v8.3.1...v8.4.0) (2023-02-28)


### Features

* **builder:** add api for adding spentproof ([3cfb58d](https://github.com/maidsafe/sn_dbc/commit/3cfb58de45e46b32209a470d3aad3a10d09c3080))

### [8.3.1](https://github.com/maidsafe/sn_dbc/compare/v8.3.0...v8.3.1) (2023-02-21)

## [8.3.0](https://github.com/maidsafe/sn_dbc/compare/v8.2.2...v8.3.0) (2023-02-16)


### Features

* expose PedersenGens ([fc7b40e](https://github.com/maidsafe/sn_dbc/commit/fc7b40e27f8519a35959fd5eaee5c09756a31fce))


### Bug Fixes

* forgotten rename ([4b17ebf](https://github.com/maidsafe/sn_dbc/commit/4b17ebfa9ae52a92f7be06dc6a46ac497cf0e77d))

### [8.2.2](https://github.com/maidsafe/sn_dbc/compare/v8.2.1...v8.2.2) (2023-02-15)


### Bug Fixes

* cargo keywords ([5bf3f33](https://github.com/maidsafe/sn_dbc/commit/5bf3f338aade0b0ea4a03c065aed3531bbddbc3f))

### [8.2.1](https://github.com/maidsafe/sn_dbc/compare/v8.2.0...v8.2.1) (2023-02-15)


### Bug Fixes

* remove space in keywords ([20fdc79](https://github.com/maidsafe/sn_dbc/commit/20fdc79b46542a8c646476f1912606ec88d9c4df))

## [8.2.0](https://github.com/maidsafe/sn_dbc/compare/v8.1.1...v8.2.0) (2023-02-14)


### Features

* add domain separators to msg encoding ([34348f3](https://github.com/maidsafe/sn_dbc/commit/34348f30c69b1a3588166e50b33e3ecc1dbde874))
* domain separators for DbcTransaction encoding ([6ac9400](https://github.com/maidsafe/sn_dbc/commit/6ac9400c3e2d95f91527e3ae1875ba419acb015e))
* remove hand wavy crypto, use blsttc ([c25ef94](https://github.com/maidsafe/sn_dbc/commit/c25ef94f3c5ec61f0cf6640ba23398472687e6e7))
* remove ringct ([e06e9f0](https://github.com/maidsafe/sn_dbc/commit/e06e9f01a7b8a3b746b694dcdc7124dbcf7d1ff1))
* remove ringct dependency ([746cec3](https://github.com/maidsafe/sn_dbc/commit/746cec33c017c65b2bac87233f55dca4604cd6f9))
* revamp input commitment code ([423e3dc](https://github.com/maidsafe/sn_dbc/commit/423e3dc6499e1898410f5f00866b330d22cc408b))
* use safer bulletproofs instead of bls_bulletproofs ([e6cb255](https://github.com/maidsafe/sn_dbc/commit/e6cb2554f770046256520a05b5f6ddda9593b696))


### Bug Fixes

* broken test ([0d391e3](https://github.com/maidsafe/sn_dbc/commit/0d391e36f78f73aa52f66f888fd1281fbcfbe7de))
* genesis reissue failure in mint_repl ([6e501fe](https://github.com/maidsafe/sn_dbc/commit/6e501fea2166d58f4debf6d04026ab9baf598f6a))
* serde flag ([985170f](https://github.com/maidsafe/sn_dbc/commit/985170fb30e633b8728bf71f0e69e587582ff5eb))

## [8.2.0](https://github.com/maidsafe/sn_dbc/compare/v8.1.1...v8.2.0) (2023-02-08)


### Features

* add domain separators to msg encoding ([34348f3](https://github.com/maidsafe/sn_dbc/commit/34348f30c69b1a3588166e50b33e3ecc1dbde874))
* domain separators for DbcTransaction encoding ([6ac9400](https://github.com/maidsafe/sn_dbc/commit/6ac9400c3e2d95f91527e3ae1875ba419acb015e))
* remove hand wavy crypto, use blsttc ([c25ef94](https://github.com/maidsafe/sn_dbc/commit/c25ef94f3c5ec61f0cf6640ba23398472687e6e7))
* remove ringct ([e06e9f0](https://github.com/maidsafe/sn_dbc/commit/e06e9f01a7b8a3b746b694dcdc7124dbcf7d1ff1))
* remove ringct dependency ([746cec3](https://github.com/maidsafe/sn_dbc/commit/746cec33c017c65b2bac87233f55dca4604cd6f9))
* revamp input commitment code ([423e3dc](https://github.com/maidsafe/sn_dbc/commit/423e3dc6499e1898410f5f00866b330d22cc408b))
* use safer bulletproofs instead of bls_bulletproofs ([e6cb255](https://github.com/maidsafe/sn_dbc/commit/e6cb2554f770046256520a05b5f6ddda9593b696))


### Bug Fixes

* broken test ([0d391e3](https://github.com/maidsafe/sn_dbc/commit/0d391e36f78f73aa52f66f888fd1281fbcfbe7de))
* genesis reissue failure in mint_repl ([6e501fe](https://github.com/maidsafe/sn_dbc/commit/6e501fea2166d58f4debf6d04026ab9baf598f6a))
* serde flag ([985170f](https://github.com/maidsafe/sn_dbc/commit/985170fb30e633b8728bf71f0e69e587582ff5eb))

## [8.2.0](https://github.com/maidsafe/sn_dbc/compare/v8.1.1...v8.2.0) (2023-02-02)


### Features

* add domain separators to msg encoding ([34348f3](https://github.com/maidsafe/sn_dbc/commit/34348f30c69b1a3588166e50b33e3ecc1dbde874))
* domain separators for DbcTransaction encoding ([6ac9400](https://github.com/maidsafe/sn_dbc/commit/6ac9400c3e2d95f91527e3ae1875ba419acb015e))
* remove hand wavy crypto, use blsttc ([c25ef94](https://github.com/maidsafe/sn_dbc/commit/c25ef94f3c5ec61f0cf6640ba23398472687e6e7))
* remove ringct ([e06e9f0](https://github.com/maidsafe/sn_dbc/commit/e06e9f01a7b8a3b746b694dcdc7124dbcf7d1ff1))
* remove ringct dependency ([746cec3](https://github.com/maidsafe/sn_dbc/commit/746cec33c017c65b2bac87233f55dca4604cd6f9))
* revamp input commitment code ([423e3dc](https://github.com/maidsafe/sn_dbc/commit/423e3dc6499e1898410f5f00866b330d22cc408b))


### Bug Fixes

* broken test ([0d391e3](https://github.com/maidsafe/sn_dbc/commit/0d391e36f78f73aa52f66f888fd1281fbcfbe7de))
* genesis reissue failure in mint_repl ([6e501fe](https://github.com/maidsafe/sn_dbc/commit/6e501fea2166d58f4debf6d04026ab9baf598f6a))
* serde flag ([985170f](https://github.com/maidsafe/sn_dbc/commit/985170fb30e633b8728bf71f0e69e587582ff5eb))

### [8.1.2](https://github.com/maidsafe/sn_dbc/compare/v8.1.1...v8.1.2) (2023-01-04)

### [8.1.2](https://github.com/maidsafe/sn_dbc/compare/v8.1.1...v8.1.2) (2022-12-13)

### [8.1.1](https://github.com/maidsafe/sn_dbc/compare/v8.1.0...v8.1.1) (2022-11-08)

## [8.1.0](https://github.com/maidsafe/sn_dbc/compare/v8.0.0...v8.1.0) (2022-09-23)


### Features

* function to get commitments from transaction ([fa23ff9](https://github.com/maidsafe/sn_dbc/commit/fa23ff9f1a6e2fa40ca53c8b80a23c3f5bdbb9e8))

## [8.0.0](https://github.com/maidsafe/sn_dbc/compare/v7.2.0...v8.0.0) (2022-08-16)


### ⚠ BREAKING CHANGES

* reducing spent proof verification public API scope to only check it is known key

* reducing spent proof verification public API scope to only check it is known key ([cf559f1](https://github.com/maidsafe/sn_dbc/commit/cf559f11b5c3db3c05ceb26223513a2e674a04b6))

## [7.2.0](https://github.com/maidsafe/sn_dbc/compare/v7.1.0...v7.2.0) (2022-08-04)


### Features

* expose Token type in public API ([5333138](https://github.com/maidsafe/sn_dbc/commit/53331387d8bd24a96ab4b85b6416ea877abf1287))

## [7.1.0](https://github.com/maidsafe/sn_dbc/compare/v7.0.1...v7.1.0) (2022-07-28)


### Features

* expose a public API which allows to build a SpentProof from a given set of proof shares ([d25a01b](https://github.com/maidsafe/sn_dbc/commit/d25a01b14392beacd8f07f3c100603cf5a73ba91))

### [7.0.1](https://github.com/maidsafe/sn_dbc/compare/v7.0.0...v7.0.1) (2022-07-20)

## [7.0.0](https://github.com/maidsafe/sn_dbc/compare/v6.0.0...v7.0.0) (2022-07-07)


### ⚠ BREAKING CHANGES

* simplifying spent proofs and TX verification public APIs

### Features

* simplifying spent proofs and TX verification public APIs ([e4ec6ce](https://github.com/maidsafe/sn_dbc/commit/e4ec6ce4f94bd9e7167b41fa52bdb84ef5996807))

## [6.0.0](https://github.com/maidsafe/sn_dbc/compare/v5.0.0...v6.0.0) (2022-06-29)


### ⚠ BREAKING CHANGES

* changes in the API due to Dbc struct change, but also due
to moving GenesisMaterial to the mock/exmaple mod as it's not needed in public API.
* embed the transaction which spent the inputs within the Dbc struct

### Features

* embed the transaction which spent the inputs within the Dbc struct ([7db1874](https://github.com/maidsafe/sn_dbc/commit/7db18742a985268ee850acbc904795e87971b892))


* keeping spent transactions within Dbc in a set rather than a vec ([861288a](https://github.com/maidsafe/sn_dbc/commit/861288a431cb069698df7389aff7043bd6ec64bf))

## [5.0.0](https://github.com/maidsafe/sn_dbc/compare/v4.0.0...v5.0.0) (2022-06-16)


### ⚠ BREAKING CHANGES

* **errors:** additional context information to Error::SpentProofInputLenMismatch

### Features

* **errors:** additional context information to Error::SpentProofInputLenMismatch ([3e291d7](https://github.com/maidsafe/sn_dbc/commit/3e291d734d9a21f7a54dc68d4cec80afe42143df))

## [4.0.0](https://github.com/maidsafe/sn_dbc/compare/v3.3.0...v4.0.0) (2022-06-11)


### ⚠ BREAKING CHANGES

* a change from the blsttc release cascades here to require the error type to remove
derivation from `Serialize` and `Deserialize`.

This release includes some utilities for converting keys to and from hex, which I have been making
use of in work related to owned DBCs.

* update blsttc to 6.0.0 ([f5fddba](https://github.com/maidsafe/sn_dbc/commit/f5fddba49974c073eff8bd0dd75e5f6eafb850b1))

## [3.3.0](https://github.com/maidsafe/sn_dbc/compare/v3.2.1...v3.3.0) (2022-06-09)


### Features

* convert owned dbc to bearer ([40a1775](https://github.com/maidsafe/sn_dbc/commit/40a1775b6b244478ffc2c72e4c4abbd0937c45f8))

### [3.2.1](https://github.com/maidsafe/sn_dbc/compare/v3.2.0...v3.2.1) (2022-06-03)

## [3.2.0](https://github.com/maidsafe/sn_dbc/compare/v3.1.2...v3.2.0) (2022-06-02)


### Features

* provide hex serialization utilities ([abfa4da](https://github.com/maidsafe/sn_dbc/commit/abfa4da5447fc2498dc739d379cfe7cc04f9781a))

### [3.1.2](https://github.com/maidsafe/sn_dbc/compare/v3.1.1...v3.1.2) (2022-05-12)

### [3.1.1](https://github.com/maidsafe/sn_dbc/compare/v3.1.0...v3.1.1) (2022-04-21)

## [3.1.0](https://github.com/maidsafe/sn_dbc/compare/v3.0.1...v3.1.0) (2022-04-20)


### Features

* **api:** decouple the verification of Tx and spentproofs from DbcBuilder::build ([918b076](https://github.com/maidsafe/sn_dbc/commit/918b076050670a3c3c1103ad967ce574c7d98e22))

### [3.0.1](https://github.com/maidsafe/sn_dbc/compare/v3.0.0...v3.0.1) (2022-04-19)

## [3.0.0](https://github.com/maidsafe/sn_dbc/compare/v2.18.0...v3.0.0) (2022-04-08)


### ⚠ BREAKING CHANGES

* The sn_ringct crate was renamed to bls_ringct, so we update this reference.

* reference renamed ringct crate ([2d15911](https://github.com/maidsafe/sn_dbc/commit/2d15911eee1dd01bc4ece91ff294722255e54c76))

### [2.17.1](https://github.com/maidsafe/sn_dbc/compare/v2.17.0...v2.17.1) (2022-04-05)

## [2.17.0](https://github.com/maidsafe/sn_dbc/compare/v2.16.3...v2.17.0) (2022-04-05)


### Features

* serialize blsttc and ringct error variants ([18c80a3](https://github.com/maidsafe/sn_dbc/commit/18c80a3aae9d1b459b7c1704d6cd564199a61a8f))

### [2.16.3](https://github.com/maidsafe/sn_dbc/compare/v2.16.2...v2.16.3) (2022-04-05)


### Bug Fixes

* avoid true input inclusion in decoys ([7dd204e](https://github.com/maidsafe/sn_dbc/commit/7dd204eef4a551c2507fcd9720cba648cb1c6935))

### [2.16.2](https://github.com/maidsafe/sn_dbc/compare/v2.16.1...v2.16.2) (2022-03-29)


### Bug Fixes

* filter true input from decoy inputs ([0b7b133](https://github.com/maidsafe/sn_dbc/commit/0b7b133650bce18ca37b6ff6410b41a1a617b6aa))

### [2.16.1](https://github.com/maidsafe/sn_dbc/compare/v2.16.0...v2.16.1) (2022-03-29)

## [2.16.0](https://github.com/maidsafe/sn_dbc/compare/v2.15.0...v2.16.0) (2022-03-24)


### Features

* decouple deps and remove bls_dkg ([48f4b84](https://github.com/maidsafe/sn_dbc/commit/48f4b847cd065e74372dd4cc37af105fc930df92))

## [2.15.0](https://github.com/maidsafe/sn_dbc/compare/v2.14.2...v2.15.0) (2022-03-22)


### Features

* impl add_output(s)_by_amount() methods ([2f5b01d](https://github.com/maidsafe/sn_dbc/commit/2f5b01df486fb8fe00f8267b4c2bd3fa372c1325))
* integrate blsttc+blstrs ([ae4d0ca](https://github.com/maidsafe/sn_dbc/commit/ae4d0ca711a4cdc2dad266d3e18250d9cb504995))
* remove mint and related data structures ([5e043c6](https://github.com/maidsafe/sn_dbc/commit/5e043c6f38cd3212741243742ea9d183ad9e5d46))

### [2.14.2](https://github.com/maidsafe/sn_dbc/compare/v2.14.1...v2.14.2) (2022-03-14)


### Bug Fixes

* verify that ReissueShare match ([6f1eb89](https://github.com/maidsafe/sn_dbc/commit/6f1eb89c5ffd911a1d1e97350ec1349b622b069a))

### [2.14.1](https://github.com/maidsafe/sn_dbc/compare/v2.14.0...v2.14.1) (2022-03-07)


### Bug Fixes

* avoid unnecessary sig verifications ([d6f9036](https://github.com/maidsafe/sn_dbc/commit/d6f90366f4181a7f4ba329fe51f06ea32e293316))
* make prop_dbc_validation pass ([e0d3453](https://github.com/maidsafe/sn_dbc/commit/e0d345342760b184d11e972bfb556e72dff82de4))
* verify Tx in DbcBuilder::build() ([6db3a00](https://github.com/maidsafe/sn_dbc/commit/6db3a00edc992237058d6fe00804cd907dd4997b))

## [2.14.0](https://github.com/maidsafe/sn_dbc/compare/v2.13.1...v2.14.0) (2022-03-03)


### Features

* verify (always) Amount matches Commitment ([d38c5de](https://github.com/maidsafe/sn_dbc/commit/d38c5de725dd39b44cc37f3c72f03b9eede8338e))

### [2.13.1](https://github.com/maidsafe/sn_dbc/compare/v2.13.0...v2.13.1) (2022-03-02)

## [2.13.0](https://github.com/maidsafe/sn_dbc/compare/v2.12.2...v2.13.0) (2022-02-23)


### Features

* make GenesisMaterial available to wallets ([aad4e7f](https://github.com/maidsafe/sn_dbc/commit/aad4e7f4ed9dba3a9d001a98372eb315889eccae))
* make GenesisMaterial usable by any node ([3b8d2d2](https://github.com/maidsafe/sn_dbc/commit/3b8d2d2664a1c5d1b7c8a61ff4272e82274fd6e9))
* set genesis seed values ([d45477c](https://github.com/maidsafe/sn_dbc/commit/d45477c5e0a38ffe89623ed329513e25fd1ce5ac))


### Bug Fixes

* use TransactionMustHaveAnInput from ringct ([e0a814e](https://github.com/maidsafe/sn_dbc/commit/e0a814e11ac6eebea6865beff2cab454317ba928))

### [2.12.2](https://github.com/maidsafe/sn_dbc/compare/v2.12.1...v2.12.2) (2022-02-23)


### Bug Fixes

* change BTreeSet<SpentProofShare> to HashSet ([cf8a030](https://github.com/maidsafe/sn_dbc/commit/cf8a03006d04ffb3c34225113dbca5ecf3aa38f0))

### [2.12.1](https://github.com/maidsafe/sn_dbc/compare/v2.12.0...v2.12.1) (2022-02-23)

## [2.12.0](https://github.com/maidsafe/sn_dbc/compare/v2.11.2...v2.12.0) (2022-02-23)


### Features

* remove the key image maths ([a8f40ed](https://github.com/maidsafe/sn_dbc/commit/a8f40ed8021143c3896fadb10179589e5c9b77a7))

### [2.11.2](https://github.com/maidsafe/sn_dbc/compare/v2.11.1...v2.11.2) (2022-02-23)


### Bug Fixes

* return Spentbook errors. don't panic ([b280bde](https://github.com/maidsafe/sn_dbc/commit/b280bde92b8265bd1c1e3f1aa4e5789a394af84d))

### [2.11.1](https://github.com/maidsafe/sn_dbc/compare/v2.11.0...v2.11.1) (2022-02-23)

## [2.11.0](https://github.com/maidsafe/sn_dbc/compare/v2.10.0...v2.11.0) (2022-02-23)


### Features

* moved input and key image uniqueness checks to blst-ringct ([df4da9e](https://github.com/maidsafe/sn_dbc/commit/df4da9e7738727dbe0397c2ce7e879ab6eaca018))

## [2.10.0](https://github.com/maidsafe/sn_dbc/compare/v2.9.2...v2.10.0) (2022-02-17)


### Features

* add Dbc::key_image() for checking if spent ([f72fe8f](https://github.com/maidsafe/sn_dbc/commit/f72fe8f04656328cce313dc0ee25389864a1f539))
* add GenesisBuilderMock ([cfc2b67](https://github.com/maidsafe/sn_dbc/commit/cfc2b673d657bf0d1dbce02bff9ddfcc032e1d45))
* add input/output getters to Tx builder ([78d910c](https://github.com/maidsafe/sn_dbc/commit/78d910c103b83d6d827a864badd2e28eeee3cd15))
* add mock spentbook to tests ([f1ee03c](https://github.com/maidsafe/sn_dbc/commit/f1ee03c4a1f9d1ffc8710fa4f5530ebc563a6f51))
* add serde feature flag ([ff32395](https://github.com/maidsafe/sn_dbc/commit/ff323950405538a4d8ba72642c53371462599dbc))
* add spentbook pubkey to mint's key_manager ([c2bce8b](https://github.com/maidsafe/sn_dbc/commit/c2bce8b04ad11038cc3c65de196917efaa7a2200))
* include AmountSecrets ciphertext in DbcContent ([90f8a01](https://github.com/maidsafe/sn_dbc/commit/90f8a01505211262b0dec04fff6d2477c57e12a2))
* integrate ringct into sn_dbc. wip: it now builds without warnings ([289b242](https://github.com/maidsafe/sn_dbc/commit/289b242c1b65ebb033841fd99fd3f5812c914277))
* re-enable two tests: tests::hash, mint::tests::prop_genesis ([b239316](https://github.com/maidsafe/sn_dbc/commit/b239316f657d3fa4b7eeb938baf2e5d780e91303))
* return RingCtMaterial from TransactionBuilder::build() ([afede07](https://github.com/maidsafe/sn_dbc/commit/afede07dbe5aa99c20bf3a5368480c65222c59b4))
* update mint-repl to use ringct ([5c41110](https://github.com/maidsafe/sn_dbc/commit/5c4111054b5cdd88aa6026382f41d71e2f880dfd))
* use PublicKey from KeyManager for genesis dbc owner ([29dd342](https://github.com/maidsafe/sn_dbc/commit/29dd3428647fc2f801f1d8e00f4d133f4a8b145f))
* validate tx in spentbook ([42fb29e](https://github.com/maidsafe/sn_dbc/commit/42fb29e664fa719652f403b3b60213dc1554346c))
* working on ringct integration. does not build ([411d8d3](https://github.com/maidsafe/sn_dbc/commit/411d8d35fad773df5bc4dab4aab5e1862a97a7d1))


### Bug Fixes

* avoid possible panic in issue_genesis_dbc ([5fa45c7](https://github.com/maidsafe/sn_dbc/commit/5fa45c71d9e6e5d41511e50eff6ec413bf49b728))
* first pass at public_commitments. prop_splitting_the_genesis_dbc() test (mostly) passes ([cf38ec7](https://github.com/maidsafe/sn_dbc/commit/cf38ec7c07bf420c8ee9ee3b452370cc968ceca9))
* handle empty output_amounts in test prop_splitting_the_genesis_dbc ([26c05dd](https://github.com/maidsafe/sn_dbc/commit/26c05dde23da436f38c4356383ebd062e5bcff28))
* make dbc_packet.rs build again ([6670818](https://github.com/maidsafe/sn_dbc/commit/6670818d8db6c36bb015eb061487724a9c5eab9a))
* make ReissueRequestBuilder and DbcBuilder build again ([6db4449](https://github.com/maidsafe/sn_dbc/commit/6db44494eb688b0d5dedfbf6aabe0c8881f08ac2))
* prop_dbc_transaction_many_to_many() is passing now ([d0e29f3](https://github.com/maidsafe/sn_dbc/commit/d0e29f3b0a4c07a6d4af1f2733b6df0eed2917d4))
* refactor to include tx_hash in spentbook sig ([2069d34](https://github.com/maidsafe/sn_dbc/commit/2069d3421141241be02c4e6f502d386b008bec79))
* refactor to validate spent_proofs in Dbc::confirm_valid ([0059b3e](https://github.com/maidsafe/sn_dbc/commit/0059b3ed907d35a00afe4992762f0781f9565fb6))
* reverse logic valdiating spentproof shares ([b9d2e5c](https://github.com/maidsafe/sn_dbc/commit/b9d2e5ca4fa0d381096375bd7d3dd705ca920f0d))
* **mint:** verify KeyImage unique across inputs ([56c62c8](https://github.com/maidsafe/sn_dbc/commit/56c62c8eeec0032d1cbe3311aa1a9f9227482e82))
* **reissue:** key mint sigs by mlsag index not KeyImage ([5d0b72f](https://github.com/maidsafe/sn_dbc/commit/5d0b72f2ea0aeaf9edcdc5a675a696f38340f837))
* use deterministic secret key for genesis dbc ([4edfd6c](https://github.com/maidsafe/sn_dbc/commit/4edfd6cf11774a2885c705e78730e711f6504c13))

### [2.9.2](https://github.com/maidsafe/sn_dbc/compare/v2.9.1...v2.9.2) (2021-12-04)

### [2.9.1](https://github.com/maidsafe/sn_dbc/compare/v2.9.0...v2.9.1) (2021-10-22)


### Bug Fixes

* **tests:** fix many-to-many test handling of invalid + valid proofs ([8bbf2e7](https://github.com/maidsafe/sn_dbc/commit/8bbf2e7130834d2889c334f5fa517b70b6fa4827))

## [2.9.0](https://github.com/maidsafe/sn_dbc/compare/v2.8.0...v2.9.0) (2021-10-21)


### Features

* add DbcPacket and DerivedKeySet ([1042a63](https://github.com/maidsafe/sn_dbc/commit/1042a634d85d76e8df9281f49d2f34a0cfd45394))

## [2.8.0](https://github.com/maidsafe/sn_dbc/compare/v2.7.1...v2.8.0) (2021-10-14)


### Features

* **client-writes-spentbook:** move reissue flow to SpentProofs ([fb7635c](https://github.com/maidsafe/sn_dbc/commit/fb7635c0a74cee9bb6202b220033da1b9da8ae5d))
* **spentproofs:** mint-repl is working again ([930b643](https://github.com/maidsafe/sn_dbc/commit/930b64319c8eb542abf62abe4fe3f28dfdb621c1))
* **spentproofs:** update benches ([482cb97](https://github.com/maidsafe/sn_dbc/commit/482cb9774a11fdef259b82535c28452d410048fa))

### [2.7.1](https://github.com/maidsafe/sn_dbc/compare/v2.7.0...v2.7.1) (2021-09-21)

## [2.7.0](https://github.com/maidsafe/sn_dbc/compare/v2.6.0...v2.7.0) (2021-09-16)


### Features

* add ReissueRequestBuilder to simplify aggregating dbc ownership proofs ([b0c3d5a](https://github.com/maidsafe/sn_dbc/commit/b0c3d5ae1b6e49534ddef75763141530cbace9dd))

## [2.6.0](https://github.com/maidsafe/sn_dbc/compare/v2.5.0...v2.6.0) (2021-09-14)


### Features

* **forced-one-time-keys:** dbc name is the owner ([0b4e9ef](https://github.com/maidsafe/sn_dbc/commit/0b4e9efef238ad5014f66211d99136f9e9ff8356))
* **forced-one-time-keys:** derive spending key from dbc hash ([1e1fbd1](https://github.com/maidsafe/sn_dbc/commit/1e1fbd168b57bed7515e5db93cc5148e2955dd3d))
* **forced-one-time-keys:** mint-repl works with dbc name change ([6ba078b](https://github.com/maidsafe/sn_dbc/commit/6ba078bb87cfff95428d15a2a65ec1a87d2a449f))
* **forced-one-time-keys:** remove blinded owner ([987b65e](https://github.com/maidsafe/sn_dbc/commit/987b65e8fb308d85c3d3c1e9430d6ede01af1313))
* **forced-one-time-keys:** update benchmarks ([1ea8cd3](https://github.com/maidsafe/sn_dbc/commit/1ea8cd3a0d17ca60443d23af8372deefe52fc37b))
* **forced-one-time-keys:** update mint-repl & benchmarks ([c8ae2e1](https://github.com/maidsafe/sn_dbc/commit/c8ae2e1edbd8d5a8d25657cfa3266e6774846ec0))
* **mint-repl:** more robust input handling ([51e9e43](https://github.com/maidsafe/sn_dbc/commit/51e9e43cd3ba078c4b70742dd31eb27ea7e7fd4e))

## [2.5.0](https://github.com/maidsafe/sn_dbc/compare/v2.4.2...v2.5.0) (2021-09-07)


### Features

* add DbcBuilder ([66fda04](https://github.com/maidsafe/sn_dbc/commit/66fda04e4589c4d97b105a1bb6d6ae25232f120b))
* add errors NoReissueShares and NoReissueTransaction ([f6aa707](https://github.com/maidsafe/sn_dbc/commit/f6aa7070ccdea830ebd536c52c34b2697ff7fc56))

### [2.4.2](https://github.com/maidsafe/sn_dbc/compare/v2.4.1...v2.4.2) (2021-08-19)


### Bug Fixes

* **bench:** fixes [#79](https://github.com/maidsafe/sn_dbc/issues/79) - bug in code to generate ownership proofs ([082e4bb](https://github.com/maidsafe/sn_dbc/commit/082e4bb9f3fd56a68408dd0c6c445540d2203659))
* **dkg:** use Outcome::index instead of hardcoding 0 ([0650b37](https://github.com/maidsafe/sn_dbc/commit/0650b378abed9e9c946c46db2013bc64aa6013e2))
* make dbc_content::AmountSecrets impl Copy ([5b5ef05](https://github.com/maidsafe/sn_dbc/commit/5b5ef059f5272f6e9df1ff3786487954c71b2fb5))

### [2.4.1](https://github.com/maidsafe/sn_dbc/compare/v2.4.0...v2.4.1) (2021-08-19)

## [2.4.0](https://github.com/maidsafe/sn_dbc/compare/v2.3.0...v2.4.0) (2021-08-18)


### Features

* **builder:** add fns for getting input/output sum and input hashes ([5eeae06](https://github.com/maidsafe/sn_dbc/commit/5eeae0623285242a7d91c68914f5649c559b499c))

## [2.3.0](https://github.com/maidsafe/sn_dbc/compare/v2.2.0...v2.3.0) (2021-08-17)


### Features

* **tx_builder:** introduce transaction builder pattern ([d0539a7](https://github.com/maidsafe/sn_dbc/commit/d0539a7a929a1cfc7027553c6d99da508faefa9f))


### Bug Fixes

* address CR comments - fix naming and spelling ([e796cfe](https://github.com/maidsafe/sn_dbc/commit/e796cfe7c96a87a27c7f50f1e24244a9145919c9))

## [2.2.0](https://github.com/maidsafe/sn_dbc/compare/v2.1.0...v2.2.0) (2021-08-13)


### Features

* add APIs that enable recipient to verify AmountSecrets match committed amount ([54776ee](https://github.com/maidsafe/sn_dbc/commit/54776eef6edf5973f5a543700a76292ecb0475d5))
* confidential transactions.  pedersen commitments + bulletproofs (range proofs) ([ee2623e](https://github.com/maidsafe/sn_dbc/commit/ee2623e9d30551bf731be0a3ead3969e39626376))

## [2.1.0](https://github.com/maidsafe/sn_dbc/compare/v2.0.0...v2.1.0) (2021-07-07)


### Features

* remove IntoIterator requirement on SpendBook trait ([c0ac6c2](https://github.com/maidsafe/sn_dbc/commit/c0ac6c2b215fc853d4d979bb68fd13d8862c92ea))

## [2.0.0](https://github.com/maidsafe/sn_dbc/compare/v1.7.0...v2.0.0) (2021-06-29)


### ⚠ BREAKING CHANGES

* updates to use blsstc

### Features

* use blsstc instead of threshold_crypto ([4044c27](https://github.com/maidsafe/sn_dbc/commit/4044c27aca4fdf03ec7e13a01e7cde4b9605e107))

## [1.7.0](https://github.com/maidsafe/sn_dbc/compare/v1.6.8...v1.7.0) (2021-06-24)


### Features

* add SpendBook::entries() to enforce type of Iterator values ([5a6d20e](https://github.com/maidsafe/sn_dbc/commit/5a6d20ec1a9d15fe363aab24a77d11e5db72c9c8))
* make SpendBook a trait so that implementer can decide how to store it ([287a341](https://github.com/maidsafe/sn_dbc/commit/287a34131da204a20d0a03a08bca0ac4e1acd0d9))
* return Result for SpendBook trait methods.  adds Error::SpendBook enum ([5bddb4c](https://github.com/maidsafe/sn_dbc/commit/5bddb4c346a140e2eb44f59641bc46dedcce94e5))

### [1.6.8](https://github.com/maidsafe/sn_dbc/compare/v1.6.7...v1.6.8) (2021-06-21)


### Bug Fixes

* **tests:** also match on the mapped errors ([df5c98c](https://github.com/maidsafe/sn_dbc/commit/df5c98c1b5ee3106c26b73642cefb50b0cd61d38))

### [1.6.7](https://github.com/maidsafe/sn_dbc/compare/v1.6.6...v1.6.7) (2021-06-17)

### [1.6.6](https://github.com/maidsafe/sn_dbc/compare/v1.6.5...v1.6.6) (2021-06-16)

### [1.6.5](https://github.com/maidsafe/sn_dbc/compare/v1.6.4...v1.6.5) (2021-06-15)

### [1.6.4](https://github.com/maidsafe/sn_dbc/compare/v1.6.3...v1.6.4) (2021-06-10)

### [1.6.3](https://github.com/maidsafe/sn_dbc/compare/v1.6.2...v1.6.3) (2021-06-09)

### [1.6.2](https://github.com/maidsafe/sn_dbc/compare/v1.6.1...v1.6.2) (2021-06-08)

### [1.6.1](https://github.com/maidsafe/sn_dbc/compare/v1.6.0...v1.6.1) (2021-06-07)

## [1.6.0](https://github.com/maidsafe/sn_dbc/compare/v1.5.0...v1.6.0) (2021-06-03)


### Features

* **mint:** replace ed25519 mint identities with BLS ([78baf59](https://github.com/maidsafe/sn_dbc/commit/78baf59d7f7e09c31ca083f459420ac15c847be5))


### Bug Fixes

* **bench:** update benchmarks to work with the new BLS keys ([e3da1fb](https://github.com/maidsafe/sn_dbc/commit/e3da1fb37dabc4b548ca819425065fd70f763f7a))
* **bls:** remove ed25519 dependency ([d46422a](https://github.com/maidsafe/sn_dbc/commit/d46422a5a6c9672ca805d7108e600ed32bfdf8ec))
* **mint:** replace mint keys with key sets; fixed size BLS indices ([3bd7e29](https://github.com/maidsafe/sn_dbc/commit/3bd7e29f7579414c884f8d092e0ef58debff514f))

## [1.5.0](https://github.com/maidsafe/sn_dbc/compare/v1.4.0...v1.5.0) (2021-06-02)


### Features

* **bench:** benchmark split and merge reissus ([852ac41](https://github.com/maidsafe/sn_dbc/commit/852ac41ddb46726268f81ff1c58bda5a52e6b9e3))

## [1.4.0](https://github.com/maidsafe/sn_dbc/compare/v1.3.1...v1.4.0) (2021-05-28)


### Features

* **owners:** blind owners in dbccontent ([f63454b](https://github.com/maidsafe/sn_dbc/commit/f63454bed3f3addfeecb9399422c17cd909c1e7f))

### [1.3.1](https://github.com/maidsafe/sn_dbc/compare/v1.3.0...v1.3.1) (2021-05-28)

## [1.3.0](https://github.com/maidsafe/sn_dbc/compare/v1.2.0...v1.3.0) (2021-05-27)


### Features

* redefine Hash as a struct so we can impl Display on it, and print as base64 ([b540203](https://github.com/maidsafe/sn_dbc/commit/b540203c5d988943662d91050d00939afd725cd4))

## [1.2.0](https://github.com/maidsafe/sn_dbc/compare/v1.1.0...v1.2.0) (2021-05-25)


### Features

* **mint:** take input hashes belonging to mint, in reissue method ([37b826b](https://github.com/maidsafe/sn_dbc/commit/37b826bf3a15d1a3215eb333544330edd7c7b83b))

## [1.1.0](https://github.com/maidsafe/sn_dbc/compare/v1.0.8...v1.1.0) (2021-05-19)


### Features

* **dbc_owner:** dbc_content now has an owner ([0eaede9](https://github.com/maidsafe/sn_dbc/commit/0eaede9640a51e51092dbde4881ce3e4676ae211))
* **dbc_owners:** make room in MintRequest for input ownership proof ([58f84af](https://github.com/maidsafe/sn_dbc/commit/58f84af22e4cb5494053eec65934c8a277ff6e0b))


### Bug Fixes

* **dbc_owner:** verify input owner proofs ([ffb5b66](https://github.com/maidsafe/sn_dbc/commit/ffb5b664dece2550b84d696a38fc18134689c74b))
* **fuzz_testing:** start fuzzing for ownership proofs ([b83e0eb](https://github.com/maidsafe/sn_dbc/commit/b83e0ebc9fece40c47ab38b9ab8240f22762b838))
* **owner:** depend on threshold_crypto instead of bls_dkg ([1fd6a7b](https://github.com/maidsafe/sn_dbc/commit/1fd6a7ba2a8871125cec4a469c37787d70b7eeaa))
* **owner:** tests are now fuzzing the owner field ([fd81ae0](https://github.com/maidsafe/sn_dbc/commit/fd81ae087575bcbbf7f6f4ece0a74f5bb4f8e52d))

### [1.0.8](https://github.com/maidsafe/sn_dbc/compare/v1.0.7...v1.0.8) (2021-05-11)

### [1.0.7](https://github.com/maidsafe/sn_dbc/compare/v1.0.6...v1.0.7) (2021-05-11)


### Bug Fixes

* **mint:** ensure mint request balances; validate output parents ([18835d6](https://github.com/maidsafe/sn_dbc/commit/18835d68f716ce3cdbdf5f6fbbd16580fe5bb5fa))
* **mint:** output parents are now checked ([93ae081](https://github.com/maidsafe/sn_dbc/commit/93ae081e027bc01b2f31112c1710da04108efdc1))
* **mint:** validate output numbering ([64f67df](https://github.com/maidsafe/sn_dbc/commit/64f67df94eaa6d1322514a2fdcd8bf0e33858246))

### [1.0.6](https://github.com/maidsafe/sn_dbc/compare/v1.0.5...v1.0.6) (2021-05-11)

### [1.0.5](https://github.com/maidsafe/sn_dbc/compare/v1.0.4...v1.0.5) (2021-05-06)

### [1.0.4](https://github.com/maidsafe/sn_dbc/compare/v1.0.3...v1.0.4) (2021-05-06)

### [1.0.3](https://github.com/maidsafe/sn_dbc/compare/v1.0.2...v1.0.3) (2021-05-06)

### [1.0.2](https://github.com/maidsafe/sn_dbc/compare/v1.0.1...v1.0.2) (2021-05-06)


### Bug Fixes

* **build:** remove references to vec{set,map} ([c937710](https://github.com/maidsafe/sn_dbc/commit/c9377107cbefd0dab5002ea75f1bc9fd8e3eec75))

### 1.0.1 (2021-05-06)

### 1.0.1 (2021-05-06)

### [0.1.0](https://github.com/maidsafe/sn_dbc/compare/v0.1.0...v0.1.0) (2021-05-06)

## 0.1.0 (2021-05-06)

* **sn_dbc:** initial implementation
