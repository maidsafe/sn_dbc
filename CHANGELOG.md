# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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
