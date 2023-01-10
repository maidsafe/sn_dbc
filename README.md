# sn_dbc
Safe Network DBCs

|Crate|Documentation|CI|Safe Rust|
|:-:|:-:|:-:|:-:|
|[![](http://meritbadge.herokuapp.com/sn_dbc)](https://crates.io/crates/sn_dbc)|[![Documentation](https://docs.rs/sn_dbc/badge.svg)](https://docs.rs/sn_dbc)|![](https://github.com/maidsafe/sn_dbc/workflows/Master/badge.svg)|[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-error.svg)](https://github.com/rust-secure-code/safety-dance/)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:-:|:-:|:-:|

# About

This crate provides a library and API for working with Digital Bearer Certificates (DBC)
on the Safe Network.

Safe Network DBCs are envisioned to be a private and fungible digital currency that utilize a distributed (and sharded) spentbook/mint rather than a blockchain.

Some key properties of these DBCs:
* distributed mint means that it is not necessary to trust in a single mint entity
* sharded mint means that the system scales indefinitely
* transactions are settled immmediately
* privacy by default.  all transactions use privacy features.
* incorporates RingCT to obfuscate the transaction history
* utilizes a one-time key for each payment (aka stealh address)
* use BLS cryptography

At present DBC ownership is single signature only.   Multi-sig support is planned.
Older versions of this crates supported multi-sig, but that support was
temporarily removed when RingCT was incorporated.

Some writeups about the technology can be found at:

https://safenetforum.org/t/safenetwork-dbc-technical-series


# Building

```
$ git clone https://github.com/maidsafe/sn_dbc.git
$ cd sn_dbc
$ cargo build
```

# Running

## mint-repl example

A `mint-repl` example is provided which enables interacting with a mock
spentbook/mint and wallet.

```
$ cd sn_dbc
$ cargo run --example mint-repl
```

Additional examples can be found in a separate crate:

https://github.com/maidsafe/sn_dbc_examples

## benchmark(s)

```
$ cd sn_dbc
$ cargo bench
```

## tests

```
$ cd sn_dbc
$ cargo test
```

# Key dependencies:

This crate depends most heavily on:

- [blsttc](https://github.com/maidsafe/blsttc/) - BLS keys



## License

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
