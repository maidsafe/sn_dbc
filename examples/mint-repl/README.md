# mint-repl

[MaidSafe website](http://maidsafe.net) | [Safe Network Forum](https://safenetforum.org/)
:-------------------------------------: | :---------------------------------------------:

## About

This example implements a minimal P2P DBC Mint, built on sn_dbc, with an interactive ([repl](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop)) interface.  Sort of a playground for 
DBCs and BLS keys.  It implements both server (mint) and client functionality in a single process.

A design goal is to be interoperable with Ian Coleman's web BLS tool/playground at:
https://iancoleman.io/threshold_crypto_ui/

Key components are:
* [sn_dbc](https://github.com/maidsafe/sn_dbc/) - Safe Network DBC library
* [threshold_crypto](https://github.com/poanetwork/threshold_crypto) - BLS key library


## Building


```
$ cargo build --examples
```

## Running

```
$ cargo run --example mint-repl
```

Use the `help` command for a list of available commands.

For a simple guided reissue, use the `reissue_ez` command.

Alternatively, a manual reissue will use these commands in order.

`prepare_tx` --> `sign_tx` --> `prepare_reissue` --> `reissue`

## Usage Examples

- [reissue_ez](./sample_runs/reissue_ez.txt)
- [reissue_manual](./sample_runs/reissue_manual.txt)
- [newkey](./sample_runs/newkey.txt)
- [newmint](./sample_runs/newmint.txt)
- [validate](./sample_runs/validate.txt)
- [decode](./sample_runs/decode.txt)

## License

This Safe Network software is dual-licensed under the Modified BSD (<LICENSE-BSD> <https://opensource.org/licenses/BSD-3-Clause>) or the MIT license (<LICENSE-MIT> <https://opensource.org/licenses/MIT>) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
