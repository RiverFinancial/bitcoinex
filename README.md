# Bitcoinex

Bitcoinex is striving to be the best and up-to-date Bitcoin Library for Elixir.

## Documentation
Documentation is available on [hexdocs.pm](https://hexdocs.pm/bitcoinex/api-reference.html).

## Current Utilities
* Serialization and validation for Bech32 and Base58.
* Support for standard on-chain scripts (P2PKH..P2WPKH) and Bolt#11 Lightning Invoices.
* Transaction serialization.
* Basic PSBT (BIP174) parsing.

## Usage

With [Hex](https://hex.pm/packages/bitcoinex):

    {:bitcoinex, "~> 0.1.0"}

Local:

    $ mix deps.get
    $ mix compile

## Roadmap
Continued support for on-chain and off-chain functionality including:
* Full script support including validation.
* Block serialization.
* Transaction creation.
* Broader BIP support including BIP32.

## Contributing
We have big goals and this library is still in a very early stage. Contributions and comments are very much welcome.