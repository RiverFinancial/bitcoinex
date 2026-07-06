# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- BOLT11 invoice decoding now parses all `r` (route hint) fields instead of only the first. **Breaking:** `Invoice.route_hints` is now a list of route hints, each a list of `HopHint`s (`list(list(HopHint.t()))`), matching the BOLT11 spec where each `r` field is a separate private route. Empty `r` fields (invalid per BOLT11, which requires "one or more entries") are skipped, and invoices with more than 20 route hints are rejected during parsing with `:too_many_private_routes`.
- BOLT11 invoice decoding now parses all `f` (fallback address) fields instead of only the first, and correctly skips unknown-version `f` fields without blocking later valid ones. **Breaking:** `Invoice.fallback_address` (a single address or `nil`) is replaced by `Invoice.fallback_addresses`, a list of addresses in order of preference (empty if none).

## [0.1.8] - 2024-03-01
### Added
- Fix warning emitted from String.slice with negative step when parsing amountful BOLT11 invoices.

## [0.1.7] - 2023-01-16
### Added
- Support for Schnorr signature creation and validation
- Fixed bug which would not correctly parse a BOLT11 invoice with amount explicitly set to 0.
- Bump Elixir & Erlang Requirements & dependencies

## [0.1.4] - 2021-05-19
### Added
- BIP32 support with new modules for extended keys and derivation paths.
- Security document for vulnerability reports.
- Extra test for PSBT with 0 inputs and 0 outputs.

### Changed
- Jason updated to 1.2.2

## [0.1.3] - 2021-04-19
### Added
- Disclaimer to README.
- Support for Bech32m.
- Private key module with signing functionality.
- hash160 added to utils.

### Changed
- Decimal dependency.

## [0.1.2] - 2021-01-13
### Added
- Code snippet examples to README.
- Padding function to utils.

### Fixed
- Padding to public keys and transaction IDs.

## [0.1.1] - 2020-12-21
### Added
- Native Elixir Secp256k1 elliptic curve support with ECDSA public key recovery.

### Removed
- libsecp25k1 and ex_doc dependencies.

## [0.1.0] - 2020-12-02
### Added
- Bech32 and base58 encoding.
- Address and lightning invoice serialization.
- PSBT serialization.
- Transaction module.


[0.1.4]: https://diff.hex.pm/diff/bitcoinex/0.1.3..0.1.4
[0.1.3]: https://diff.hex.pm/diff/bitcoinex/0.1.2..0.1.3
[0.1.2]: https://diff.hex.pm/diff/bitcoinex/0.1.1..0.1.2
[0.1.1]: https://diff.hex.pm/diff/bitcoinex/0.1.0..0.1.1
[0.1.0]: https://preview.hex.pm/preview/bitcoinex/0.1.0