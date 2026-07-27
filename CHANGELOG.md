# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-01
### Added
- BIP-39 mnemonic support (`Bitcoinex.BIP39`): entropy-to-mnemonic encoding and decoding with checksum validation, NFKD-normalized seed derivation via PBKDF2-HMAC-SHA512, and master extended private key derivation.
- SLIP-39 Shamir's Secret-Sharing mnemonic support (`Bitcoinex.SLIP39`): two-level (group/member) secret splitting via `generate_mnemonics/4` and recovery via `combine_mnemonics/2`, with passphrase encryption (four-round Feistel over PBKDF2-HMAC-SHA256), GF(256) Shamir sharing with digest verification, RS1024 checksums, and the extendable share-set flag. Verified against all 45 official SLIP-0039 test vectors.

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