# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- `Transaction.Utils.serialize_compact_size_unsigned_int/1` now encodes values above `0xFFFFFFFF` as a `0xFF`-prefixed little-endian uint64. The final `cond` branch previously read `compact_size <= 0xFF` (unreachable), so any such value raised `CondClauseError`.
- PSBT (de)serialization is now lossless for all BIP-174 v0 fields. `PSBT.encode_b64/1` previously dropped the global `version`, per-input `por_commitment`, and any proprietary records (`Global.serialize_global/1` carried a `TODO: serialize all other fields`), so `decode |> encode_b64` was not the identity for many PSBTs.
- `In.partial_sig` is now a **list** of `%{public_key: .., signature: ..}` records. It is a repeatable field (keyed by pubkey), and the previous single-map representation kept only the last record, silently discarding all but one signature from any multisig PSBT on decode.
- `Transaction` decoding now represents an input's empty witness stack as `%Witness{txinwitness: []}` (previously the integer `0`), which made re-serialization of any transaction containing one — e.g. a PSBT `non_witness_utxo` in segwit form with a mixed witness/non-witness input set — raise `Protocol.UndefinedError`.
### Added
- PSBT parsing now covers the BIP-174 v0 input hash-preimage fields (`ripemd160`, `sha256`, `hash160`, `hash256`) and preserves unrecognized proprietary (`:proprietary`) and unknown (`:unknown`) key-value records on every map, so they round-trip.
- PSBT decoding now rejects malformed inputs per BIP-174: duplicate keys (`{:error, :duplicate_key}`), a known key type carrying wrong-length key data (`:invalid_key_format`), a wrong-length `sighash_type` or `version` value (`:invalid_sighash_type` / `:invalid_version`), a missing global unsigned tx (`:missing_unsigned_tx`), an unsigned tx with a non-empty scriptSig (`:unsigned_tx_has_script_sig`) or a witness/non-canonical serialization (`:unsigned_tx_not_canonically_serialized`), trailing bytes after the final output map (`:trailing_bytes`), and truncated/oversized data — instead of crashing or silently accepting.
- PSBT decoding rejects non-minimally encoded compact size lengths (`{:error, :non_canonical_compact_size}` for key lengths and the global unsigned-tx value length; `:invalid_psbt` for other value lengths), as BIP-174 requires. These were previously accepted and re-serialized minimally, breaking byte-for-byte losslessness — and a non-minimally encoded *zero* key length produced an empty key that re-serialized as a map separator, so `decode |> encode_b64` silently emitted a different valid PSBT.
- PSBT decoding rejects a `non_witness_utxo` whose transaction does not re-serialize to the exact value bytes (`{:error, :invalid_non_witness_utxo}`), mirroring the existing canonical-serialization check on the global unsigned tx.
- PSBT decoding also rejects trailing bytes *inside* a value payload — a `witness_utxo` with bytes after the scriptPubKey (`:invalid_witness_utxo`), a `final_scriptwitness` with bytes after the last stack item (`:invalid_final_scriptwitness`), and an `xpub`/`bip32_derivation` value whose path bytes are not whole 32-bit indexes (`:invalid_derivation`) — and, with the same errors, a `witness_utxo` or `final_scriptwitness` whose internal compact sizes are non-minimal, so the value could not re-serialize byte-for-byte. These were previously accepted and silently re-encoded differently, breaking losslessness.
- PSBT decoding rejects 65-byte (uncompressed) public keys in `partial_sig`/`bip32_derivation` records with `{:error, :uncompressed_public_key}`. BIP-174 permits them, but bitcoinex cannot represent them faithfully (deliberate limitation, see the `Bitcoinex.PSBT` moduledoc).
- `PSBT.encode_b64/1` and `PSBT.to_file/2` return `{:error, :missing_unsigned_tx}` for a (hand-built) PSBT lacking the mandatory global unsigned transaction, instead of emitting a PSBT their own decoder rejects.

## [0.2.0] - 2026-07-10
### Changed
- BOLT11 invoice decoding now rejects invoices longer than 7089 characters with `{:error, :overall_max_length_exceeded}`, matching rust-lightning's limit (the capacity of the largest QR code). This bounds the work done decoding untrusted input now that all `r` (route hint) and `f` (fallback address) fields are parsed.
### Fixed
- BOLT11 invoice decoding now parses all `r` (route hint) fields instead of only the first. **Breaking:** `Invoice.route_hints` is now a list of route hints, each a list of `HopHint`s (`list(list(HopHint.t()))`), matching the BOLT11 spec where each `r` field is a separate private route. Empty `r` fields (invalid per BOLT11, which requires "one or more entries") are skipped.
- BOLT11 invoice decoding now parses all `f` (fallback address) fields instead of only the first, and correctly skips unknown-version and empty `f` fields without blocking later valid ones or failing the decode. **Breaking:** `Invoice.fallback_address` (a single address or `nil`) is replaced by `Invoice.fallback_addresses`, a list of addresses in order of preference (empty if none).
- BOLT11 `f` (fallback address) fields with version 17 (P2PKH) or 18 (P2SH) now require a 20-byte hash payload; any other length fails the decode with `:invalid_pubkey_hash_length` / `:invalid_script_hash_length` instead of encoding a garbage address.
- Removed an unreachable `Invoice.decode/1` clause that shadowed the `{:error, :no_ln_prefix}` error; the error is (and was) returned by HRP parsing inside the main clause, so behavior is unchanged.
### Removed
- The lnd-specific limit of 20 route hints per invoice (`{:error, :too_many_private_routes}`). BOLT11 places no limit on the number of `r` fields, so invoices with more than 20 route hints now decode successfully.

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


[0.2.0]: https://diff.hex.pm/diff/bitcoinex/0.1.8..0.2.0
[0.1.4]: https://diff.hex.pm/diff/bitcoinex/0.1.3..0.1.4
[0.1.3]: https://diff.hex.pm/diff/bitcoinex/0.1.2..0.1.3
[0.1.2]: https://diff.hex.pm/diff/bitcoinex/0.1.1..0.1.2
[0.1.1]: https://diff.hex.pm/diff/bitcoinex/0.1.0..0.1.1
[0.1.0]: https://preview.hex.pm/preview/bitcoinex/0.1.0