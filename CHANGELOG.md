# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `PSBT.finalize/1` and `PSBT.finalized?/1` (Input Finalizer): assembles `final_scriptsig`/`final_scriptwitness` from the collected signatures and scripts for p2pkh, p2wpkh, (nested) p2sh-p2wpkh, bare/p2sh/p2wsh multisig, and p2sh-p2wsh inputs, ordering multisig signatures by the script's pubkey order. Best-effort per input (matching Bitcoin Core): inputs it cannot finalize — including any whose signatures do not match a specified `sighash_type`, whose `redeem_script`/`witness_script` does not hash to the scriptPubKey/witness program, or whose single-key signature's pubkey does not hash to the p2pkh/p2wpkh hash (the BIP-174 Signer script/key-hash checks) — are left untouched.
- `PSBT.extract_tx/1` (Transaction Extractor): produces the fully-signed network `Transaction` from a finalized PSBT, or `{:error, :not_finalized}`.
- `PSBT.combine/2` (Combiner): merges two PSBTs describing the same unsigned transaction, unioning repeatable fields by key and requiring singleton fields to agree. Returns `{:error, :mismatched_tx}` for different transactions, `{:error, :conflicting_field}` on conflicting values, and `{:error, :map_count_mismatch}` rather than silently truncating mismatched input/output map lists. Repeatable records are ordered canonically so the operation is commutative and idempotent.
- `PSBT.from_tx/1` (Creator), `PSBT.txid/1`, and the Updater API — `PSBT.add_global_field/3`, `PSBT.add_input_field/4`, `PSBT.add_output_field/4` (each dispatching on a field-name atom via `PSBT.Global.add_field/3`, `PSBT.In.add_field/3`, `PSBT.Out.add_field/3`). Adding a hash-preimage field (`:ripemd160`/`:sha256`/`:hash160`/`:hash256`) validates that the hash is the digest of the preimage (`{:error, :invalid_hash_preimage}` otherwise). `add_global_field(:unsigned_tx, ..)` validates the tx is unsigned and refuses to replace an existing one or desync the input/output map counts (`:unsigned_tx_already_set` / `:tx_io_count_mismatch`). `add_input_field(:witness_utxo/:final_scriptwitness, ..)` normalizes hex to lowercase and rejects non-hex, so the Updater never stores a value that would raise at encode time.
### Changed
- **Breaking:** decoded PSBT fields are now typed `Bitcoinex` structs rather than hex/Base58 strings or integer lists: pubkeys are `Secp256k1.Point.t()`, signatures `Secp256k1.Signature.t()`, scripts (`redeem_script`/`witness_script`/`final_scriptsig`) `Script.t()`, extended keys `ExtendedKey.t()`, and BIP-32 key origins a new `PSBT.KeyOrigin` struct (`fingerprint` as raw 4 bytes, `derivation` as `ExtendedKey.DerivationPath.t()`). `sighash_type` and global `version` are now integers. `partial_sig` is now a list (BIP-174 allows multiple signatures per input), each record `%{public_key: Point.t(), signature: Signature.t(), sighash_flag: flag}` (the trailing 1-byte SIGHASH flag is `sighash_flag`, distinct from the input-level `sighash_type` field). Public keys in `partial_sig`/`bip32_derivation` must be 33-byte compressed SEC keys (the `Point` representation re-serializes compressed); legacy uncompressed 65-byte keys are rejected rather than silently re-encoded. Decoding rejects a `sighash_type` field or a `partial_sig` sighash flag outside the valid ECDSA set (`0x01`/`0x02`/`0x03` optionally `| 0x80`), a hash-preimage record whose key hash is not the digest of its value (`:invalid_hash_preimage`), and any PSBT whose global version is not 0 (`:unsupported_version`) — only BIP-174 v0 is supported.
### Fixed
- `Transaction.Utils.serialize_compact_size_unsigned_int/1` now encodes values above `0xFFFFFFFF` as a `0xFF`-prefixed little-endian uint64. The final `cond` branch previously read `compact_size <= 0xFF` (unreachable), so any such value raised `CondClauseError`.
- PSBT (de)serialization is now lossless for all BIP-174 v0 fields. `PSBT.encode_b64/1` previously dropped the global `version`, per-input `por_commitment`, and any proprietary records (`Global.serialize_global/1` carried a `TODO: serialize all other fields`), so `decode |> encode_b64` was not the identity for many PSBTs.
### Added
- PSBT parsing now covers the BIP-174 v0 input hash-preimage fields (`ripemd160`, `sha256`, `hash160`, `hash256`) and preserves unrecognized proprietary (`:proprietary`) and unknown (`:unknown`) key-value records on every map, so they round-trip.
- PSBT decoding now rejects malformed inputs per BIP-174: duplicate keys (`{:error, :duplicate_key}`), a known key type carrying wrong-length key data (`:invalid_key_format`), a missing global unsigned tx (`:missing_unsigned_tx`), an unsigned tx with a non-empty scriptSig (`:unsigned_tx_has_script_sig`) or witness serialization (`:unsigned_tx_has_witness_serialization`), trailing bytes after the final output map (`:trailing_bytes`), and truncated/oversized data — instead of crashing or silently accepting.
- `Transaction.Out.output/1` and `Transaction.Witness.witness/1` now reject trailing bytes instead of silently dropping them. These parse a single PSBT record value (`PSBT_IN_WITNESS_UTXO` / `PSBT_IN_FINAL_SCRIPTWITNESS`), so an over-long value (stated length exceeding the actual output/witness) is now rejected rather than decoding and re-encoding to different bytes — restoring the `decode |> encode_b64` round-trip guarantee.
- `Transaction.decode/1` now parses a 0-input transaction (whose `00 01` prefix collides with the segwit marker+flag) by falling back to legacy parsing when the segwit interpretation does not parse cleanly. PSBTs whose unsigned tx has 0 inputs (e.g. Bitcoin Core's `rpc_psbt.json` `valid[5]`) now decode and round-trip.

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