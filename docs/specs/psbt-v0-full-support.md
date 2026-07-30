# Full BIP-174 PSBT v0 Support — Spec

## 1. Context & Summary

`Bitcoinex.PSBT` (`lib/psbt.ex`) today supports **only a lossy subset** of BIP-174 (PSBT v0). It can decode a PSBT from base64/binary and re-serialize it, but:

- **Serialization is lossy.** `Global.serialize_global/1` carries a literal `# TODO: serialize all other fields in global` (psbt.ex:236) — it emits only `unsigned_tx` and `xpub`, silently dropping `version` and `proprietary`. `In.serialize_input/2` emits only 8 of the 11 parsed fields (drops `por_commitment`, `proprietary`, and never round-trips unknown keys). So `decode |> encode_b64` is **not** the identity for many real PSBTs.
- **Fields are missing.** BIP-174's hash-preimage input fields (`PSBT_IN_RIPEMD160` 0x0a … `PSBT_IN_HASH256` 0x0d) are neither parsed nor serialized. Unknown/proprietary key-value pairs are not preserved.
- **No roles are implemented.** There is no Creator (build a PSBT from an unsigned tx), no Updater API (add fields ergonomically), no Combiner (merge two PSBTs), no Finalizer (assemble `final_scriptsig`/`final_scriptwitness` from collected data), and no Extractor (produce the network `Transaction`). Callers must hand-mutate the nested structs.
- **A latent serialization bug.** `Transaction.Utils.serialize_compact_size_unsigned_int/1` (transaction.ex:177) has an unreachable final branch (`compact_size <= 0xFF`) where the uint64 case should be — any value `> 0xFFFFFFFF` raises `CondClauseError`. This affects tx and PSBT serialization alike.

Two prior stacked PRs (#44 "Refactor PSBT module & add new PSBT fields", #70 "Add psbt fields functionality") prototyped much of this against a Jan-2023 master. They are **design references only** — not to be reopened — because #70 drags in unrelated, unreviewed crypto (`taproot.ex`, Schnorr adaptor signatures, DLC scripts) and both target PSBT v2 (BIP-370) + taproot (BIP-371), which are explicitly out of scope here. Crucially, `lib/psbt.ex` on master is byte-identical to the base those PRs branched from, so their PSBT-only logic ports cleanly onto today's tree.

**Proposed change:** make `Bitcoinex.PSBT` a complete, lossless BIP-174 v0 implementation — full field coverage with round-trip fidelity, an atom-dispatched Updater API, and Creator / Combiner / Finalizer / Extractor role logic. Signing stays out (bitcoinex holds no signing responsibility); the Finalizer only *assembles* signatures the caller already placed.

## 2. Scope

**In scope**
- Lossless decode↔encode for all BIP-174 v0 global/input/output fields, including proprietary and unknown key-value pairs, with BIP-defined key ordering and duplicate-key rejection.
- Add the missing hash-preimage input fields (`ripemd160`, `sha256`, `hash160`, `hash256`) and complete the global/input/output serializers.
- Fix `serialize_compact_size_unsigned_int/1`.
- Updater API: a single atom-dispatched `add_field` per section, wrapped by `PSBT.add_global_field/3`, `PSBT.add_input_field/4`, `PSBT.add_output_field/4`.
- Creator: `PSBT.from_tx/1` (build an empty PSBT skeleton from an unsigned `Transaction`).
- Combiner: `PSBT.combine/2`.
- Finalizer: `PSBT.finalize/1` (+ per-input) for legacy + segwit-v0 script types: p2pkh, p2sh, p2wpkh, p2wsh, and (nested) p2sh-p2wpkh / p2sh-p2wsh, including bare/p2sh/p2wsh multisig.
- Extractor: `PSBT.extract_tx/1`.
- `PSBT.txid/1` — the txid of the global unsigned tx.
- Migrate all in-struct representations to `Bitcoinex` structs — pubkeys → `Secp256k1.Point.t()`, signatures → `Secp256k1.Signature.t()`, scripts → `Bitcoinex.Script.t()`, extended keys → `ExtendedKey.t()`, derivation paths → `ExtendedKey.DerivationPath.t()` — never encoded strings/byte-arrays (see §3.5).

**Out of scope** (and who owns it)
- **Signing** — callers produce signatures (via `Bitcoinex.Ecdsa`/their HSM) and place them with `add_input_field(.., :partial_sig, ..)`. The Finalizer never signs.
- **PSBT v2 / BIP-370** — no `tx_version`/`fallback_locktime`/`input_count`/`output_count`/`tx_modifiable` globals, no per-input `previous_txid`/`output_index`/`sequence`/locktime fields. Deferred to a future spec.
- **BIP-371 taproot fields** — no `tap_*` fields; the Finalizer does not handle p2tr inputs. Deferred.
- **Fee/sanity checks** beyond what BIP-174 mandates for a role (e.g. no independent fee-rate policy).

## 3. Design / Approach

### 3.1 Module layout

Keep the existing four-module structure in `lib/psbt.ex`: `Bitcoinex.PSBT` (top-level + roles), `Bitcoinex.PSBT.Utils`, `Bitcoinex.PSBT.Global`, `Bitcoinex.PSBT.In`, `Bitcoinex.PSBT.Out`. Roles (Creator/Combiner/Finalizer/Extractor) live as public functions on `Bitcoinex.PSBT`, delegating per-section work into the sub-modules. No new files.

### 3.2 Parsing — completeness, ordering, and duplicate keys

Current parse is a `parse_key_value/3` recursion that pattern-matches on the leading key byte. Extend the `parse/3` clause set in `In` to cover 0x09–0x0d, and ensure every parsed field has a matching `serialize_kv` clause (§3.3).

**Duplicate-key handling (invariant).** BIP-174: within a single map, a repeated key (full key, i.e. type byte + key-data) is invalid and parsing MUST fail. Today duplicates silently overwrite. Introduce, in `PSBT.Utils`, a duplicate-detecting wrapper:

- `parse_key_value/3` accumulates the set of raw keys seen for the current map; on a repeat it returns `{:error, :duplicate_key}` which propagates out of `decode/1` as `{:error, :duplicate_key}`.

For **repeatable** fields (`partial_sig`, `bip32_derivation`, global `xpub`, and the four hash-preimage fields) the *type byte* legitimately repeats — uniqueness is on the full key (type byte + pubkey/hash), so the check is on the full key and these are fine.

**Options considered — parse-error propagation.** (A) Keep the current bang-style (`{:ok, txn} = ...`) that crashes on malformed input. (B) Thread `{:error, reason}` through the recursion. **Decision: B.** BIP-174 defines several hard "MUST fail" conditions (duplicate key, unknown required-in-v0 layout, trailing bytes); `decode/1` already advertises `{:ok, t} | {:error, term}`, so surfacing them as `{:error, _}` matches the module contract and the repo's result-tuple convention.

### 3.3 Serialization — lossless, ordered

Rewrite the three serializers so that **every populated struct field is emitted**, in ascending key-type order, followed by proprietary then unknown pairs, terminated by the `0x00` map separator. Concretely:

- `Global.serialize_global/1`: `unsigned_tx` (0x00) → `xpub` (0x01, repeatable) → `version` (0xFB) → `proprietary` (0xFC, repeatable) → unknown → `0x00`.
- `In.serialize_input/1`: 0x00 `non_witness_utxo` → 0x01 `witness_utxo` → 0x02 `partial_sig` (repeatable) → 0x03 `sighash_type` → 0x04 `redeem_script` → 0x05 `witness_script` → 0x06 `bip32_derivation` (repeatable) → 0x07 `final_scriptsig` → 0x08 `final_scriptwitness` → 0x09 `por_commitment` → 0x0a–0x0d hash preimages (repeatable) → 0xFC `proprietary` → unknown → `0x00`.
- `Out.serialize_output/1`: 0x00 `redeem_script` → 0x01 `witness_script` → 0x02 `bip32_derivation` (repeatable) → 0xFC `proprietary` → unknown → `0x00`.

**Invariant (round-trip):** for any valid v0 PSBT `p`, `decode(encode_b64(p)) == {:ok, p}`, and `encode_b64(decode(b64)) == {:ok, b64}` for any canonically-serialized input. Enforced by the BIP-174 official-vector tests (§8).

A shared `PSBT.Utils.serialize_repeatable/2` helper (referenced by PR #70's `serialize_repeatable_fields`) collapses the `for … |> :erlang.list_to_binary()` boilerplate repeated across sections.

### 3.4 Unknown & proprietary key-value pairs

Add an `:unknown` field (list of `%{key: binary, value: binary}`) and normalize `:proprietary` to a list of `%{key: binary, value: binary}` on every section struct. Any key byte with no known parser is collected into `:unknown` verbatim (full key incl. type byte) so it survives round-trips, as BIP-174 requires. Proprietary keys (0xFC) are collected into `:proprietary`.

### 3.5 In-struct representation: typed structs everywhere

Today parsed values are stored inconsistently — pubkeys/scripts/sigs as lowercase hex strings, xpubs as Base58 strings, derivation paths as raw `[integer]`, `witness_utxo` as a `Transaction.Out`.

**Options considered.** (A) Keep everything as hex/Base58 strings and int lists (status quo; minimal churn). (B) Store typed domain objects throughout, using bitcoinex's own structs. **Decision: B** — this is a hard requirement, not a preference: PSBTs are represented with `Bitcoinex` structs, never encoded strings/byte-arrays, matching PR #44's aim. The Finalizer must *interpret* redeem/witness scripts and match pubkeys to sigs; consumers want `ExtendedKey`/`DerivationPath` objects, not Base58 blobs. This is a **breaking change to the decode output shape** — accepted (see §10, resolved). Concrete mapping:

| Field | Old rep | New rep |
|---|---|---|
| `partial_sig.public_key` | hex string | `Secp256k1.Point.t()` |
| `partial_sig.signature` | hex string | `Secp256k1.Signature.t()` (via `Secp256k1.Signature.der_parse_signature/1`; sighash byte stored alongside — see note) |
| `redeem_script`, `witness_script`, `final_scriptsig` | hex string | `Bitcoinex.Script.t()` |
| `witness_utxo` | `Transaction.Out` | `Transaction.Out` (unchanged) |
| `final_scriptwitness` | `Transaction.Witness` | `Transaction.Witness` (unchanged) |
| `bip32_derivation` item | `%{public_key: hex, pfp: int, derivation: [int]}` | `%{public_key: Point.t(), origin: KeyOrigin.t()}` |
| global `xpub` item | `%{xpub: Base58, master_pfp: int, derivation: [int]}` | `%{xkey: ExtendedKey.t(), origin: KeyOrigin.t()}` |
| hash preimages (0x0a–0x0d) | — | `%{hash: binary(), preimage: binary()}` |

`Script` already exposes `get_script_type/1`, `is_p2wpkh?/1`, `extract_multi_policy/1`, `parse_script/1`, `to_hex/1`; `Point` exposes `parse_public_key/1`, `sec/1`, `x_bytes/1`.

**Signature note (required):** signatures in PSBTs are represented as `Secp256k1.Signature.t()` structs — never hex/DER strings. A PSBT `partial_sig` value is DER-encoded ECDSA **plus a trailing 1-byte sighash flag**, so store `%{public_key: Point.t(), signature: Signature.t(), sighash: 0..0xFF}`; parse via `Signature.der_parse_signature/1` on the leading bytes, serialize via `Signature.serialize_signature/1 <> <<sighash>>`. BIP-174 mandates canonical low-S DER, so this re-serialization is byte-identical for well-formed sigs; the round-trip vector tests (§8) assert it. (`final_scriptsig`/`final_scriptwitness` remain `Script`/`Witness` and carry their raw pushed sig bytes as-is — only the interpreted `partial_sig` uses `Signature`.)

**Ergonomic `add_field`:** clauses accept *either* a struct or its raw binary/hex (PR #70 pattern: `add_field(input, :redeem_script, <<..>>)` and `add_field(input, :redeem_script, %Script{})` both work), normalizing to the struct rep internally.

### 3.5.1 Key origin: `ExtendedKey` / `DerivationPath`

Introduce a small shared struct `Bitcoinex.PSBT.KeyOrigin` — `defstruct [:fingerprint, :derivation]` where `fingerprint :: <<_::32>>` (raw 4-byte master key fingerprint) and `derivation :: ExtendedKey.DerivationPath.t()`. Used by both `xpub` (global) and `bip32_derivation` (input/output), since both encode `<4-byte fingerprint><32-bit LE child index>*`.

- **Path mapping:** each little-endian uint32 in the PSBT value maps directly to a `DerivationPath.child_nums` integer (the hardened bit is already set in the raw value), so parse = `for <<i::little-32 <- rest>>, do: i` into `%DerivationPath{child_nums: ...}`, and serialize = the inverse. `DerivationPath.to_string/1` gives callers the `m/84'/0'/0'` view for free.
- **Xpub key-data ↔ `ExtendedKey`:** the PSBT `PSBT_GLOBAL_XPUB` key-data is the **raw 78-byte** BIP32 extended key (no Base58 checksum), whereas `ExtendedKey.parse_extended_key/1` expects the 82-byte checksummed form and `serialize_extended_key/1` appends a checksum. Bridge explicitly: **parse** with `parse_extended_key(Base58.append_checksum(raw78))`; **serialize** with `binary_part(serialize_extended_key(xkey), 0, 78)`. Wrap these two directions in `PSBT.Utils.parse_xpub_keydata/1` and `serialize_xpub_keydata/1` so the conversion lives in one place.

### 3.6 Creator — `from_tx/1`

`from_tx(tx)` builds a skeleton PSBT from an **unsigned** `Transaction.t()`: `global.unsigned_tx = tx` (with all input `script_sig`s empty and no witnesses — validated), one empty `%In{}` per `tx.inputs`, one empty `%Out{}` per `tx.outputs`. Returns `{:error, :tx_not_unsigned}` if any input carries a non-empty `script_sig` or the tx carries witnesses.

### 3.7 Combiner — `combine/2`

`combine(psbt_a, psbt_b)` per BIP-174 Combiner rules:

1. **Precondition:** both `global.unsigned_tx` must be equal (same txid *and* identical serialization). Else `{:error, :mismatched_tx}`.
2. Result has the same length input/output lists; combine positionally.
3. For each map (global, each input, each output): **union** of fields.
   - Singleton fields (`sighash_type`, `redeem_script`, `witness_script`, `witness_utxo`, `non_witness_utxo`, `final_scriptsig`, `final_scriptwitness`, `version`, `por_commitment`): if only one side has it, take it; if both have it and they are equal, keep it; if both have it and they differ → `{:error, :conflicting_field}`.
   - Repeatable fields (`partial_sig`, `bip32_derivation`, `xpub`, hash preimages, `proprietary`, `unknown`): union keyed by the full key (pubkey / hash / raw key). On a key collision with differing values → `{:error, :conflicting_field}`.

**Invariant:** `combine` is commutative and idempotent for non-conflicting inputs — `combine(a,b) == combine(b,a)` and `combine(a,a) == a`.

### 3.8 Finalizer — `finalize/1`

`finalize(psbt)` walks each input and, for inputs not yet finalized, attempts to build `final_scriptsig` and/or `final_scriptwitness` from the collected `partial_sig`/`redeem_script`/`witness_script`/`sighash_type`, then strips all fields except `non_witness_utxo`, `witness_utxo`, `final_scriptsig`, `final_scriptwitness`, `unknown`, `proprietary` (BIP-174).

Script-type dispatch uses the input's scriptPubKey (from `witness_utxo.script_pub_key` or `non_witness_utxo` at the referenced vout) run through `Script.get_script_type/1`, plus `redeem_script`/`witness_script` when present:

| Input type | scriptSig | witness |
|---|---|---|
| p2pkh | `<sig> <pubkey>` | — |
| p2sh (bare multisig) | `OP_0 <sig>… <redeemScript>` | — |
| p2wpkh | empty | `<sig> <pubkey>` |
| p2wsh multisig | empty | `OP_0 <sig>… <witnessScript>` |
| p2sh-p2wpkh | `<redeemScript>` (push of the p2wpkh program) | `<sig> <pubkey>` |
| p2sh-p2wsh | `<redeemScript>` | `OP_0 <sig>… <witnessScript>` |

For multisig, order sigs by the pubkey order in the redeem/witness script (BIP-174 / BIP-147 `OP_0` dummy prepended). If an input lacks enough material to finalize, it is left untouched (not an error); `finalize/1` returns the partially-finalized PSBT. A `finalized?/1` predicate reports whether every input now has `final_scriptsig`/`final_scriptwitness`.

**`non_witness_utxo` mismatch (OQ1, resolved):** match Bitcoin Core — if a `non_witness_utxo` is present but its computed txid ≠ the input's `prev_txid`, the input is **skipped** (left unfinalized), not hard-errored, so a best-effort finalize over a mixed PSBT still makes progress on valid inputs. `finalized?/1` will then report false for that input.

**Options considered — partial finalize.** (A) All-or-nothing: error if any input can't finalize. (B) Best-effort per input. **Decision: B**, matching Bitcoin Core's finalizer, so a PSBT can round-trip through multiple finalizers.

### 3.9 Extractor — `extract_tx/1`

`extract_tx(psbt)` requires every input finalized (`finalized?/1` true) else `{:error, :not_finalized}`. It copies `global.unsigned_tx`, sets each input's `script_sig` from `final_scriptsig` (hex ""), and, if any input has a `final_scriptwitness`, attaches a `witnesses` list (empty `Witness` for non-witness inputs). Returns `{:ok, Transaction.t()}`.

### 3.10 `txid/1`

`txid(psbt)` = `Transaction.transaction_id(psbt.global.unsigned_tx)`. Thin wrapper; `transaction_id/1` (transaction.ex:34) already serializes witness-stripped and returns the reversed lowercase-hex txid. Returns `{:error, :no_unsigned_tx}` if `global.unsigned_tx` is nil.

**Options considered — cache txid as a struct field vs. compute on demand.** (A) Add `:txid` to `%PSBT{}`, populated at `decode`/`from_tx`. (B) Pure `txid/1` function, no field. **Decision: B.** (1) It's derived data with no enforceable invariant — `%PSBT{}` is an open map, so any `%{psbt | global: ..}` or hand-built struct would carry a stale `:txid` with nothing to catch it. (2) Recompute is one witness-stripped serialize + double-SHA256 off any hot path. (3) A denormalized field would break the struct-equality the Combiner invariants rely on (`combine(a,b) == combine(b,a)`, §3.7/§8). (4) In the deferred v2 (BIP-370) there is no `unsigned_tx` and the txid is rebuilt from fields that change mid-workflow, so a cache would be actively wrong. Callers that index many PSBTs cache the `txid/1` result themselves.

### 3.11 compact-size fix

`serialize_compact_size_unsigned_int/1`: replace the final `compact_size <= 0xFF` branch with `compact_size <= 0xFFFFFFFFFFFFFFFF -> <<0xFF>> <> <<compact_size::little-size(64)>>`.

### 3.12 Endianness & byte-order compliance (BIP-174 audit)

Every scalar in a PSBT is either a **little-endian integer** or a **raw byte string that must not be reordered**. Getting this wrong silently corrupts data on round-trip. The complete field-by-field mapping the implementation MUST honor:

| Wire field | Encoding | Struct rep & handling |
|---|---|---|
| Magic `0x70736274` + `0xFF` sep | fixed byte sequence | `<<0x70736274::big-size(32)>>` (emits `70 73 62 74`) |
| Map key type byte / separator `0x00` | single byte | as-is |
| CompactSize (key/val lengths, counts) | **little-endian** multibyte | `serialize_compact_size_unsigned_int/1` (§3.11) |
| `unsigned_tx` internals (version, vout, sequence, locktime, output value) | **little-endian** | delegated to `Transaction` (already LE) |
| `prev_txid` (inside unsigned tx) | wire = internal order; **display hex = byte-reversed** | `Transaction.In` reverses symmetrically on parse/serialize — do not touch |
| `txid/1` result | reversed vs. the raw hash | `transaction_id/1` reverses; correct as-is |
| **Master fingerprint** (xpub 0x01, bip32 0x06/0x02) | **raw 4 bytes — NOT reversed, NOT an integer** | `KeyOrigin.fingerprint :: <<_::32>>`; parse `<<fp::binary-size(4), rest::binary>>`. **Never `little-32`.** |
| BIP32 derivation-path indexes (after fingerprint) | **32-bit little-endian** uint, each | `for <<i::little-32 <- rest>>, do: i` → `DerivationPath.child_nums`; serialize inverse |
| Xpub key-data (78 bytes) | BIP32 serialization (its internal `child_num` is **big-endian**, per BIP32 — distinct from the path indexes above) | delegated to `ExtendedKey` (keeps raw bytes); bridge via `parse_xpub_keydata/1` (§3.5.1) |
| `sighash_type` (in 0x03) | **32-bit little-endian** uint | store `integer`; parse/serialize `<<n::little-size(32)>>`; validate against `@valid_sighash_flags` |
| `version` (global 0xFB) | **32-bit little-endian** uint | store `integer`; parse/serialize `<<n::little-size(32)>>` |
| `witness_utxo` amount | **64-bit little-endian** | `Transaction.Out` (`little-64`) |
| `partial_sig` value | DER sig + 1 trailing **sighash byte** | `Signature.t()` + `sighash :: 0..0xFF` (§3.5); the trailing byte has no endianness |
| pubkeys (SEC), scripts, hash preimages (0x0a–0x0d) keys/vals, `por_commitment`, `redeem`/`witness_script`, `final_script*` | raw byte strings | stored as `Point`/`Script`/`binary` verbatim — no reordering |

**Two traps called out explicitly:**
1. **Fingerprint ≠ little-endian integer.** The current code (psbt.ex:176, 228, 350) treats the master fingerprint as `little-unsigned-32`. It round-trips only because it's never interpreted; compared against `ExtendedKey.get_fingerprint/1` (raw 4 bytes) it would be byte-reversed. The `KeyOrigin` migration MUST read/write it as an opaque `binary-size(4)`.
2. **Path-index LE vs. xpub-internal child_num BE.** The derivation-*path* indexes in the PSBT value are little-endian; the child_num *inside* the 78-byte xpub is big-endian (BIP32). These live in different parsers (`parse_key_origin` vs. `ExtendedKey`) and must not be conflated.

**Invariant:** exercised by the round-trip vector suite (§8) — any incorrect reversal makes `decode |> encode_b64` diverge from the source bytes on the affected vector.

## 4. Code Changes

All in `lib/psbt.ex` and `lib/transaction.ex` (plus the small new `KeyOrigin` module, colocated in `lib/psbt.ex`).

### 4.0 `Bitcoinex.PSBT.KeyOrigin` (new, in `lib/psbt.ex`)
- `defstruct [:fingerprint, :derivation]` — `fingerprint :: <<_::32>>`, `derivation :: ExtendedKey.DerivationPath.t()` (§3.5.1).
- `@type t :: %__MODULE__{fingerprint: binary(), derivation: DerivationPath.t()}`.

### 4.1 `lib/transaction.ex`
- `Transaction.Utils.serialize_compact_size_unsigned_int/1` — fix uint64 branch (§3.11).

### 4.2 `Bitcoinex.PSBT` (top-level roles)
- `@spec from_tx(Transaction.t()) :: {:ok, t()} | {:error, atom()}` — Creator (§3.6).
- `@spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}` — Combiner (§3.7).
- `@spec finalize(t()) :: t()` — Finalizer (§3.8).
- `@spec finalized?(t()) :: boolean()`.
- `@spec extract_tx(t()) :: {:ok, Transaction.t()} | {:error, atom()}` — Extractor (§3.9).
- `@spec txid(t()) :: {:ok, String.t()} | {:error, :no_unsigned_tx}` (§3.10).
- `@spec add_global_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}`.
- `@spec add_input_field(t(), non_neg_integer(), atom(), any()) :: {:ok, t()} | {:error, atom()}`.
- `@spec add_output_field(t(), non_neg_integer(), atom(), any()) :: {:ok, t()} | {:error, atom()}`.
- `serialize/1` → change from `defp` to `def` (Extractor/tests need it) or keep private and expose only via `encode_b64`. **Decision: keep private**; expose nothing new.

### 4.3 `Bitcoinex.PSBT.Utils`
- `parse_key_value/3` — add duplicate-key detection, return `{:error, :duplicate_key}` (§3.2).
- `serialize_repeatable/2` — `(field_values :: list | nil, (item -> binary)) :: binary` helper (§3.3).
- `parse_xpub_keydata/1 :: (binary() -> {:ok, ExtendedKey.t()} | {:error, term})` and `serialize_xpub_keydata/1 :: (ExtendedKey.t() -> binary())` — raw-78 ↔ checksummed bridge (§3.5.1).
- `parse_key_origin/1 :: (binary() -> KeyOrigin.t())` and `serialize_key_origin/1 :: (KeyOrigin.t() -> binary())` — `<4-byte fp><LE-u32 path>` ↔ `KeyOrigin.t()` (§3.5.1); shared by xpub + bip32_derivation.
- Keep `parse_compact_size_value/1`, `serialize_kv/2`.

### 4.4 `Bitcoinex.PSBT.Global`
- `defstruct` add `:proprietary` (list) and `:unknown` (list); keep `:unsigned_tx`, `:xpub`, `:version`. `xpub` items become `%{xkey: ExtendedKey.t(), origin: KeyOrigin.t()}` (§3.5). `version` stored as `integer`, wire encoding `<<n::little-size(32)>>` (§3.12).
- `add_field/3` clauses: `:unsigned_tx`, `:xpub`, `:version`, `:proprietary`, `:unknown` (atom-dispatch; §3.5 ergonomic overloads).
- `parse/3` — unchanged field set (drop the v2 clauses that PR #44 added); add `:unknown` catch-all.
- `serialize_global/1` — full ordered emit (§3.3).

### 4.5 `Bitcoinex.PSBT.In`
- `defstruct` add `:ripemd160, :sha256, :hash160, :hash256, :unknown`; normalize `:proprietary` to list. Fields become typed (§3.5): `partial_sig` → `%{public_key: Point.t(), signature: Signature.t(), sighash: 0..0xFF}`, `redeem_script`/`witness_script`/`final_scriptsig` → `Script.t()`, `bip32_derivation` item → `%{public_key: Point.t(), origin: KeyOrigin.t()}`.
- `@valid_sighash_flags` constant (0x01,0x02,0x03,0x81,0x82,0x83); `sighash_type` stored as `integer`, wire encoding `<<n::little-size(32)>>` (§3.12), not the current raw-binary pass-through.
- `add_field/3` clauses for every field (atom-dispatch), each with a guard validating type/shape (mirror PR #70 psbt.ex:602–759 but v0-only).
- `parse/3` — add clauses 0x09 `por_commitment`, 0x0a `ripemd160`, 0x0b `sha256`, 0x0c `hash160`, 0x0d `hash256` (each `%{hash: binary, preimage: binary}`), 0xFC `proprietary` (append to list), `:unknown` catch-all. Remove any v2/taproot clauses.
- `serialize_input/1` — full ordered emit (§3.3).

### 4.6 `Bitcoinex.PSBT.Out`
- `defstruct` add `:proprietary` (list), `:unknown` (list).
- `add_field/3` clauses: `:redeem_script`, `:witness_script`, `:bip32_derivation`, `:proprietary`, `:unknown`.
- `parse/3` — add 0xFC proprietary + unknown catch-all; typed reps (§3.5).
- `serialize_output/1` — full ordered emit; drop the special-case empty-output branch (redundant once all fields emit uniformly).

### 4.7 Constants / errors
Error atoms (all reasons are atoms, per §3.2 Decision B): `:duplicate_key`, `:mismatched_tx`, `:conflicting_field`, `:tx_not_unsigned`, `:not_finalized`, `:no_unsigned_tx`, `:invalid_field`, `:index_out_of_range`, `:unfinalizable_input`.

## 5. DB Schema Changes
None — bitcoinex is a stateless library.

## 6. Security Concerns
- **Malicious PSBT parsing.** Parsers must not crash the caller (Decision B replaces bang-matches with `{:error, _}`) and must bound work: reject duplicate keys, reject trailing bytes, and rely on `parse_compact_size_value/1` reading exactly the declared length (already the case). No unbounded recursion beyond input/output counts, which are bounded by the unsigned tx.
- **`non_witness_utxo` ↔ input mismatch.** The Finalizer/Extractor must confirm a supplied `non_witness_utxo`'s txid matches the input's `prev_txid` before trusting its scriptPubKey — otherwise a lying utxo could steer finalization. Enforced in §3.8 dispatch. This is validation only; no signing trust is placed.
- **No secrets.** PSBTs carry public keys, sigs, and scripts only; no private keys pass through this module.

## 7. Metrics / Alerting
None — library code, no runtime process.

## 8. Testing

Tests in `test/psbt_test.exs` (extend existing) and `test/transaction_test.exs`.

**Vector sources (vendor these):**
1. **BIP-174 official test vectors** — the Invalid / Creator / Combiner / Finalizer / Extractor blocks from the BIP-174 mediawiki. These are the primary conformance suite and map 1:1 onto our roles. Vendor as a fixture (e.g. `test/data/bip174_vectors.json` or inline module attrs, matching the repo's existing fixture style).
2. **Bitcoin Core `rpc_psbt.json`** (`src/test/data/rpc_psbt.json`) — Core's `valid`/`invalid`/`creator`/`combiner`/`finalizer`/`extractor` arrays are directly transposable (base64 PSBTs + expected results) and cover far more script-type and edge-case combinations than BIP-174 alone. Vendor the v0-relevant entries; **skip** any entry exercising PSBT v2 or taproot fields (out of scope) and note the skip count in the test module so the exclusion is visible, not silent.
3. The extra vectors already vendored in PR #44's `test/psbt_test.exs` (BIP-174 fill-ins), minus its BIP-370/371 additions.

**To add — round-trip & parsing (§3.2–3.5)**
- `decode/1` succeeds on every BIP-174 valid v0 vector.
- `decode/1` returns `{:error, :duplicate_key}` for each BIP-174 "invalid: duplicate key" vector (global, input, output).
- `decode/1` returns `{:error, _}` on trailing-bytes and truncated inputs.
- Round-trip identity `decode |> encode_b64` for every valid vector (this is the lossless guarantee; currently fails for version/proprietary/por_commitment/hash-preimage-bearing PSBTs).
- Each new input field parses & re-serializes: `por_commitment`, `ripemd160`, `sha256`, `hash160`, `hash256`.
- `:unknown` and `:proprietary` pairs survive round-trip (global, input, output).
- Typed-representation assertions: `partial_sig.public_key` is a `%Point{}`, `redeem_script` is a `%Script{}`.

**To add — endianness (§3.12)**
- Master fingerprint survives round-trip as the exact 4 wire bytes, and a parsed `bip32_derivation`/`xpub` `KeyOrigin.fingerprint` equals `ExtendedKey.get_fingerprint/1` of the matching key (guards against the LE-int regression).
- A hardened derivation index (e.g. `84'` = `0x80000054`) parses to `DerivationPath.child_nums` `[0x80000054, ..]` and `to_string/1` renders `84'`, proving path indexes are read little-endian.
- `sighash_type` value `0x01` round-trips as wire bytes `01 00 00 00` (LE-32), not `00 00 00 01`.
- global `version` `0x02` round-trips as `02 00 00 00`.
- An xpub with a nonzero internal `child_num` round-trips (guards path-LE vs. xpub-child_num-BE conflation).

**To add — compact size (§3.11)**
- `serialize_compact_size_unsigned_int/1` for boundaries: 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000 (previously raised), 0xFFFF_FFFF_FFFF_FFFF.
- Round-trip against `get_counter/1` for each boundary.

**To add — Updater (§3.5)**
- `add_global_field` for `:version`, `:xpub`, `:proprietary`; `:unknown`.
- `add_input_field` happy path for each field atom; struct-or-binary overload for `:redeem_script`, `:witness_script`, `:final_scriptsig`.
- `add_input_field` guard rejections: bad `:sighash_type` (0x04) → `{:error, :invalid_field}`; out-of-range index → `{:error, :index_out_of_range}`.
- `add_output_field` for `:redeem_script`, `:witness_script`, `:bip32_derivation`.

**To add — Creator (§3.6)**
- `from_tx/1` produces N empty inputs / M empty outputs matching a decoded unsigned tx.
- `from_tx/1` rejects a tx with a non-empty `script_sig` → `{:error, :tx_not_unsigned}`.

**To add — Combiner (§3.7)**
- BIP-174 Combiner vector: `combine/2` of the two partially-signed PSBTs equals the expected combined vector.
- `combine/2` mismatched `unsigned_tx` → `{:error, :mismatched_tx}`.
- Union of `partial_sig` from two single-sig-each PSBTs (multisig case).
- Conflicting singleton (`sighash_type` differs) → `{:error, :conflicting_field}`.
- Commutativity: `combine(a,b) == combine(b,a)`; idempotence: `combine(a,a) == {:ok, a}`.

**To add — Finalizer (§3.8)**, one per script type:
- p2pkh, p2wpkh, p2sh-p2wpkh, bare-multisig-in-p2sh, p2wsh-multisig, p2sh-p2wsh-multisig — each finalizes to the BIP-174 (or Core-produced) expected `final_scriptsig`/`final_scriptwitness`.
- Multisig sig ordering follows script pubkey order regardless of `partial_sig` insertion order.
- Finalized input strips non-final fields (assert `partial_sig`/`bip32_derivation`/`redeem_script` are nil afterward, `non_witness_utxo`/`witness_utxo` retained).
- Insufficient sigs → input left untouched, `finalized?/1` false.
- `non_witness_utxo` txid mismatch → `{:error, :unfinalizable_input}` (or input skipped — pick per §3.8; test asserts chosen behavior).

**To add — Extractor (§3.9)**
- BIP-174 Extractor vector: `extract_tx/1` of the finalized PSBT equals the expected network tx hex.
- `extract_tx/1` on a non-finalized PSBT → `{:error, :not_finalized}`.
- Mixed witness/non-witness inputs produce a correctly-structured `witnesses` list.

**To add — txid (§3.10)**
- `txid/1` on a known PSBT equals the txid of its decoded unsigned tx.
- `txid/1` with nil `unsigned_tx` → `{:error, :no_unsigned_tx}`.

**To update**
- Existing `test/psbt_test.exs` assertions that read `partial_sig`/`bip32_derivation`/`redeem_script` as hex strings must change to `%Point{}`/`%Script{}` (§3.5). Enumerate at implementation time; the file has ~8 decode/encode assertions today.
- Any existing round-trip test that currently passes *because* it uses a PSBT with no version/proprietary field is now subsumed by the exhaustive vector round-trip.

## 9. PR Breakdown

Prefix `P` (PSBT). Dependency graph:

```
P1 (round-trip + compact-size fix) ──► P2 (structs + Updater + Creator + txid) ──┬─► P3 (Combiner)
                                                                                  └─► P4 (Finalizer + Extractor)
```

### P1 — Lossless round-trip & compact-size fix
Pure correctness, **no public API change**. Fix `serialize_compact_size_unsigned_int/1`; complete all three serializers to emit every stored field in order; add input fields 0x09–0x0d; add `:unknown`/`:proprietary` capture; add duplicate-key rejection; thread `{:error,_}` through parse.
- **Files:** `lib/transaction.ex`, `lib/psbt.ex`.
- **Tests:** round-trip & parsing group, compact-size group (§8).
- **Blocks:** P2. **Depends on:** nothing.

### P2 — Typed structs, Updater API, Creator, txid
Migrate reps to `Point`/`Signature`/`Script`/`ExtendedKey`/`DerivationPath` + new `KeyOrigin` (§3.5, §3.5.1); add `add_field/3` per section + `add_global_field/3`/`add_input_field/4`/`add_output_field/4`; add `from_tx/1`; add `txid/1`.
- **Files:** `lib/psbt.ex`.
- **Tests:** Updater, Creator, txid groups; update existing hex-string assertions (§8 "To update").
- **Blocks:** P3, P4. **Depends on:** P1. **Coupling:** the struct migration touches the same parse/serialize clauses as P1 — land P1 first to avoid rework.

### P3 — Combiner
`combine/2` (§3.7).
- **Files:** `lib/psbt.ex`. **Tests:** Combiner group. **Depends on:** P2 (typed reps for keyed union).

### P4 — Finalizer & Extractor
`finalize/1`, `finalized?/1`, `extract_tx/1` (§3.8–3.9).
- **Files:** `lib/psbt.ex`. **Tests:** Finalizer + Extractor groups. **Depends on:** P2. Independent of P3 (can land in either order).

Each PR: update `CHANGELOG.md`; P2 notes the breaking decode-shape change. Bump `version` in `mix.exs` at the end of the stack (or per-PR if released incrementally).

## 10. Open Questions
_All resolved._
- **OQ1 — `non_witness_utxo` mismatch in Finalizer:** resolved — skip the input (Bitcoin Core behavior), see §3.8.
- **OQ2 — P2 breaking change:** resolved — the `ExtendedKey`/`DerivationPath`/`Point`/`Script`/`Signature` decode-shape change is accepted for this 0.x line; no legacy hex-string mode retained. Called out in `CHANGELOG.md` under P2.
