# SLIP-39 & BIP-39 Mnemonic Primitives — Spec

## 1. Context & Summary

Bitcoinex implements BIP-32 (`Bitcoinex.ExtendedKey`) but has **no mnemonic layer**: there is no way to go from a human-transcribable word list to a BIP-32 seed, and no Shamir-based backup scheme. A grep across `lib/` for `bip39|mnemonic|pbkdf2|wordlist|shamir|gf256|rs1024|lagrange` returns zero matches; there is no `priv/` directory and no bundled word lists. The only adjacent prior art is `Bitcoinex.Bech32` (whose `bech32_polymod/1` and `convert_bits/4` are structurally identical to SLIP-39's RS1024 checksum and 10-bit packing) and `Bitcoinex.Secp256k1.Math` (prime-field arithmetic — **not** GF(256)).

[SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) ("Shamir's Secret-Sharing for Mnemonic Codes") encodes a master secret into a set of mnemonic word lists using a two-level (group → member) Shamir Secret Sharing scheme over GF(256), with a passphrase-based Feistel encryption layer and an RS1024 error-detection checksum. [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) is the simpler, ubiquitous scheme: entropy → checksummed word list → 512-bit seed via PBKDF2-HMAC-SHA512.

This spec adds both, sharing primitives where they overlap (PBKDF2, bit↔word packing) and feeding the existing `ExtendedKey.seed_to_master_private_key/2` for the "mnemonic → xprv" story. The proposed change: a `Bitcoinex.BIP39` module, a `Bitcoinex.SLIP39` module family (`GF256`, `Shamir`, `Cipher`, `Encoding`, `Share`, plus the top-level orchestrator), a new `Utils.pbkdf2/5` helper, and two bundled word lists under `priv/`.

### Acronyms

| Term | Meaning |
|------|---------|
| MS | Master Secret (the entropy being protected) |
| EMS | Encrypted Master Secret (MS after the Feistel/PBKDF2 layer) |
| SSS | Shamir Secret Sharing |
| GF(256) | Galois field of 256 elements, Rijndael/AES polynomial |
| RS1024 | Reed-Solomon checksum over GF(1024), 3 words |
| GT / G | Group threshold / group count |
| Ti / Ni | Member threshold / member count of group *i* |
| `e` | Iteration exponent (4 bits); PBKDF2 iterations = `10000 << e` |
| `ext` | Extendable backup flag (1 bit) |

## 2. Scope

**In scope**

- `Bitcoinex.BIP39`: entropy → mnemonic, mnemonic → entropy (with checksum validation), `valid?/1`, mnemonic → 512-bit seed (PBKDF2-HMAC-SHA512, NFKD normalization), mnemonic → master `xprv` (wraps `ExtendedKey.seed_to_master_private_key/2`).
- `Bitcoinex.SLIP39` family: GF(256) arithmetic + Lagrange interpolation, single- and two-level share split/recover, digest verification, Feistel encrypt/decrypt (PBKDF2-HMAC-SHA256), RS1024 checksum, 10-bit word packing, `Share` struct encode/decode, and the top-level `generate_mnemonics` / `combine_mnemonics` API. Extendable-flag (`ext`) supported.
- `Bitcoinex.Utils.pbkdf2/5`: single shared PBKDF2 helper used by both schemes.
- Two word lists under `priv/`: `bip39_english.txt` (2048) and `slip39_english.txt` (1024), read at compile time.
- `mix.exs` package `files` updated to ship `priv`.

**Out of scope**

- Non-English BIP-39 word lists (Japanese NFKD spacing edge cases, etc.). English only; the `to_seed` NFKD path is language-correct so other lists can be added later.
- Address/descriptor derivation beyond the master `xprv` — callers use existing `ExtendedKey.derive_extended_key/2`.
- BIP-85 deterministic entropy, Electrum seeds, and the legacy Trezor SLIP-39 GUI flow.
- Hardened memory zeroing / secret scrubbing (Elixir binaries are immutable/GC-managed; out of the library's control — noted in §6).

## 3. Design / Approach

### 3.1 Shared primitive: `Utils.pbkdf2/5`

Both schemes need PBKDF2. OTP 27 (pinned in `.tool-versions`) exposes `:crypto.pbkdf2_hmac/5`, so this is a thin, testable wrapper — not a from-scratch implementation.

```
@spec pbkdf2(digest :: :sha256 | :sha512, password :: binary, salt :: binary,
             iterations :: pos_integer, key_len :: pos_integer) :: binary
def pbkdf2(digest, password, salt, iterations, key_len)
  #=> :crypto.pbkdf2_hmac(digest, password, salt, iterations, key_len)
```

**Options considered.** (A) Hand-roll PBKDF2 with `:crypto.mac/4` for portability to old OTP. (B) Delegate to `:crypto.pbkdf2_hmac/5`. **Decision: B** — the repo already pins OTP 27 and calls `:crypto.mac/4` inline (`extendedkey.ex:336`, `ecdsa.ex`), so requiring `pbkdf2_hmac/5` (added in OTP 24.2) is consistent with the existing floor. Keeps the "no native deps" property.

**Invariant.** `Utils.pbkdf2/5` never applies string normalization or salt prefixes — callers own that (BIP-39 NFKD, SLIP-39 `"shamir"` salt). This keeps it reusable.

### 3.2 BIP-39 (`Bitcoinex.BIP39`)

Word list is `priv/bip39_english.txt` (2048 lines), read at compile time into `@wordlist` (a tuple, for O(1) index access) and `@word_index` (a `%{word => index}` map), mirroring the `@base58_decode_map` idiom (`base58.ex:...`).

**Entropy → mnemonic.** ENT ∈ {128,160,192,224,256} bits (16/20/24/28/32 bytes). CS = ENT/32 checksum bits = first CS bits of `Utils.sha256(entropy)`. Concatenate `entropy || checksum_bits`; the total is a multiple of 11. Split into 11-bit groups (`for <<idx::11 <- bits>>, do: elem(@wordlist, idx)`), join with spaces.

**Mnemonic → entropy.** Split on whitespace; map each word to its 11-bit index (`{:error, :word_not_in_list}` on miss); repack to a bitstring; split off the trailing CS bits; recompute the checksum and compare (`{:error, :invalid_checksum}`). Word count must be one of {12,15,18,21,24} (`{:error, :invalid_word_count}`).

**Mnemonic → seed.** `Utils.pbkdf2(:sha512, nfkd(mnemonic), "mnemonic" <> nfkd(passphrase), 2048, 64)`. `nfkd/1` = `:unicode.characters_to_nfkd_binary/1` (or `String.normalize(s, :nfkd)`). `to_seed/2` does **not** re-validate the checksum (BIP-39 §"From mnemonic to seed" permits any string), but `to_master_private_key/3` validates first.

**Invariants.** Round-trip `entropy_to_mnemonic |> mnemonic_to_entropy == {:ok, entropy}` for every valid length. Seed derivation is independent of checksum validity.

### 3.3 SLIP-39 constants (`Bitcoinex.SLIP39`)

All values verbatim from the spec; module attributes:

| Constant | Value |
|----------|-------|
| `@radix_bits` | 10 |
| `@id_length_bits` | 15 |
| `@extendable_flag_length_bits` | 1 |
| `@iteration_exp_length_bits` | 4 |
| `@id_exp_length_words` | 2 |
| `@max_share_count` | 16 |
| `@checksum_length_words` | 3 |
| `@digest_length_bytes` | 4 |
| `@metadata_length_words` | 7 (`@id_exp_length_words + 2 + @checksum_length_words`) |
| `@min_strength_bits` | 128 |
| `@min_mnemonic_length_words` | 20 |
| `@base_iteration_count` | 10000 |
| `@round_count` | 4 |
| `@secret_index` | 255 |
| `@digest_index` | 254 |
| `@customization_string_orig` | `"shamir"` |
| `@customization_string_extendable` | `"shamir_extendable"` |
| `@gf256_reducing_poly` | `0x11B` (x⁸+x⁴+x³+x+1) |

### 3.4 GF(256) (`Bitcoinex.SLIP39.GF256`)

Field over the Rijndael polynomial `0x11B`. Build exp/log tables **at compile time** using generator `3` (0x03), stored as tuples `@exp_table` (size 255, cyclic) and `@log_table` (size 256).

```
@spec add(byte, byte) :: byte            # Bitwise.bxor/2
@spec mul(byte, byte) :: byte            # 0 if either 0; else exp[(log[a]+log[b]) rem 255]
@spec div(byte, byte) :: byte            # a / b; raises/errors on b == 0
@spec pow(byte, integer) :: byte
@spec interpolate(points :: [{byte, binary}], x :: byte) :: binary
```

`interpolate/2` performs byte-wise Lagrange interpolation: for `points = [{x_i, y_i}]` (each `y_i` an `n`-byte binary) it computes `f(x)` for each of the `n` byte lanes independently, per the spec formula `f(x) = Σ_i y_i · Π_{j≠i} (x − x_j)/(x_i − x_j)` in GF(256). Returns the `n`-byte binary. All `x_i` must be distinct (caller-guaranteed).

**Options considered.** (A) Compute-time tables via `:math`-free repeated `mul_slow` (Russian-peasant with `0x11B` reduction) memoized into module attrs. (B) Runtime tables in an Agent/ETS. **Decision: A** — matches the repo's compile-time `@base58_decode_map` / `@gen` style; no runtime process (the library has no supervision tree). `mul_slow/2` (the shift-and-reduce loop) is a private compile-time helper only; runtime `mul/2` uses the log tables.

### 3.5 Shamir split/recover (`Bitcoinex.SLIP39.Shamir`)

```
@spec split_secret(threshold :: 1..16, count :: 1..16, secret :: binary,
                    rng :: (pos_integer -> binary)) :: [{byte, binary}]
@spec recover_secret(threshold :: 1..16, shares :: [{byte, binary}]) ::
        {:ok, binary} | {:error, atom}
@spec create_digest(random :: binary, shared_secret :: binary) :: binary
@spec valid_digest?(digest_share :: binary, shared_secret :: binary) :: boolean
```

**`split_secret/4`.**
- `threshold == 1` → return `[{0, secret}, {1, secret}, …, {count-1, secret}]` (all equal). (Constraint enforced upstream: `threshold == 1` ⇒ `count == 1`.)
- else: `random_share_count = threshold - 2`; produce `base = [{i, rng.(byte_size(secret))} : i ← 0..random_share_count-1]`; build `R = rng.(byte_size(secret) - @digest_length_bytes)`, `digest = create_digest(R, secret)` (= `HMAC-SHA256(R, secret)[0..3] || R`), and the anchor points `[{@digest_index, digest}, {@secret_index, secret}]`. Interpolate the remaining indices `random_share_count..count-1` from `base ++ anchors` via `GF256.interpolate/2`. Return `base ++ interpolated`.

**`recover_secret/2`.**
- `threshold == 1` → `{:ok, value_of_the_single_share}`.
- else: `secret = GF256.interpolate(shares, @secret_index)`; `digest_share = GF256.interpolate(shares, @digest_index)`; if `valid_digest?(digest_share, secret)` → `{:ok, secret}` else `{:error, :invalid_digest}`.

`create_digest/2` uses `:crypto.mac(:hmac, :sha256, random, shared_secret)` sliced to `@digest_length_bytes`, matching the inline HMAC idiom already in `extendedkey.ex`.

**Invariant.** For any `T ≤ k ≤ N`, recovering from any `T` of the `N` shares returns the original `secret`; recovering from `< T` or mismatched shares yields `{:error, :invalid_digest}` with ~2⁻³² false-accept probability.

### 3.6 Feistel cipher (`Bitcoinex.SLIP39.Cipher`)

```
@spec encrypt(ms :: binary, passphrase :: binary, e :: 0..15, id :: 0..0x7FFF, ext :: boolean) :: binary
@spec decrypt(ems :: binary, passphrase :: binary, e :: 0..15, id :: 0..0x7FFF, ext :: boolean) :: binary
```

4-round balanced Feistel on `n`-byte input (`n` even), `L = first n/2`, `R = last n/2`:
- round function `F(i, R) = Utils.pbkdf2(:sha256, <<i::8>> <> passphrase, salt <> R, iterations, div(n,2))`
- `iterations = (@base_iteration_count <<< e) |> div(@round_count)` = `2500 <<< e`
- `salt = if ext, do: "", else: @customization_string_orig <> <<id::16>>` (id big-endian 2 bytes)
- encrypt: `i ∈ [0,1,2,3]`, `{L,R} = {R, Utils.xor_bytes(L, F(i,R))}`; output `R <> L`.
- decrypt: identical with `i ∈ [3,2,1,0]`.

`encrypt` and `decrypt` share one private `feistel/6` taking the round-index list; `xor_bytes/2` is the existing `Utils.xor_bytes/2`. **Invariant:** `decrypt(encrypt(ms, …), …) == ms` for identical `(passphrase, e, id, ext)`.

### 3.7 Encoding: RS1024 + word packing (`Bitcoinex.SLIP39.Encoding`)

Word list `priv/slip39_english.txt` (1024 lines) → `@wordlist` tuple + `@word_index` map (same idiom as BIP-39).

**RS1024** mirrors `Bech32.bech32_polymod/1` but over GF(1024) with the SLIP-39 generator:

```
@gen [0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
      0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120]
@spec rs1024_polymod([non_neg_integer]) :: non_neg_integer
@spec rs1024_create_checksum(data :: [0..1023], ext :: boolean) :: [0..1023]  # 3 words
@spec rs1024_verify_checksum(data :: [0..1023], ext :: boolean) :: boolean
```

`customization = if ext, do: @customization_string_extendable, else: @customization_string_orig`, expanded to a list of its byte values. `create`: `poly = rs1024_polymod(cust ++ data ++ [0,0,0]) |> Bitwise.bxor(1)`; the 3 checksum words are `[(poly >>> (10*(2-i))) &&& 1023 : i ← 0..2]`. `verify`: `rs1024_polymod(cust ++ data_including_checksum) == 1`.

**Word packing.** `indices_to_words/1` maps each 10-bit index to `elem(@wordlist, idx)`; `words_to_indices/1` maps each word to its index (`{:error, :word_not_in_list}` on miss). Bits↔indices uses Elixir bitstring comprehension (`for <<idx::10 <- bin>>, do: idx`), the same technique as BIP-39's 11-bit packing — see §3.9 for the shared helper.

### 3.8 Share struct + single-mnemonic codec (`Bitcoinex.SLIP39.Share`)

```
@enforce_keys [:identifier, :extendable, :iteration_exponent, :group_index,
               :group_threshold, :group_count, :member_index, :member_threshold, :share_value]
defstruct     [:identifier, :extendable, :iteration_exponent, :group_index,
               :group_threshold, :group_count, :member_index, :member_threshold, :share_value]
@type t :: %__MODULE__{
  identifier: 0..0x7FFF, extendable: boolean, iteration_exponent: 0..15,
  group_index: 0..15, group_threshold: 1..16, group_count: 1..16,
  member_index: 0..15, member_threshold: 1..16, share_value: binary }
```

Note thresholds/counts are stored **1-based** in the struct; the wire format stores them minus 1 (`Gt-1`, `G-1`, `t-1`) in 4 bits each. `group_index`/`member_index` are stored as-is (0-based x-coordinates).

**Wire layout** (before RS1024), bit-packed with a single bitstring match:

```
<<identifier::15, ext_bit::1, iteration_exponent::4,
  group_index::4, group_threshold_minus1::4, group_count_minus1::4,
  member_index::4, member_threshold_minus1::4,
  padding::size(pad_bits), share_value::binary>>
```

- First 4 words (40 bits) = the metadata above; remaining words (minus 3 checksum words) = padded share value.
- `pad_bits = (10 - rem(bit_size(share_value), 10)) |> rem(10)` — leading zero bits so the padded share value is a multiple of 10 bits. For a 16-byte value: 2 pad bits → 13 words; 32-byte: 4 pad bits → 26 words. Constraint: `pad_bits < 10` and all-zero (`{:error, :invalid_padding}` on decode).

```
@spec encode(t()) :: {:ok, String.t()} | {:error, atom}   # struct -> space-joined mnemonic
@spec decode(String.t()) :: {:ok, t()} | {:error, atom}   # mnemonic -> struct, verifies RS1024
```

`decode/1`: split words → indices (`words_to_indices`) → verify RS1024 (`{:error, :invalid_checksum}`) and word count ≥ `@min_mnemonic_length_words` (`{:error, :invalid_mnemonic_length}`) → strip 3 checksum words → bit-unpack metadata → validate padding → build struct (adding 1 to the stored thresholds/counts). `encode/1`: reverse, appending `rs1024_create_checksum`.

### 3.9 Two-level orchestration (`Bitcoinex.SLIP39`)

```
@type group_spec :: {member_threshold :: 1..16, member_count :: 1..16}

@spec generate_mnemonics(group_threshold :: 1..16, groups :: [group_spec],
        master_secret :: binary, opts :: keyword) ::
        {:ok, [[String.t()]]} | {:error, atom}
# opts: passphrase (default ""), extendable (default true),
#       iteration_exponent (default 0), rng (default &:crypto.strong_rand_bytes/1),
#       identifier (default nil -> random 15 bits from rng)

@spec combine_mnemonics(mnemonics :: [String.t()], passphrase :: binary) ::
        {:ok, binary} | {:error, atom}
```

**`generate_mnemonics/4`.**
1. Validate: `master_secret` byte length even and `≥ 16` (`:invalid_secret_length`); `1 ≤ group_threshold ≤ length(groups) ≤ 16` (`:invalid_group_threshold`); each `{t,n}` with `1 ≤ t ≤ n ≤ 16`, and **not** (`t == 1 and n > 1`) (`:invalid_member_threshold`).
2. `identifier` = opt or `:rand`-free draw of 15 bits from `rng` (`<<id::15, _::1>> = rng.(2)`).
3. `ems = Cipher.encrypt(master_secret, passphrase, e, id, ext)`.
4. `group_shares = Shamir.split_secret(group_threshold, length(groups), ems, rng)` → `[{group_index, group_value}]`.
5. For each `{group_index, group_value}` paired with its `{Ti, Ni}`: `member_shares = Shamir.split_secret(Ti, Ni, group_value, rng)`; for each `{member_index, share_value}` build a `Share` and `Share.encode/1`.
6. Return `{:ok, list_of_groups}` where each element is that group's list of mnemonic strings.

**`combine_mnemonics/2`.**
1. `Share.decode/1` every mnemonic (propagate first `{:error, _}`).
2. Cross-share consistency: all shares must share `identifier`, `extendable`, `iteration_exponent`, `group_threshold`, `group_count`, and `byte_size(share_value)` (`:mismatching_shares`).
3. Group by `group_index`. Distinct group count must equal `group_threshold` (`:insufficient_groups` / `:too_many_groups`). Within each present group: all members share the same `member_threshold`; member count must equal that threshold (`:insufficient_member_shares`); member indices distinct (`:duplicate_member_index`).
4. Per group: `group_value = Shamir.recover_secret(Ti, [{member_index, share_value}])`.
5. `ems = Shamir.recover_secret(group_threshold, [{group_index, group_value}])`.
6. `ms = Cipher.decrypt(ems, passphrase, e, id, ext)`; return `{:ok, ms}`.

**Options considered — module granularity.** (A) One monolithic `Bitcoinex.SLIP39`. (B) Submodules `GF256`/`Shamir`/`Cipher`/`Encoding`/`Share` + thin top module. **Decision: B** — mirrors the repo's `Transaction.{In,Out,Witness,Utils}` and `PSBT.{Global,In,Out}` decomposition, keeps each file testable in isolation, and lets `GF256`/`Shamir` be reused independently.

**Options considered — naming (`BIP39`/`SLIP39` vs descriptive).** `ExtendedKey` (BIP-32) uses a descriptive name, but "Mnemonic" is ambiguous here (both schemes are mnemonics). **Decision:** use spec-number names `Bitcoinex.BIP39` and `Bitcoinex.SLIP39` for disambiguation; note this deviates slightly from `ExtendedKey`.

**Options considered — error style.** Repo mixes string errors (`Utils`, `ExtendedKey`, `PrivateKey`) and atom errors (`Base58`, `Bech32`). **Decision:** atom reasons for all BIP-39/SLIP-39 decode/validate paths, matching the closest analogs (`Base58`/`Bech32`, which are the checksum/parse modules). Listed exactly in §4.

### 3.10 Shared bit-packing helper (DRY)

BIP-39 (11-bit) and SLIP-39 (10-bit) both convert between a bitstring and a list of fixed-width indices. Factor the *generic* direction that isn't a trivial comprehension into `Utils`:

```
@spec int_list_to_bits([non_neg_integer], width :: pos_integer) :: bitstring
def int_list_to_bits(ints, width)   # Enum.reduce building <<acc::bitstring, i::size(width)>>
```

The reverse direction is the one-liner `for <<i::size(width) <- bits>>, do: i` and stays inline in each module (a shared function buys nothing there). This is the only packing code shared; word lists and checksum logic stay scheme-specific.

## 4. Code Changes

### `lib/utils.ex` — `Bitcoinex.Utils`
- **add** `pbkdf2/5` (§3.1) — shared PBKDF2-HMAC wrapper.
- **add** `int_list_to_bits/2` (§3.10) — shared MSB-first index packer.

### `lib/bip39.ex` — `Bitcoinex.BIP39` (new)
- `@wordlist` (2048-tuple), `@word_index` (map) from `priv/bip39_english.txt` at compile time.
- `@spec entropy_to_mnemonic(binary) :: {:ok, String.t()} | {:error, atom}`
- `@spec mnemonic_to_entropy(String.t()) :: {:ok, binary} | {:error, atom}`
- `@spec valid?(String.t()) :: boolean`
- `@spec to_seed(String.t(), passphrase :: binary) :: binary` (passphrase default `""`)
- `@spec to_master_private_key(String.t(), passphrase :: binary, prefix :: atom) :: {:ok, ExtendedKey.t()} | {:error, atom | String.t()}` — validates, `to_seed`, then `ExtendedKey.seed_to_master_private_key/2`.
- private `nfkd/1`.
- Error atoms: `:invalid_entropy_length`, `:invalid_word_count`, `:word_not_in_list`, `:invalid_checksum`.

### `lib/slip39.ex` — `Bitcoinex.SLIP39` (new)
- All `@`-constants from §3.3.
- `@type group_spec`, `generate_mnemonics/4`, `combine_mnemonics/2` (§3.9).
- private validators (`validate_secret/1`, `validate_groups/2`), grouping/consistency helpers.
- Error atoms: `:invalid_secret_length`, `:invalid_group_threshold`, `:invalid_member_threshold`, `:mismatching_shares`, `:insufficient_groups`, `:too_many_groups`, `:insufficient_member_shares`, `:duplicate_member_index`, `:empty_mnemonic_set`.

### `lib/slip39/gf256.ex` — `Bitcoinex.SLIP39.GF256` (new)
- `@exp_table`, `@log_table` (compile-time, generator 3, poly `0x11B`).
- `add/2`, `mul/2`, `div/2`, `pow/2`, `interpolate/2` (§3.4). Private compile-time `mul_slow/2`.

### `lib/slip39/shamir.ex` — `Bitcoinex.SLIP39.Shamir` (new)
- `split_secret/4`, `recover_secret/2`, `create_digest/2`, `valid_digest?/2` (§3.5). Error atom: `:invalid_digest`.

### `lib/slip39/cipher.ex` — `Bitcoinex.SLIP39.Cipher` (new)
- `encrypt/5`, `decrypt/5`, private `feistel/6`, `round_function/5` (§3.6).

### `lib/slip39/encoding.ex` — `Bitcoinex.SLIP39.Encoding` (new)
- `@wordlist`/`@word_index` from `priv/slip39_english.txt`; `@gen`.
- `rs1024_polymod/1`, `rs1024_create_checksum/2`, `rs1024_verify_checksum/2`, `indices_to_words/1`, `words_to_indices/1` (§3.7). Error atom: `:word_not_in_list`.

### `lib/slip39/share.ex` — `Bitcoinex.SLIP39.Share` (new)
- Struct (§3.8), `encode/1`, `decode/1`. Error atoms: `:invalid_checksum`, `:invalid_mnemonic_length`, `:invalid_padding`.

### `priv/bip39_english.txt`, `priv/slip39_english.txt` (new)
- Verbatim upstream lists (2048 / 1024 lines, newline-separated). Source: BIP-39 `english.txt` and SLIP-39 `wordlist.txt`.

### `mix.exs`
- Add `priv` to the package `files` list (currently `~w(lib test .formatter.exs mix.exs README.md UNLICENSE CHANGELOG.md SECURITY.md)`) so word lists ship in the Hex package.
- Bump `version` (e.g. `0.1.8` → `0.2.0`).

### `CHANGELOG.md`
- New "Added" entry (Keep a Changelog format): BIP-39 mnemonics + SLIP-39 secret sharing.

## 5. DB Schema Changes

None — Bitcoinex is a stateless library with no datastore.

## 6. Security Concerns

- **Randomness.** Share splitting and identifier generation MUST use a CSPRNG. Default `rng` is `:crypto.strong_rand_bytes/1`; the injectable `rng` opt exists **only** for deterministic round-trip tests and is documented as test-only. Never default to `:rand`.
- **Passphrase & secret handling.** Elixir binaries are immutable and GC-managed; the library cannot guarantee zeroization of secrets/passphrases in memory. Documented as a known limitation (consistent with the repo's README "not for real funds" disclaimer). No secrets are logged.
- **Digest verification.** `recover_secret/2` rejects mismatched/insufficient shares via the HMAC digest (~2⁻³² false-accept) — prevents silently reconstructing a wrong secret. `combine_mnemonics/2` additionally enforces threshold/consistency invariants before interpolation.
- **Input validation.** All decode paths validate word membership, RS1024 checksum, padding zero-ness, word count, and cross-share consistency before use — no unchecked bitstring math on attacker-supplied mnemonics.
- **Timing.** Not constant-time (GF(256) table lookups, HMAC compare). Acceptable: this is offline backup/recovery, not an online oracle. Noted, not mitigated.
- **PBKDF2 cost.** SLIP-39 iterations scale `2500 << e` per round × 4 rounds; `e` is attacker-influenced only within a share the attacker already holds, so no amplification vector beyond the holder's own choice.

## 7. Metrics / Alerting

None — library code, no runtime process or telemetry surface.

## 8. Testing

Test files mirror `lib/` as `test/*_test.exs` / `test/slip39/*_test.exs`, `use ExUnit.Case`, `doctest` the module, large `@vector` module attributes, `for pair <- @vectors` iteration, hex via `Base.decode16!(s, case: :lower)` — matching `extendedkey_test.exs` / `base58_test.exs`. Official vectors: SLIP-39 `vectors.json` (recovery vectors: description, mnemonic list, expected MS hex, expected xprv) and BIP-39 Trezor `vectors.json` (entropy/mnemonic/seed/xprv, passphrase `"TREZOR"`).

### To add

**`test/utils_test.exs`** (new file — Utils is currently untested)
- `pbkdf2/5`: RFC 6070 SHA-1? (N/A — SHA-256/512 only); assert against a known BIP-39 seed vector and a known SLIP-39 round-function output.
- `int_list_to_bits/2`: packs `[1,2,3]` at width 11 to the expected bitstring; round-trips against the `for <<i::11 <- bits>>` comprehension.

**`test/bip39_test.exs`**
- `entropy_to_mnemonic/1`: each Trezor vector (12/15/18/21/24 words) → expected mnemonic.
- `mnemonic_to_entropy/1`: each vector mnemonic → expected entropy.
- Round-trip: `entropy_to_mnemonic |> mnemonic_to_entropy == {:ok, entropy}` for all five lengths.
- `entropy_to_mnemonic/1` rejects entropy of 15/17/33 bytes → `{:error, :invalid_entropy_length}`.
- `mnemonic_to_entropy/1`: 11-word and 13-word inputs → `{:error, :invalid_word_count}`.
- `mnemonic_to_entropy/1`: word not in list → `{:error, :word_not_in_list}`.
- `mnemonic_to_entropy/1`: last word altered so checksum fails → `{:error, :invalid_checksum}`.
- `to_seed/2`: each vector `(mnemonic, "TREZOR")` → expected 64-byte seed; empty passphrase path.
- `to_seed/2`: NFKD — a mnemonic/passphrase with composed vs decomposed Unicode yields identical seed.
- `valid?/1`: true for valid vector, false for checksum-broken and word-count-broken inputs.
- `to_master_private_key/3`: each vector → expected `xprv` (equality vs `ExtendedKey.parse_extended_key/1`); invalid mnemonic → error before derivation.

**`test/slip39/gf256_test.exs`**
- `add/2`: XOR identities (`a+a==0`, `a+0==a`).
- `mul/2`: `a*0==0`, `a*1==a`, known AES vectors (e.g. `0x57 * 0x13 == 0xFE`), commutativity on a sample grid.
- `div/2`: `mul(a, div(1,a)) == 1` for all `a ∈ 1..255`; `div(a,b)` inverse of `mul` on samples.
- `pow/2`: `pow(a,0)==1`, `pow(a,1)==a`, `exp/log` table consistency across full field.
- `interpolate/2`: degree-0 (constant) and degree-1 line recover exactly; reconstructs a known polynomial's `f(255)` from `T` points; independent of *which* `T` points are chosen.

**`test/slip39/shamir_test.exs`**
- `split_secret/4` with `threshold==1`: all `count` shares equal the secret.
- `split_secret` + `recover_secret` round-trip for `(T,N) ∈ {(2,3),(3,5),(2,2),(16,16)}` with a fixed test `rng`; recover from every `T`-subset.
- `recover_secret/2` from `< T` shares → wrong value rejected by digest → `{:error, :invalid_digest}`.
- `recover_secret/2` with one corrupted share byte → `{:error, :invalid_digest}`.
- `create_digest/2` / `valid_digest?/2`: valid pair true, tampered secret false.
- Secret lengths 16 and 32 bytes both round-trip.

**`test/slip39/cipher_test.exs`**
- `encrypt` then `decrypt` == identity for `ext ∈ {true,false}`, `e ∈ {0,1}`, passphrase `""` and non-empty, 16- and 32-byte MS.
- Salt selection: `ext==false` uses `"shamir"<>id`, `ext==true` uses `""` (assert differing ciphertext for otherwise-identical inputs).
- Iteration count: `e` change yields different ciphertext (sanity that `e` is threaded).
- Known-answer: derive an EMS embedded in a SLIP-39 official vector and assert `decrypt` recovers the vector's MS.

**`test/slip39/encoding_test.exs`**
- `rs1024_polymod/1` matches spec pseudocode on a fixed word array.
- `rs1024_create_checksum/2` then `rs1024_verify_checksum/2` == true, for `ext ∈ {true,false}` (different customization strings).
- `rs1024_verify_checksum/2` false when any single word is mutated (1-,2-,3-word error detection).
- `indices_to_words/1` / `words_to_indices/1` round-trip; unknown word → `{:error, :word_not_in_list}`.
- Word list loaded from `priv/` has exactly 1024 entries, all unique, all length 4–8.

**`test/slip39/share_test.exs`**
- `decode/1` on each official-vector mnemonic → struct with expected metadata (identifier, thresholds, indices).
- `encode/1` round-trips every decoded struct back to the identical mnemonic string.
- `decode/1`: mutated checksum word → `{:error, :invalid_checksum}`.
- `decode/1`: too-short mnemonic (< 20 words) → `{:error, :invalid_mnemonic_length}`.
- `decode/1`: non-zero padding bits → `{:error, :invalid_padding}`.
- Threshold/count off-by-one: struct stores 1-based, wire stores 0-based (encode of `Gt=2` produces the byte for `1`).
- Both 128-bit (20-word) and 256-bit (33-word) shares.

**`test/slip39_test.exs`** (top-level)
- `combine_mnemonics/2` on every SLIP-39 official `vectors.json` entry → expected MS hex (and derived `xprv` where the vector supplies one), including passphrase and `ext` variants.
- Official invalid vectors (empty expected result) → appropriate `{:error, _}`.
- `generate_mnemonics/4` + `combine_mnemonics/2` round-trip with fixed `rng`: single group `2-of-3`; multi-group `2-of-{(2,3),(3,5),(1,1)}`; `16` groups; recover from exactly-threshold subsets in each.
- `generate_mnemonics/4` validation errors: even/`≥16` secret (`:invalid_secret_length`); `group_threshold > #groups` (`:invalid_group_threshold`); `t>n` and `t==1,n>1` (`:invalid_member_threshold`).
- `combine_mnemonics/2` errors: mixed identifiers (`:mismatching_shares`); fewer than `GT` groups (`:insufficient_groups`); a group with fewer than `Ti` members (`:insufficient_member_shares`); duplicate member index (`:duplicate_member_index`); empty list (`:empty_mnemonic_set`).
- Passphrase mismatch on combine yields a *different* MS (SLIP-39 has no wrong-passphrase error — documented), assert it differs from the correct MS.
- `extendable: true` vs `false` produce mnemonics that both round-trip and use the correct customization/salt.

### To update
- None. All additions are net-new modules; no existing signatures change. `mix.exs` `version`/`files` and `CHANGELOG.md` edits carry no test impact. `ExtendedKey.seed_to_master_private_key/2` is consumed unchanged — confirmed by reading `extendedkey.ex:330-346` (no mock/regen needed; the library has no mocks).

### Toolchain / fixtures
- Add `priv/` word lists before compiling (module attrs read them at compile time — a missing file fails compilation loudly).
- Vectors: vendor SLIP-39 `vectors.json` and BIP-39 `vectors.json` under `test/data/` (new dir) or inline as `@` attributes, following the `extendedkey_test.exs` inline-vector precedent. `stream_data` is available if property tests (round-trip GF/Shamir) are desired, though the repo currently defines none.

## 9. PR Breakdown

```
PR B1 (Utils.pbkdf2 + int_list_to_bits) ──┬─► PR B2 (BIP39)
                                           │
                                           └─► PR S3 (SLIP39 GF256+Shamir) ─► PR S4 (Cipher) ─► PR S5 (Encoding+Share) ─► PR S6 (SLIP39 orchestrator + vectors)
PR B0 (priv word lists + mix.exs files) ───(prereq for B2 and S5)
```

- **PR B0 — `S0:` word lists & packaging.** Add `priv/bip39_english.txt`, `priv/slip39_english.txt`; add `priv` to `mix.exs` package `files`. No code. Test: a trivial `priv`-load smoke test (counts 2048 / 1024). Blocks B2, S5.
- **PR B1 — `S1:` shared primitives.** `Utils.pbkdf2/5`, `Utils.int_list_to_bits/2`, `test/utils_test.exs`. Independent. Blocks B2, S3.
- **PR B2 — `S2:` BIP-39.** `lib/bip39.ex`, `test/bip39_test.exs`, BIP-39 vectors, `CHANGELOG.md`. Depends on B0, B1. Independently shippable (delivers "mnemonic → xprv").
- **PR S3 — `S3:` SLIP-39 field & sharing.** `lib/slip39/gf256.ex`, `lib/slip39/shamir.ex` + tests. Depends on B1 (none of Utils' bit helpers, actually — only `:crypto`), so effectively independent; sequence after B1 to avoid `Utils` merge conflicts.
- **PR S4 — `S4:` SLIP-39 cipher.** `lib/slip39/cipher.ex` + tests. Depends on B1 (`Utils.pbkdf2`, `xor_bytes`).
- **PR S5 — `S5:` SLIP-39 encoding & share.** `lib/slip39/encoding.ex`, `lib/slip39/share.ex` + tests. Depends on B0 (word list), B1 (`int_list_to_bits`).
- **PR S6 — `S6:` SLIP-39 orchestrator.** `lib/slip39.ex`, `test/slip39_test.exs`, official vectors, `CHANGELOG.md` + `mix.exs` version bump. Depends on S3, S4, S5.

**Coupling / conflict risk.** `mix.exs` is touched by B0 (files) and S6 (version) — sequence or rebase to avoid a conflict. `CHANGELOG.md` is touched by B2 and S6 — same. `lib/utils.ex` is touched only by B1. No shared generated files. Each PR opens as **draft** with a stacked `SN:` title prefix (S = SLIP/seed feature).

## 10. Open Questions

- **Passphrase-wrong on `combine_mnemonics`.** SLIP-39 by design cannot detect a wrong passphrase (any passphrase yields *some* MS — plausible-deniability feature). Spec returns `{:ok, ms}` regardless. Confirm we don't want an optional "expected fingerprint" check layered on top.
- **`extendable` default.** Defaulted to `true` (current-spec direction). If interop with older wallets that predate the `ext` flag matters, flip the default to `false`. Decision needed before S6.
- **Vector storage location.** Inline `@` attributes (matches `extendedkey_test.exs`) vs a new `test/data/*.json` read at test time. Leaning inline for consistency; confirm.
