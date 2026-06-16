# BIP-352 Silent Payments — Primitives Implementation Notes

## Scope

Implement the **cryptographic primitives** that a Silent Payments wallet/scanner builds on,
plus silent-payment address encode/decode and full **label** support.

**In scope:** send/scan/spend key derivation, the ECDH + tweak math, input/label tweaks,
even-Y / parity handling, `sp1q…`/`tsp1q…` address codec.

**Out of scope (wallet/scanner concerns, caller's job):** coin selection and input/output
selection; parsing transactions / scriptSigs / witnesses to extract input pubkeys and
outpoints; choosing `outpoint_L` (the smallest outpoint); the `k`-increment scan loop; the
`K_max` (=2323) cap; the label-lookup table; BIP158 / light-client support.

> **`outpoint_L` (smallest outpoint):** SP hashes the lexicographically smallest 36-byte
> outpoint into `input_hash`, but **selecting it is the caller's job** — the caller builds
> the transaction and chooses the inputs, then passes the already-chosen `outpoint_L` to
> `input_hash/2`. This needs no helper from us: Elixir's native binary ordering is unsigned
> byte-by-byte lexicographic (verified: `Enum.min([<<0x02,…>>, <<0x01,0xFF,…>>]) ==
> <<0x01,0xFF,…>>`), exactly BIP-352's ordering for fixed-width 36-byte outpoints, so the
> caller just does `Enum.min(outpoints)`.

Reference: [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) (v1.1.1).

---

## Notation

- Uppercase = public keys (points), lowercase = private keys (scalars),
- `·` = EC scalar-mult,
- `G` = generator point,
- `n` = curve order.
- `ser_P(P)` = 33-byte compressed point,
- `ser_256(x)` = 32-byte big-endian scalar,
- `ser_32(i)` = 4-byte big-endian int.
- Tagged hash per BIP340: `hash_tag(x) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ x)`.

Three tags are used:

| Tag string             | Used for               |
| ---------------------- | ---------------------- |
| `BIP0352/Inputs`       | `input_hash`           |
| `BIP0352/SharedSecret` | per-output tweak `t_k` |
| `BIP0352/Label`        | label tweak            |

---

## Existing library primitives (reuse — do not reinvent)

| Need                                  | Library function                                          |
| ------------------------------------- | --------------------------------------------------------- |
| Tagged hash                           | `Bitcoinex.Utils.tagged_hash/2`                           |
| `ser_256` / `ser_32`                  | `Bitcoinex.Utils.int_to_big/2`                            |
| Point add / scalar-mult               | `Bitcoinex.Secp256k1.Math.add/2`, `multiply/2`            |
| Curve order `n`                       | `Bitcoinex.Secp256k1.Params.curve().n`                    |
| `ser_P(P)` (compressed)               | `Bitcoinex.Secp256k1.Point.sec/1`                         |
| x-only 32 bytes                       | `Bitcoinex.Secp256k1.Point.x_bytes/1`                     |
| lift x-only → **even-Y** point        | `Bitcoinex.Secp256k1.Point.lift_x/1`                      |
| parse compressed pubkey               | `Bitcoinex.Secp256k1.Point.parse_public_key/1`            |
| even/odd-Y test, infinity test        | `Point.has_even_y/1`, `Point.is_inf/1`                    |
| negate privkey to even-Y pubkey       | `Bitcoinex.Secp256k1.force_even_y/1`                      |
| privkey ↔ point, validate             | `PrivateKey.to_point/1`, `PrivateKey.new/1`               |
| bech32m encode/decode (custom length) | `Bitcoinex.Bech32.encode/4`, `decode/2`, `convert_bits/4` |
| Schnorr (BIP340) sign / verify        | `Bitcoinex.Secp256k1.Schnorr.sign/3`, `verify_signature/3` |
| build P2TR `scriptPubKey` from output | `Bitcoinex.Script.create_p2tr/1`                          |
| **point negate** (port — see below)   | `Bitcoinex.Secp256k1.Point.negate/1`                      |

### BIP-340/341 foundation: what is already here vs. what to port

Silent Payments is built on Taproot (BIP340/341). This repo's `origin`
(`RiverFinancial/bitcoinex`) **already ships** the cryptographic foundation SP needs:

- Tagged hashing — `Bitcoinex.Utils.tagged_hash/2`
- Schnorr (BIP340) sign/verify — `Bitcoinex.Secp256k1.Schnorr`
- bech32m (with a configurable length cap) — `Bitcoinex.Bech32`
- even-Y handling — `Secp256k1.force_even_y/1`, `Point.lift_x/1` (returns even-Y), `Point.has_even_y/1`
- P2TR `scriptPubKey` construction from an output key — `Script.create_p2tr/1`

The **only** SP dependency missing from this repo is point/scalar negation (label matching
must compute `output − P_k`). Rather than add a private helper, **port the upstream
implementation from the fork** `SachinMeier/bitcoinex@master`, which already defines:

- `Bitcoinex.Secp256k1.Point.negate/1` — same `x`, opposite-parity `y` (via `Secp256k1.get_y/2`)
- `Bitcoinex.Secp256k1.PrivateKey.negate/1` — `n − d`
- (nice-to-have) `Signature.to_hex/1`, `PrivateKey.to_hex/1` for test ergonomics

This port is a ~25-line, low-risk delta to `point.ex` / `privatekey.ex` / `secp256k1.ex`
(it cleanly addresses the point-negation note). With it, `output − P_k` is
`Math.add(output_pt, Point.negate(P_k))` — no new private helper in `SilentPayments`.

---

## The math (entire protocol)

| Name              | Definition                                                                | Notes                                               |
| ----------------- | ------------------------------------------------------------------------- | --------------------------------------------------- |
| `input_hash`      | `hash_BIP0352/Inputs(outpoint_L ‖ ser_P(A))`                              | scalar; `outpoint_L` = smallest 36-byte LE outpoint |
| `ecdh_secret`     | sender: `input_hash · a · B_scan` · · receiver: `input_hash · b_scan · A` | identical point (ECDH)                              |
| `t_k`             | `hash_BIP0352/SharedSecret(ser_P(ecdh_secret) ‖ ser_32(k))`               | per-output tweak scalar                             |
| `P_k`             | `B_spend + t_k·G`                                                         | x-only of `P_k` is the BIP341 taproot output key    |
| `label_tweak(m)`  | `hash_BIP0352/Label(ser_256(b_scan) ‖ ser_32(m))`                         | scalar; `b_scan` is the **scan private key**        |
| `label_point(m)`  | `label_tweak(m)·G`                                                        | what the scanner stores in its lookup table         |
| `B_m`             | `B_spend + label_point(m)`                                                | the labeled spend pubkey published in the address   |
| spend privkey `d` | `(b_spend + t_k + label_tweak(m)?) mod n`                                 | label term only if the output was labeled           |

**Parity rules (the footguns):**

- _Sender:_ for every input that is a taproot output, negate its private key to the even-Y
  form before summing (`Secp256k1.force_even_y/1`). Non-taproot keys are summed as-is.
- _Receiver:_ every taproot input contributes its x-only key lifted to **even Y**
  (`Point.lift_x/1` already returns even Y); non-taproot inputs contribute their compressed
  pubkey as parsed. These conventions must match or sender/receiver derive different secrets.
- _Direct output match_ is an **x-only** comparison (`Point.x_bytes(P_k)` vs the 32-byte
  output) — no parity ambiguity.
- _Label match_ computes `output − P_k`, and the output is x-only, so **both** parities of
  the output point must be tried (the spec's "negate output and check a second time").

**Mandatory failure cases** (return `{:error, _}`):

- `input_hash == 0` or `≥ n`
- `t_k == 0` or `≥ n`
- final private-key sum `a == 0` (an _intermediate_ partial sum of 0 is fine — see the
  v1.1.1 vector "Input keys intermediate sum is zero but final sum is non-zero")
- receiver's summed pubkey `A` is the point at infinity

---

## New module: `Bitcoinex.SilentPayments`

File `lib/silent_payments.ex`; tests `test/silent_payments_test.exs`. No new dependencies.
All public functions return `{:ok, _} | {:error, String.t()}` unless noted; structs use
`@enforce_keys` + `@type t()` + `@spec` per project convention.

### Core top-level API (the three the wallet/scanner calls)

```elixir
# SENDING — derive one taproot output key for a recipient.
# Needs BOTH recipient pubkeys: B_scan (for ECDH) and B_spend (added in).
@spec create_output_pubkey(a_sum :: PrivateKey.t(), b_scan :: Point.t(),
        b_spend :: Point.t(), input_hash :: <<_::256>>, k :: non_neg_integer())
        :: {:ok, Point.t()} | {:error, String.t()}

# RECEIVER SCAN — for index k, derive the per-output tweak and candidate output point.
# Caller compares Point.x_bytes(p_k) to the tx's taproot outputs; on a hit, feeds t_k
# straight into spending_privkey/3. Drives its own k-loop.
@spec scan_output(b_scan :: PrivateKey.t(), a_sum :: Point.t(),
        b_spend :: Point.t(), input_hash :: <<_::256>>, k :: non_neg_integer())
        :: {:ok, {t_k :: PrivateKey.t(), p_k :: Point.t()}} | {:error, String.t()}

# RECEIVER SPEND — derive the spending privkey for a found output. Pass the label tweak
# (from label_tweak/2) when the output matched a label, else nil.
@spec spending_privkey(b_spend :: PrivateKey.t(), t_k :: PrivateKey.t(),
        label_tweak :: PrivateKey.t() | nil) :: {:ok, PrivateKey.t()} | {:error, String.t()}
```

`create_output_pubkey/5` and `scan_output/5` are the same formula with different ECDH
inputs — both internally do `shared_secret/3 → shared_secret_tweak/2 → B_spend + t_k·G`.

### Supporting primitives (public — callers and the BIP test vectors exercise these)

```elixir
# Caller supplies outpoint_L — the lexicographically smallest 36-byte outpoint
# (txid LE ‖ vout LE), e.g. via Enum.min/1 — and the summed input pubkey A.
# We do not parse transactions or select inputs/outpoints.
@spec input_hash(outpoint_smallest :: <<_::288>>, a_sum_pubkey :: Point.t())
        :: {:ok, <<_::256>>} | {:error, String.t()}

# ECDH point: input_hash · scalar · point.
# Sender passes (a_sum, B_scan); receiver passes (b_scan, A).
@spec shared_secret(scalar :: PrivateKey.t(), point :: Point.t(),
        input_hash :: <<_::256>>) :: {:ok, Point.t()} | {:error, String.t()}

# Per-output tweak t_k from the ECDH point and output index k.
@spec shared_secret_tweak(ecdh_secret :: Point.t(), k :: non_neg_integer())
        :: {:ok, PrivateKey.t()} | {:error, String.t()}

# Sum input private keys: taproot keys negated to even-Y, others as-is. Fails iff the
# FINAL sum is 0 (intermediate zero is allowed).
@spec sum_input_privkeys(taproot :: [PrivateKey.t()], other :: [PrivateKey.t()])
        :: {:ok, PrivateKey.t()} | {:error, String.t()}

# Sum input public keys (A): taproot inputs given as x-only (lifted to even-Y), others as
# points. Fails if the sum is the point at infinity.
@spec sum_input_pubkeys(taproot_xonly :: [<<_::256>>], other :: [Point.t()])
        :: {:ok, Point.t()} | {:error, String.t()}
```

### Label primitives (full BIP-352 label support)

```elixir
# label_tweak(m) = hash_BIP0352/Label(ser_256(b_scan) ‖ ser_32(m))  — the scalar.
@spec label_tweak(b_scan :: PrivateKey.t(), m :: non_neg_integer())
        :: {:ok, PrivateKey.t()} | {:error, String.t()}

# label_point(m) = label_tweak(m)·G  — the point a scanner precomputes and stores keyed
# to m for fast lookup (always include m = 0, the reserved change label).
@spec label_point(b_scan :: PrivateKey.t(), m :: non_neg_integer())
        :: {:ok, Point.t()} | {:error, String.t()}

# B_m = B_spend + label_point(m)  — the labeled spend pubkey to publish in an address.
# m = 0 is the reserved change label and MUST NOT be handed out as a receive address.
@spec create_labeled_spend_pubkey(b_spend :: Point.t(), b_scan :: PrivateKey.t(),
        m :: non_neg_integer()) :: {:ok, Point.t()} | {:error, String.t()}

# Scan-side label match. Given the unmatched x-only output and the P_k from scan_output,
# return the candidate label points {output_pt − P_k, negate(output_pt) − P_k}. Caller
# looks these up in its label_point ⇒ m table; on a hit it knows m, then derives the
# spend key via label_tweak(b_scan, m) ▸ spending_privkey/3. Encapsulates the both-parity
# ("negate output") handling so callers can't get it wrong.
@spec output_label_candidates(p_k :: Point.t(), output :: <<_::256>>)
        :: {:ok, [Point.t()]} | {:error, String.t()}
```

### Implementation sketch (the non-obvious ones)

```
input_hash(outpoint_L, A):
  h = tagged_hash("BIP0352/Inputs", outpoint_L <> Point.sec(A))
  i = big-endian int of h;  if i == 0 or i >= n: {:error}  else {:ok, h}

shared_secret(scalar, point, input_hash):
  m = (scalar.d * big(input_hash)) mod n;  if m == 0: {:error}
  s = Math.multiply(point, m);  if Point.is_inf(s): {:error}  else {:ok, s}

shared_secret_tweak(ecdh, k):
  t = tagged_hash("BIP0352/SharedSecret", Point.sec(ecdh) <> int_to_big(k, 4))
  i = big-endian int of t;  if i == 0 or i >= n: {:error}  else PrivateKey.new(i)

# both send + scan reduce to this:
output_pubkey(ecdh, B_spend, k):
  {:ok, t_k} = shared_secret_tweak(ecdh, k)
  P = Math.add(B_spend, PrivateKey.to_point(t_k))    # B_spend + t_k·G

sum_input_privkeys(taproot, other):
  ds = Enum.map(taproot, &force_even_y/1) ++ other     # negate taproot to even-Y
  d  = (sum of d.d) mod n;  if d == 0: {:error}  else PrivateKey.new(d)

spending_privkey(b_spend, t_k, label):
  add = if label, do: label.d, else: 0
  d = (b_spend.d + t_k.d + add) mod n;  PrivateKey.new(d)

output_label_candidates(P_k, output_xonly):
  {:ok, even_pt} = Point.lift_x(output_xonly)          # even-Y
  odd_pt = Point.negate(even_pt)                       # ported from fork
  sub = fn p, q -> Math.add(p, Point.negate(q)) end    # P - Q
  {:ok, [sub.(even_pt, P_k), sub.(odd_pt, P_k)]}
```

---

## Address encode / decode (`sp1q…` / `tsp1q…`)

Bech32m of: silent-payment version (0) followed by `convert_bits(ser_P(B_scan) ‖ ser_P(B_m),
8, 5)`. HRP = `sp` (mainnet) / `tsp` (testnet, signet, regtest). Pass
`max_encoded_length: :infinity` to `Bech32` — SP addresses are ≥117 chars and must bypass
the 90-char segwit cap (do **not** route through `Bitcoinex.Segwit`). Decode: v0 requires
exactly 66 data bytes; v1–v30 read the first 66 and ignore the remainder; v31 fails.

```elixir
@spec encode_address(b_scan :: Point.t(), b_m :: Point.t(),
        network :: Network.network_name()) :: {:ok, String.t()} | {:error, String.t()}
@spec decode_address(addr :: String.t())
        :: {:ok, {network :: atom(), version :: non_neg_integer(),
            b_scan :: Point.t(), b_m :: Point.t()}} | {:error, String.t()}
```

---

## Testing

`test/silent_payments_test.exs`, driven by the BIP-352 vendored vectors
(`bip-0352/send_and_receive_test_vectors.json`):

- **Sending** vectors → `sum_input_privkeys` + `input_hash` + `create_output_pubkey`;
  assert the derived x-only outputs match the expected set (size `n_outputs`).
- **Receiving** vectors → `sum_input_pubkeys` + `input_hash` + `scan_output` loop, plus
  label matching via `output_label_candidates`; then `spending_privkey` and check
  `priv_key_tweak` / `pub_key` / `signature` per vector. Include the labels-used and
  change-label (`m = 0`) cases.
- **Address** vectors → `encode_address` / `decode_address` round-trip, including labeled
  addresses; plus the v0/v1–v30/v31 length rules.
- Edge-case vectors: zero private-key sum, point-at-infinity `A`, intermediate-sum-zero
  (v1.1.1), and `t_k`/`input_hash` out-of-range.
- `stream_data` round-trip properties for the address codec.

Run `mix format` and `mix lint.all` (compile is warnings-as-errors).
