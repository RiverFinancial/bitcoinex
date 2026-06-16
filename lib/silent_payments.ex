defmodule Bitcoinex.SilentPayments do
  @moduledoc """
  Cryptographic primitives for BIP-352 Silent Payments.

  https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

  This module implements the key-derivation math a Silent Payments wallet or
  scanner builds on. It is intentionally **lean**: it does not select coins,
  parse transactions, extract input public keys from scriptSigs/witnesses,
  choose the lexicographically smallest outpoint, or drive the scan loop. The
  caller owns the transaction and supplies the already-summed keys, the chosen
  `outpoint_L`, and the output index `k`.

  All public functions return `{:ok, value}` or `{:error, reason}`.

  ## Notation

  Uppercase = public keys (`Point`), lowercase = private keys (`PrivateKey`),
  `·` = EC scalar multiplication, `G` = generator, `n` = curve order.

  The protocol uses three BIP-340 tagged hashes:

    * `BIP0352/Inputs`       — `input_hash/2`
    * `BIP0352/SharedSecret` — `shared_secret_tweak/2` (`t_k`)
    * `BIP0352/Label`        — `label_tweak/2`

  ## Pipeline

      # sender computes the per-output taproot key (see Bitcoinex.SilentPayments later PRs)
      {:ok, ih} = input_hash(outpoint_l, a_pub_sum)
      {:ok, ecdh} = shared_secret(a_priv_sum, b_scan, ih)
      {:ok, t_k} = shared_secret_tweak(ecdh, 0)
      # P_0 = B_spend + t_k·G
  """

  alias Bitcoinex.{Bech32, Utils}
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}

  @n Params.curve().n
  @sp_version 0

  @input_tag "BIP0352/Inputs"
  @shared_secret_tag "BIP0352/SharedSecret"
  @label_tag "BIP0352/Label"

  @typedoc "A 36-byte outpoint: 32-byte txid (little-endian) followed by a 4-byte vout (little-endian)."
  @type outpoint :: <<_::288>>

  @doc """
  input_hash computes `hash_BIP0352/Inputs(outpoint_L || ser_P(A))` as a 32-byte scalar.

  `outpoint_L` is the lexicographically smallest 36-byte outpoint among the
  transaction's inputs (the caller selects it, e.g. with `Enum.min/1`). `A` is
  the sum of the input public keys.

  Fails if the resulting value is not a valid scalar (`0` or `>= n`).
  """
  @spec input_hash(outpoint(), Point.t()) :: {:ok, <<_::256>>} | {:error, String.t()}
  def input_hash(<<outpoint::binary-size(36)>>, %Point{} = a_sum_pubkey) do
    hash = Utils.tagged_hash(@input_tag, outpoint <> Point.sec(a_sum_pubkey))

    if valid_scalar?(hash) do
      {:ok, hash}
    else
      {:error, "input_hash is not a valid scalar"}
    end
  end

  def input_hash(_, _), do: {:error, "outpoint must be 36 bytes"}

  @doc """
  shared_secret computes the ECDH point `input_hash · scalar · point`.

    * sender passes `(a_sum_privkey, B_scan, input_hash)`
    * receiver passes `(b_scan_privkey, A, input_hash)`

  `input_hash` must be a pre-validated 32-byte scalar (as produced by
  `input_hash/2`). Both parties arrive at the same point. Fails if the result is
  the point at infinity (or the effective scalar reduces to zero).
  """
  @spec shared_secret(PrivateKey.t(), Point.t(), <<_::256>>) ::
          {:ok, Point.t()} | {:error, String.t()}
  def shared_secret(%PrivateKey{d: d}, %Point{} = point, <<input_hash::binary-size(32)>>) do
    scalar = Math.modulo(d * :binary.decode_unsigned(input_hash), @n)

    if scalar == 0 do
      {:error, "shared secret scalar is zero"}
    else
      secret = Math.multiply(point, scalar)

      if Point.is_inf(secret) do
        {:error, "shared secret is the point at infinity"}
      else
        {:ok, secret}
      end
    end
  end

  @doc """
  shared_secret_tweak computes the per-output tweak
  `t_k = hash_BIP0352/SharedSecret(ser_P(ecdh_secret) || ser_32(k))`.

  Fails if `t_k` is not a valid scalar (`0` or `>= n`).
  """
  @spec shared_secret_tweak(Point.t(), non_neg_integer()) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def shared_secret_tweak(%Point{} = ecdh_secret, k) when is_integer(k) and k >= 0 do
    tweak =
      Utils.tagged_hash(@shared_secret_tag, Point.sec(ecdh_secret) <> Utils.int_to_big(k, 4))

    if valid_scalar?(tweak) do
      PrivateKey.new(:binary.decode_unsigned(tweak))
    else
      {:error, "shared secret tweak t_k is not a valid scalar"}
    end
  end

  @doc """
  sum_input_privkeys sums the input private keys into the aggregate spend key `a`.

  Taproot keys (first argument) are negated to their even-Y form before summing,
  per BIP-352; all other eligible keys (second argument) are summed as-is. The
  sum is taken mod `n`, so an intermediate sum of zero is fine — only the final
  sum being zero is an error (and means no outputs can be produced).
  """
  @spec sum_input_privkeys([PrivateKey.t()], [PrivateKey.t()]) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def sum_input_privkeys(taproot, other) when is_list(taproot) and is_list(other) do
    with {:ok, taproot_even} <- force_even_all(taproot) do
      case taproot_even ++ other do
        [] ->
          {:error, "no input private keys"}

        keys ->
          sum =
            keys |> Enum.reduce(0, fn %PrivateKey{d: d}, acc -> acc + d end) |> Math.modulo(@n)

          if sum == 0 do
            {:error, "input private key sum is zero"}
          else
            PrivateKey.new(sum)
          end
      end
    end
  end

  @doc """
  sum_input_pubkeys sums the input public keys into the aggregate `A`.

  Taproot inputs are supplied as 32-byte x-only keys (first argument) and lifted
  to their even-Y point; all other eligible inputs are supplied as `Point`s
  (second argument). Addition is commutative, so input order does not matter. An
  intermediate point at infinity is fine — only the final sum being the point at
  infinity is an error (and means the transaction is skipped).
  """
  @spec sum_input_pubkeys([<<_::256>>], [Point.t()]) :: {:ok, Point.t()} | {:error, String.t()}
  def sum_input_pubkeys(taproot_xonly, other) when is_list(taproot_xonly) and is_list(other) do
    with {:ok, taproot_points} <- lift_all(taproot_xonly) do
      case taproot_points ++ other do
        [] ->
          {:error, "no input public keys"}

        [first | rest] ->
          sum = Enum.reduce(rest, first, fn p, acc -> Math.add(acc, p) end)

          if Point.is_inf(sum) do
            {:error, "input public key sum is the point at infinity"}
          else
            {:ok, sum}
          end
      end
    end
  end

  @doc """
  label_tweak computes the label scalar
  `hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))`.

  `b_scan` is the receiver's scan **private** key. `m` is the label integer
  (`m = 0` is reserved for the change label). Fails if the tweak is not a valid
  scalar.
  """
  @spec label_tweak(PrivateKey.t(), non_neg_integer()) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def label_tweak(%PrivateKey{d: b_scan}, m) when is_integer(m) and m >= 0 do
    tweak = Utils.tagged_hash(@label_tag, Utils.int_to_big(b_scan, 32) <> Utils.int_to_big(m, 4))

    if valid_scalar?(tweak) do
      PrivateKey.new(:binary.decode_unsigned(tweak))
    else
      {:error, "label tweak is not a valid scalar"}
    end
  end

  @doc """
  label_point computes the label point `label_tweak(m)·G`.

  This is what a scanner precomputes and stores (keyed by `m`) to recognize
  labeled outputs. Always include `m = 0` (the change label) when scanning.
  """
  @spec label_point(PrivateKey.t(), non_neg_integer()) :: {:ok, Point.t()} | {:error, String.t()}
  def label_point(%PrivateKey{} = b_scan, m) do
    with {:ok, tweak} <- label_tweak(b_scan, m) do
      {:ok, PrivateKey.to_point(tweak)}
    end
  end

  @doc """
  create_output_pubkey derives a single silent payment taproot output key for a recipient
  (sender side).

  Needs both recipient public keys: `b_scan` (for ECDH) and `b_spend` (added in). `k` is the
  output index within the recipient group. Returns `P_k = B_spend + t_k·G`; take
  `Bitcoinex.Secp256k1.Point.x_bytes/1` of it for the x-only taproot output key.
  """
  @spec create_output_pubkey(
          PrivateKey.t(),
          Point.t(),
          Point.t(),
          <<_::256>>,
          non_neg_integer()
        ) :: {:ok, Point.t()} | {:error, String.t()}
  def create_output_pubkey(
        %PrivateKey{} = a_sum,
        %Point{} = b_scan,
        %Point{} = b_spend,
        <<input_hash::binary-size(32)>>,
        k
      ) do
    with {:ok, ecdh} <- shared_secret(a_sum, b_scan, input_hash),
         {:ok, {_t_k, p_k}} <- derive_output(ecdh, b_spend, k) do
      {:ok, p_k}
    end
  end

  def create_output_pubkey(_a_sum, _b_scan, _b_spend, _input_hash, _k),
    do: {:error, "input_hash must be 32 bytes"}

  @doc """
  scan_output derives the per-output tweak and candidate output point for index `k`
  (receiver side).

  Returns `{t_k, P_k}`. The caller compares `Point.x_bytes(p_k)` against the transaction's
  taproot outputs; on a direct hit the output is spendable with `spending_privkey(b_spend,
  t_k, nil)`. With no direct hit, the caller checks labels via `output_label_candidates/2`.
  The caller drives the `k` loop, incrementing on each match.
  """
  @spec scan_output(PrivateKey.t(), Point.t(), Point.t(), <<_::256>>, non_neg_integer()) ::
          {:ok, {PrivateKey.t(), Point.t()}} | {:error, String.t()}
  def scan_output(
        %PrivateKey{} = b_scan,
        %Point{} = a_sum,
        %Point{} = b_spend,
        <<input_hash::binary-size(32)>>,
        k
      ) do
    with {:ok, ecdh} <- shared_secret(b_scan, a_sum, input_hash) do
      derive_output(ecdh, b_spend, k)
    end
  end

  def scan_output(_b_scan, _a_sum, _b_spend, _input_hash, _k),
    do: {:error, "input_hash must be 32 bytes"}

  @doc """
  spending_privkey derives the private key `d` for a found silent payment output:
  `d = (b_spend + t_k + label_tweak?) mod n`.

  Pass the label tweak (from `label_tweak/2`) when the output matched a label, or `nil` for
  an unlabeled output. The BIP341 output is then spent with `d` (the signer negates to
  even-Y as usual).
  """
  @spec spending_privkey(PrivateKey.t(), PrivateKey.t(), PrivateKey.t() | nil) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def spending_privkey(b_spend, t_k, label \\ nil)

  def spending_privkey(%PrivateKey{d: b_spend}, %PrivateKey{d: t_k}, label) do
    label_d =
      case label do
        nil -> 0
        %PrivateKey{d: d} -> d
      end

    case Math.modulo(b_spend + t_k + label_d, @n) do
      0 -> {:error, "spending private key is zero"}
      d -> PrivateKey.new(d)
    end
  end

  @doc """
  create_labeled_spend_pubkey computes the labeled spend public key
  `B_m = B_spend + label_point(m)` to publish in a labeled silent payment address.

  `m = 0` is the reserved change label and MUST NOT be handed out as a receive address.
  """
  @spec create_labeled_spend_pubkey(Point.t(), PrivateKey.t(), non_neg_integer()) ::
          {:ok, Point.t()} | {:error, String.t()}
  def create_labeled_spend_pubkey(%Point{} = b_spend, %PrivateKey{} = b_scan, m) do
    with {:ok, label_point} <- label_point(b_scan, m) do
      sum = Math.add(b_spend, label_point)

      if Point.is_inf(sum) do
        {:error, "labeled spend pubkey is the point at infinity"}
      else
        {:ok, sum}
      end
    end
  end

  @doc """
  output_label_candidates returns the candidate label points for an unmatched taproot output.

  Given the `p_k` from `scan_output/5` and an x-only `output` that did not match `p_k`
  directly, returns `[output - p_k, -output - p_k]` (both parities of the output point, per
  BIP-352's "negate output and check a second time"). The caller looks each candidate up in
  its precomputed `label_point ⇒ m` table; a hit means the output is the labeled payment
  `p_k + candidate`, spendable with `spending_privkey(b_spend, t_k, label_tweak(b_scan, m))`.
  """
  @spec output_label_candidates(Point.t(), <<_::256>>) ::
          {:ok, [Point.t()]} | {:error, String.t()}
  def output_label_candidates(%Point{} = p_k, <<output::binary-size(32)>>) do
    with {:ok, even_pt} <- Point.lift_x(output) do
      odd_pt = Point.negate(even_pt)
      {:ok, [subtract(even_pt, p_k), subtract(odd_pt, p_k)]}
    end
  end

  def output_label_candidates(%Point{}, _output), do: {:error, "output must be 32 bytes"}

  @doc """
  encode_address encodes a silent payment address.

  It is the Bech32m encoding of silent-payment version 0 followed by
  `ser_P(B_scan) || ser_P(B_m)` (66 bytes). The HRP is `sp` for `:mainnet` and `tsp` for
  `:testnet`/`:regtest`. `b_m` is the (possibly labeled) spend public key — pass `B_spend`
  for an unlabeled address or the output of `create_labeled_spend_pubkey/3` for a labeled one.
  """
  @spec encode_address(Point.t(), Point.t(), Bitcoinex.Network.network_name()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_address(%Point{} = b_scan, %Point{} = b_m, network) do
    with {:ok, hrp} <- hrp_for(network),
         payload = :binary.bin_to_list(Point.sec(b_scan) <> Point.sec(b_m)),
         {:ok, data} <- Bech32.convert_bits(payload, 8, 5),
         {:ok, address} <- Bech32.encode(hrp, [@sp_version | data], :bech32m, :infinity) do
      {:ok, address}
    else
      {:error, reason} -> {:error, normalize_error(reason)}
    end
  end

  @doc """
  decode_address decodes a silent payment address into `{network, version, B_scan, B_m}`.

  Per BIP-352, a v0 address must carry exactly 66 payload bytes; v1–v30 read the first 66
  bytes and ignore the rest (forward compatibility); v31 is rejected.
  """
  @spec decode_address(String.t()) ::
          {:ok, {Bitcoinex.Network.network_name(), non_neg_integer(), Point.t(), Point.t()}}
          | {:error, String.t()}
  def decode_address(address) when is_binary(address) do
    with {:ok, {hrp, data}} <- decode_bech32m(address),
         {:ok, network} <- network_for(hrp),
         {:ok, {version, payload}} <- parse_sp_data(data),
         {:ok, {b_scan, b_m}} <- parse_address_keys(payload) do
      {:ok, {network, version, b_scan, b_m}}
    end
  end

  # A 32-byte hash is a valid secp256k1 scalar when it is neither 0 nor >= n.
  # Note: PrivateKey.new/1 only rejects d >= n, so this guard is what enforces
  # the non-zero requirement before the callers build a PrivateKey from the hash.
  defp valid_scalar?(<<bytes::binary-size(32)>>) do
    i = :binary.decode_unsigned(bytes)
    i != 0 and i < @n
  end

  # Negate each taproot private key to its even-Y form. Short-circuits on error.
  defp force_even_all(keys) do
    keys
    |> Enum.reduce_while({:ok, []}, fn key, {:ok, acc} ->
      case Secp256k1.force_even_y(key) do
        %PrivateKey{} = k -> {:cont, {:ok, [k | acc]}}
        {:error, msg} -> {:halt, {:error, msg}}
      end
    end)
    |> case do
      {:ok, ks} -> {:ok, Enum.reverse(ks)}
      err -> err
    end
  end

  # Lift each 32-byte x-only key to its even-Y point. Short-circuits on error.
  defp lift_all(xonly_keys) do
    xonly_keys
    |> Enum.reduce_while({:ok, []}, fn xonly, {:ok, acc} ->
      case Point.lift_x(xonly) do
        {:ok, point} -> {:cont, {:ok, [point | acc]}}
        {:error, msg} -> {:halt, {:error, msg}}
      end
    end)
    |> case do
      {:ok, points} -> {:ok, Enum.reverse(points)}
      err -> err
    end
  end

  # Shared by create_output_pubkey and scan_output: derive t_k, then P_k = B_spend + t_k·G.
  defp derive_output(ecdh, b_spend, k) do
    with {:ok, t_k} <- shared_secret_tweak(ecdh, k),
         {:ok, p_k} <- add_tweak(b_spend, t_k) do
      {:ok, {t_k, p_k}}
    end
  end

  # base + tweak·G, rejecting the (astronomically unlikely) point at infinity.
  defp add_tweak(%Point{} = base, %PrivateKey{} = tweak) do
    sum = Math.add(base, PrivateKey.to_point(tweak))

    if Point.is_inf(sum) do
      {:error, "output is the point at infinity"}
    else
      {:ok, sum}
    end
  end

  # P - Q = P + (-Q)
  defp subtract(p, q), do: Math.add(p, Point.negate(q))

  defp decode_bech32m(address) do
    case Bech32.decode(address, :infinity) do
      {:ok, {:bech32m, hrp, data}} -> {:ok, {hrp, data}}
      {:ok, {:bech32, _hrp, _data}} -> {:error, "silent payment address must be bech32m"}
      {:error, reason} -> {:error, normalize_error(reason)}
    end
  end

  defp parse_sp_data([]), do: {:error, "empty silent payment data"}

  defp parse_sp_data([31 | _rest]), do: {:error, "silent payment version 31 is not supported"}

  defp parse_sp_data([version | rest]) when version in 0..30 do
    # convert_bits(_, 5, 8, padding: false) requires the trailing bech32 bits to be valid
    # zero-padding, so a malformed data part is rejected here. This matches the BIP-352
    # reference (and Segwit) decoding; future SP versions still carry byte-aligned payloads.
    case Bech32.convert_bits(rest, 5, 8, false) do
      {:ok, bytes} ->
        payload = :erlang.list_to_binary(bytes)

        cond do
          version == 0 and byte_size(payload) != 66 ->
            {:error, "v0 silent payment address must have a 66-byte payload"}

          byte_size(payload) < 66 ->
            {:error, "silent payment payload too short"}

          true ->
            {:ok, {version, binary_part(payload, 0, 66)}}
        end

      {:error, reason} ->
        {:error, normalize_error(reason)}
    end
  end

  defp parse_sp_data(_), do: {:error, "invalid silent payment version"}

  defp parse_address_keys(<<scan::binary-size(33), spend::binary-size(33)>>) do
    with {:ok, b_scan} <- Point.parse_public_key(scan),
         {:ok, b_m} <- Point.parse_public_key(spend) do
      {:ok, {b_scan, b_m}}
    end
  end

  defp hrp_for(:mainnet), do: {:ok, "sp"}
  defp hrp_for(network) when network in [:testnet, :regtest], do: {:ok, "tsp"}
  defp hrp_for(_), do: {:error, "unsupported network for silent payments"}

  defp network_for("sp"), do: {:ok, :mainnet}
  defp network_for("tsp"), do: {:ok, :testnet}
  defp network_for(_), do: {:error, "unrecognized silent payment HRP"}

  defp normalize_error(reason) when is_binary(reason), do: reason
  defp normalize_error(reason), do: inspect(reason)
end
