defmodule Bitcoinex.SLIP39 do
  @moduledoc """
  SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes.

  Splits a master secret into a two-level hierarchy of mnemonic shares and
  recombines them. The master secret is first encrypted under a passphrase
  (`Bitcoinex.SLIP39.Cipher`), then split into group shares, each of which is
  split into member shares (`Bitcoinex.SLIP39.Shamir`); each member share is
  encoded as a mnemonic (`Bitcoinex.SLIP39.Share`). Recovering the master
  secret requires exactly `group_threshold` groups, each contributing exactly
  its member threshold of shares.

  Note that SLIP-39 offers plausible deniability: combining a valid share set
  with a wrong passphrase does not fail, it silently yields a different
  master secret. The caller is responsible for passphrase correctness.

  Elixir binaries are immutable and garbage-collected, so this library cannot
  guarantee zeroization of secrets or passphrases in memory.

  ## Examples

      iex> rng = fn byte_count -> :binary.copy(<<7>>, byte_count) end
      iex> master_secret = :binary.copy(<<0xAB>>, 16)
      iex> {:ok, [[share_a, share_b, _share_c]]} =
      ...>   Bitcoinex.SLIP39.generate_mnemonics(1, [{2, 3}], master_secret, rng: rng)
      iex> {:ok, recovered} = Bitcoinex.SLIP39.combine_mnemonics([share_a, share_b])
      iex> recovered == master_secret
      true
  """

  alias Bitcoinex.SLIP39.{Cipher, Shamir, Share}

  @id_length_bits 15
  @max_share_count 16
  @min_strength_bits 128
  @min_strength_bytes div(@min_strength_bits, 8)

  @typedoc """
  A group specification: `{member_threshold, member_count}`. The group is
  split into `member_count` shares, any `member_threshold` of which recover
  the group share.
  """
  @type group_spec :: {member_threshold :: 1..16, member_count :: 1..16}

  @doc """
  generate_mnemonics splits `master_secret` into SLIP-39 mnemonic shares.

  The secret is split into `length(groups)` group shares, any
  `group_threshold` of which recover it; each group `i` is split into member
  shares per its `{member_threshold, member_count}` spec. Returns
  `{:ok, groups_of_mnemonics}` where the i-th element is the list of mnemonic
  strings for the i-th group spec.

  Options:

  - `:passphrase` (default `""`) — printable-ASCII encryption passphrase.
  - `:extendable` (default `true`) — whether the share set is extendable
    (the identifier is then not used as an encryption salt).
  - `:iteration_exponent` (default `0`) — PBKDF2 cost, `2500 <<< e` per round.
  - `:rng` (default `&:crypto.strong_rand_bytes/1`) — randomness source,
    `byte_count -> binary`. Injectable ONLY for deterministic tests;
    production callers must use a CSPRNG.
  - `:identifier` (default `nil`) — 15-bit share-set identifier; drawn from
    `rng` when `nil`.

  Errors: `:invalid_secret_length` (must be at least 16 bytes and of even
  length), `:invalid_group_threshold` (requires
  `1 <= group_threshold <= length(groups) <= 16`),
  `:invalid_member_threshold` (each spec requires `1 <= t <= n <= 16` and
  forbids `t == 1` with `n > 1`), `:invalid_passphrase` (printable ASCII,
  code points 32-126, only), `:invalid_identifier` (integer in `0..0x7FFF`),
  `:invalid_iteration_exponent` (integer in `0..15`). The identifier and
  iteration exponent are range-checked because the wire format truncates
  them to 15 and 4 bits: unvalidated out-of-range values would encode
  shares whose recombination silently yields a different master secret.
  """
  @spec generate_mnemonics(1..16, [group_spec()], binary(), keyword()) ::
          {:ok, [[String.t()]]} | {:error, atom()}
  def generate_mnemonics(group_threshold, groups, master_secret, opts \\ []) do
    passphrase = Keyword.get(opts, :passphrase, "")
    extendable = Keyword.get(opts, :extendable, true)
    iteration_exponent = Keyword.get(opts, :iteration_exponent, 0)
    rng = Keyword.get(opts, :rng, &:crypto.strong_rand_bytes/1)

    with :ok <- validate_secret(master_secret),
         :ok <- validate_group_threshold(group_threshold, length(groups)),
         :ok <- validate_groups(groups),
         :ok <- validate_passphrase(passphrase),
         :ok <- validate_identifier(Keyword.get(opts, :identifier)),
         :ok <- validate_iteration_exponent(iteration_exponent) do
      identifier =
        case Keyword.get(opts, :identifier) do
          nil -> random_identifier(rng)
          identifier -> identifier
        end

      ems =
        Cipher.encrypt(master_secret, passphrase, iteration_exponent, identifier, extendable)

      mnemonics =
        group_threshold
        |> Shamir.split_secret(length(groups), ems, rng)
        |> Enum.zip(groups)
        |> Enum.map(fn {{group_index, group_value}, {member_threshold, member_count}} ->
          member_threshold
          |> Shamir.split_secret(member_count, group_value, rng)
          |> Enum.map(fn {member_index, share_value} ->
            Share.encode(%Share{
              identifier: identifier,
              extendable: extendable,
              iteration_exponent: iteration_exponent,
              group_index: group_index,
              group_threshold: group_threshold,
              group_count: length(groups),
              member_index: member_index,
              member_threshold: member_threshold,
              share_value: share_value
            })
          end)
        end)

      {:ok, mnemonics}
    end
  end

  @doc """
  combine_mnemonics recovers the master secret from SLIP-39 mnemonics.

  The share set must contain exactly `group_threshold` distinct groups, and
  each group must contribute exactly its member threshold of shares with
  distinct member indices.

  A wrong passphrase does not fail: it yields a different master secret
  (SLIP-39 plausible deniability), so the caller must verify the result.

  Errors: any `Bitcoinex.SLIP39.Share.decode/1` error (propagated as-is),
  `:invalid_passphrase`, `:empty_mnemonic_set`, `:mismatching_shares`
  (shares disagree on identifier, extendable flag, iteration exponent, group
  threshold, group count, share value length, or member threshold within a
  group), `:insufficient_groups`, `:too_many_groups`,
  `:insufficient_member_shares`, `:too_many_member_shares`,
  `:duplicate_member_index`, `:invalid_digest` (recovered share set is
  inconsistent or corrupted).
  """
  @spec combine_mnemonics([String.t()], binary()) :: {:ok, binary()} | {:error, atom()}
  def combine_mnemonics(mnemonics, passphrase \\ "") do
    with :ok <- validate_passphrase(passphrase),
         :ok <- validate_non_empty(mnemonics),
         {:ok, shares} <- decode_all(mnemonics),
         :ok <- validate_consistency(shares),
         share = hd(shares),
         {:ok, groups} <- collect_groups(shares, share.group_threshold),
         {:ok, group_points} <- recover_group_points(groups),
         {:ok, ems} <- Shamir.recover_secret(share.group_threshold, group_points) do
      {:ok,
       Cipher.decrypt(
         ems,
         passphrase,
         share.iteration_exponent,
         share.identifier,
         share.extendable
       )}
    end
  end

  defp validate_secret(master_secret)
       when is_binary(master_secret) and byte_size(master_secret) >= @min_strength_bytes and
              rem(byte_size(master_secret), 2) == 0,
       do: :ok

  defp validate_secret(_master_secret), do: {:error, :invalid_secret_length}

  defp validate_group_threshold(group_threshold, group_count)
       when group_threshold >= 1 and group_threshold <= group_count and
              group_count <= @max_share_count,
       do: :ok

  defp validate_group_threshold(_group_threshold, _group_count),
    do: {:error, :invalid_group_threshold}

  defp validate_groups(groups) do
    if Enum.all?(groups, &valid_group_spec?/1) do
      :ok
    else
      {:error, :invalid_member_threshold}
    end
  end

  # A member threshold of 1 with more than one share is forbidden: every
  # share would be the group secret verbatim, silently defeating sharing.
  defp valid_group_spec?({1, member_count}), do: member_count == 1

  defp valid_group_spec?({member_threshold, member_count}),
    do:
      member_threshold >= 1 and member_threshold <= member_count and
        member_count <= @max_share_count

  defp validate_passphrase(passphrase) when is_binary(passphrase) do
    if passphrase |> :binary.bin_to_list() |> Enum.all?(&(&1 in 32..126)) do
      :ok
    else
      {:error, :invalid_passphrase}
    end
  end

  # the wire format truncates the identifier to 15 bits and the iteration
  # exponent to 4 bits; out-of-range values would encrypt with parameters
  # that differ from the encoded ones, so recombination would silently
  # yield a different master secret
  defp validate_identifier(nil), do: :ok

  defp validate_identifier(identifier) when is_integer(identifier) and identifier in 0..0x7FFF,
    do: :ok

  defp validate_identifier(_identifier), do: {:error, :invalid_identifier}

  defp validate_iteration_exponent(e) when is_integer(e) and e in 0..15, do: :ok
  defp validate_iteration_exponent(_e), do: {:error, :invalid_iteration_exponent}

  defp validate_non_empty([]), do: {:error, :empty_mnemonic_set}
  defp validate_non_empty(_mnemonics), do: :ok

  defp random_identifier(rng) do
    <<identifier::size(@id_length_bits), _::1>> = rng.(2)
    identifier
  end

  defp decode_all(mnemonics) do
    Enum.reduce_while(mnemonics, {:ok, []}, fn mnemonic, {:ok, shares} ->
      case Share.decode(mnemonic) do
        {:ok, share} -> {:cont, {:ok, [share | shares]}}
        {:error, _reason} = err -> {:halt, err}
      end
    end)
  end

  defp validate_consistency(shares) do
    parameters =
      Enum.map(shares, fn share ->
        {share.identifier, share.extendable, share.iteration_exponent, share.group_threshold,
         share.group_count, byte_size(share.share_value)}
      end)

    case Enum.uniq(parameters) do
      [_common] -> :ok
      _mismatching -> {:error, :mismatching_shares}
    end
  end

  defp collect_groups(shares, group_threshold) do
    groups = Enum.group_by(shares, & &1.group_index)

    cond do
      map_size(groups) < group_threshold -> {:error, :insufficient_groups}
      map_size(groups) > group_threshold -> {:error, :too_many_groups}
      true -> validate_group_members(Map.values(groups), groups)
    end
  end

  defp validate_group_members([], groups), do: {:ok, groups}

  defp validate_group_members([members | rest], groups) do
    thresholds = members |> Enum.map(& &1.member_threshold) |> Enum.uniq()
    member_indices = Enum.map(members, & &1.member_index)
    member_count = length(members)

    cond do
      length(thresholds) > 1 -> {:error, :mismatching_shares}
      length(Enum.uniq(member_indices)) != member_count -> {:error, :duplicate_member_index}
      member_count < hd(thresholds) -> {:error, :insufficient_member_shares}
      member_count > hd(thresholds) -> {:error, :too_many_member_shares}
      true -> validate_group_members(rest, groups)
    end
  end

  defp recover_group_points(groups) do
    Enum.reduce_while(groups, {:ok, []}, fn {group_index, members}, {:ok, points} ->
      member_points = Enum.map(members, &{&1.member_index, &1.share_value})

      case Shamir.recover_secret(hd(members).member_threshold, member_points) do
        {:ok, group_value} -> {:cont, {:ok, [{group_index, group_value} | points]}}
        {:error, _reason} = err -> {:halt, err}
      end
    end)
  end
end
