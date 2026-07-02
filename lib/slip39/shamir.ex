defmodule Bitcoinex.SLIP39.Shamir do
  @moduledoc """
  SLIP-39 Shamir Secret Sharing over GF(256).

  A secret of `n` bytes is split into `count` shares such that any
  `threshold` of them reconstruct it, per SLIP-0039:

  - Each share is a point `{x, y}` where `x` is the share index and `y` is an
    `n`-byte binary; interpolation runs independently per byte lane.
  - The shared polynomial is anchored at two reserved indices: the secret at
    `x = 255` and a digest share at `x = 254`. The digest share is
    `HMAC-SHA256(random_part, secret)` truncated to its first 4 bytes,
    concatenated with the `n - 4`-byte `random_part`. On recovery the digest
    is recomputed and verified, rejecting wrong or insufficient share sets
    with `{:error, :invalid_digest}` (false-accept probability ~2^-32).
  - `threshold == 1` is a special case: every share is the secret verbatim.

  Randomness is injected via an `rng` function (`byte_count -> binary`).
  Production callers MUST pass a CSPRNG such as `&:crypto.strong_rand_bytes/1`;
  a deterministic rng is intended only for tests.
  """

  alias Bitcoinex.SLIP39.GF256

  @digest_length_bytes 4
  @digest_index 254
  @secret_index 255
  @max_share_count 16

  @doc """
  Splits `secret` into `count` shares recoverable from any `threshold` of them.

  Returns a list of `{index, share_value}` points with indices `0..count-1`.
  When `threshold == 1`, every share equals `secret`. Otherwise
  `threshold - 2` random base shares are drawn from `rng`, the digest and
  secret anchor points are placed at indices 254 and 255, and the remaining
  share indices are interpolated from those `threshold` points.

  ## Examples

      iex> rng = fn byte_count -> :binary.copy(<<7>>, byte_count) end
      iex> secret = :binary.copy(<<42>>, 16)
      iex> shares = Bitcoinex.SLIP39.Shamir.split_secret(2, 3, secret, rng)
      iex> {:ok, recovered} = Bitcoinex.SLIP39.Shamir.recover_secret(2, Enum.take(shares, 2))
      iex> recovered == secret
      true
  """
  @spec split_secret(1..16, 1..16, binary(), (pos_integer() -> binary())) :: [{byte(), binary()}]
  def split_secret(1, count, secret, _rng) when count in 1..@max_share_count do
    for i <- 0..(count - 1), do: {i, secret}
  end

  # count is capped so share indices can never collide with the digest (254)
  # and secret (255) anchor indices; an uncapped count would emit the secret
  # verbatim as the share at index 255
  def split_secret(threshold, count, secret, rng)
      when threshold >= 2 and threshold <= count and count <= @max_share_count do
    random_share_count = threshold - 2

    base_shares =
      for i <- 0..(random_share_count - 1)//1 do
        {i, rng.(byte_size(secret))}
      end

    random_part = rng.(byte_size(secret) - @digest_length_bytes)
    digest = create_digest(random_part, secret)

    anchor_points =
      base_shares ++ [{@digest_index, digest}, {@secret_index, secret}]

    interpolated_shares =
      for i <- random_share_count..(count - 1)//1 do
        {i, GF256.interpolate(anchor_points, i)}
      end

    base_shares ++ interpolated_shares
  end

  @doc """
  Recovers the secret from `shares` (a list of `{index, share_value}` points).

  When `threshold == 1` the single share's value is the secret. Otherwise the
  secret (index 255) and digest share (index 254) are interpolated from the
  given points and the digest is verified; a wrong, corrupted, or
  under-threshold share set yields `{:error, :invalid_digest}`. Share
  indices must be distinct; duplicates yield
  `{:error, :duplicate_share_indices}`.
  """
  @spec recover_secret(1..16, [{byte(), binary()}]) ::
          {:ok, binary()} | {:error, :invalid_digest | :duplicate_share_indices}
  def recover_secret(1, [{_index, value} | _rest]), do: {:ok, value}

  def recover_secret(threshold, shares) when threshold >= 2 do
    indices = Enum.map(shares, fn {index, _value} -> index end)

    if indices == Enum.uniq(indices) do
      secret = GF256.interpolate(shares, @secret_index)
      digest_share = GF256.interpolate(shares, @digest_index)

      if valid_digest?(digest_share, secret) do
        {:ok, secret}
      else
        {:error, :invalid_digest}
      end
    else
      {:error, :duplicate_share_indices}
    end
  end

  @doc """
  Builds the digest share for `shared_secret`: the first
  #{@digest_length_bytes} bytes of `HMAC-SHA256(random, shared_secret)`
  concatenated with `random`.

  ## Examples

      iex> digest = Bitcoinex.SLIP39.Shamir.create_digest(<<1, 2, 3>>, <<4, 5, 6, 7>>)
      iex> Bitcoinex.SLIP39.Shamir.valid_digest?(digest, <<4, 5, 6, 7>>)
      true
  """
  @spec create_digest(binary(), binary()) :: binary()
  def create_digest(random, shared_secret) do
    <<digest::binary-size(@digest_length_bytes), _rest::binary>> =
      :crypto.mac(:hmac, :sha256, random, shared_secret)

    digest <> random
  end

  @doc """
  Verifies that `digest_share` is the digest share of `shared_secret`, i.e.
  that its leading #{@digest_length_bytes} bytes match the HMAC-SHA256 of
  `shared_secret` keyed with the trailing random part.
  """
  @spec valid_digest?(binary(), binary()) :: boolean()
  def valid_digest?(digest_share, shared_secret) do
    <<_digest::binary-size(@digest_length_bytes), random::binary>> = digest_share
    create_digest(random, shared_secret) == digest_share
  end
end
