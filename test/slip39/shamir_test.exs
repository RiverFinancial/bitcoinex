defmodule Bitcoinex.SLIP39.ShamirTest do
  use ExUnit.Case
  use ExUnitProperties

  import Bitwise

  alias Bitcoinex.SLIP39.Shamir

  doctest Bitcoinex.SLIP39.Shamir

  @secret_16 Base.decode16!("0ff784df000c4380a5ed683491a8b87f", case: :lower)
  @secret_32 Base.decode16!(
               "989baf9dcaad5b10a5eec78afcaf0a1cc762c9e3d7cadef8aac343109fd90c69",
               case: :lower
             )

  # Deterministic rng stub: a counter-keyed SHA-256 stream. Every call
  # produces different (but reproducible) bytes; no CSPRNG is used in tests.
  defp make_rng(seed) do
    counter = :atomics.new(1, signed: false)

    fn byte_count ->
      call_index = :atomics.add_get(counter, 1, 1)
      expand_bytes(<<seed::unsigned-64, call_index::unsigned-64>>, byte_count, <<>>)
    end
  end

  defp expand_bytes(_key, byte_count, acc) when byte_size(acc) >= byte_count,
    do: binary_part(acc, 0, byte_count)

  defp expand_bytes(key, byte_count, acc) do
    block = :crypto.hash(:sha256, [key, <<byte_size(acc)::unsigned-32>>])
    expand_bytes(key, byte_count, acc <> block)
  end

  defp combinations(_list, 0), do: [[]]
  defp combinations([], _k), do: []

  defp combinations([head | tail], k) do
    for(combo <- combinations(tail, k - 1), do: [head | combo]) ++ combinations(tail, k)
  end

  defp corrupt_byte({index, value}, byte_position, xor_value) do
    <<prefix::binary-size(byte_position), byte, suffix::binary>> = value
    {index, <<prefix::binary, bxor(byte, xor_value), suffix::binary>>}
  end

  # Deterministic random T-subset of 0..count-1: shuffle by a hash keyed on
  # subset_seed and take the first `threshold` indices. Avoids
  # StreamData.uniq_list_of/2, which exhausts when threshold is close to count.
  defp subset_indices(count, threshold, subset_seed) do
    0..(count - 1)
    |> Enum.sort_by(&:erlang.phash2({subset_seed, &1}))
    |> Enum.take(threshold)
  end

  describe "split_secret/4 with threshold == 1" do
    test "all shares equal the secret" do
      rng = make_rng(1)

      for count <- [1, 3, 16] do
        shares = Shamir.split_secret(1, count, @secret_16, rng)
        assert length(shares) == count
        assert shares == Enum.map(0..(count - 1), &{&1, @secret_16})
      end
    end

    test "recover_secret/2 with threshold 1 returns the share value" do
      assert Shamir.recover_secret(1, [{0, @secret_16}]) == {:ok, @secret_16}
      assert Shamir.recover_secret(1, [{5, @secret_32}]) == {:ok, @secret_32}
    end
  end

  describe "split/recover round-trip" do
    test "recovers from every T-subset for (2,3), (3,5), (2,2), (16,16), 16- and 32-byte secrets" do
      for {threshold, count} <- [{2, 3}, {3, 5}, {2, 2}, {16, 16}],
          secret <- [@secret_16, @secret_32] do
        rng = make_rng(threshold * 100 + count)
        shares = Shamir.split_secret(threshold, count, secret, rng)

        assert length(shares) == count
        assert Enum.map(shares, &elem(&1, 0)) == Enum.to_list(0..(count - 1))
        assert Enum.all?(shares, fn {_i, value} -> byte_size(value) == byte_size(secret) end)

        for subset <- combinations(shares, threshold) do
          assert Shamir.recover_secret(threshold, subset) == {:ok, secret},
                 "failed for (#{threshold},#{count}) subset #{inspect(Enum.map(subset, &elem(&1, 0)))}"
        end
      end
    end

    test "recovery is independent of share order" do
      rng = make_rng(7)
      shares = Shamir.split_secret(3, 5, @secret_16, rng)
      subset = shares |> Enum.take(3) |> Enum.reverse()
      assert Shamir.recover_secret(3, subset) == {:ok, @secret_16}
    end
  end

  describe "recover_secret/2 failure modes" do
    test "fewer than threshold shares -> {:error, :invalid_digest}" do
      rng = make_rng(11)
      shares = Shamir.split_secret(3, 5, @secret_16, rng)

      for subset <- combinations(shares, 2) do
        assert Shamir.recover_secret(3, subset) == {:error, :invalid_digest}
      end
    end

    test "one corrupted share byte -> {:error, :invalid_digest}" do
      rng = make_rng(13)
      shares = Shamir.split_secret(2, 3, @secret_16, rng)
      [good, bad | _] = shares

      corrupted = corrupt_byte(bad, 0, 0x01)
      assert Shamir.recover_secret(2, [good, corrupted]) == {:error, :invalid_digest}

      corrupted = corrupt_byte(bad, 15, 0x80)
      assert Shamir.recover_secret(2, [good, corrupted]) == {:error, :invalid_digest}
    end

    test "shares from different splits -> {:error, :invalid_digest}" do
      shares_a = Shamir.split_secret(2, 3, @secret_16, make_rng(17))
      shares_b = Shamir.split_secret(2, 3, @secret_32 |> binary_part(0, 16), make_rng(19))

      assert Shamir.recover_secret(2, [Enum.at(shares_a, 0), Enum.at(shares_b, 1)]) ==
               {:error, :invalid_digest}
    end
  end

  describe "create_digest/2 and valid_digest?/2" do
    test "a created digest validates against its secret" do
      random_part = make_rng(23).(12)
      digest = Shamir.create_digest(random_part, @secret_16)

      assert byte_size(digest) == 4 + byte_size(random_part)
      assert <<_hmac_prefix::binary-size(4), ^random_part::binary>> = digest
      assert Shamir.valid_digest?(digest, @secret_16)
    end

    test "digest matches HMAC-SHA256(random, secret) truncated to 4 bytes" do
      random_part = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>

      <<expected::binary-size(4), _::binary>> =
        :crypto.mac(:hmac, :sha256, random_part, @secret_16)

      assert Shamir.create_digest(random_part, @secret_16) == expected <> random_part
    end

    test "tampered secret fails validation" do
      random_part = make_rng(29).(12)
      digest = Shamir.create_digest(random_part, @secret_16)

      <<first, rest::binary>> = @secret_16
      tampered_secret = <<bxor(first, 0xFF), rest::binary>>
      refute Shamir.valid_digest?(digest, tampered_secret)
    end

    test "tampered digest share fails validation" do
      random_part = make_rng(31).(12)
      digest = Shamir.create_digest(random_part, @secret_16)

      {_, tampered} = corrupt_byte({0, digest}, 2, 0x10)
      refute Shamir.valid_digest?(tampered, @secret_16)
    end
  end

  describe "properties" do
    property "any T-subset of N shares recovers the secret" do
      check all(
              secret_length <- member_of([16, 32]),
              secret <- binary(length: secret_length),
              threshold <- integer(2..16),
              count <- integer(threshold..16),
              seed <- integer(0..0xFFFF_FFFF),
              subset_seed <- integer(0..0xFFFF_FFFF)
            ) do
        rng = make_rng(seed)
        shares = Shamir.split_secret(threshold, count, secret, rng)

        subset =
          Enum.map(subset_indices(count, threshold, subset_seed), &Enum.at(shares, &1))

        assert Shamir.recover_secret(threshold, subset) == {:ok, secret}
      end
    end

    property "corrupting one byte of one share in the subset -> {:error, :invalid_digest}" do
      check all(
              secret_length <- member_of([16, 32]),
              secret <- binary(length: secret_length),
              threshold <- integer(2..16),
              count <- integer(threshold..16),
              seed <- integer(0..0xFFFF_FFFF),
              subset_seed <- integer(0..0xFFFF_FFFF),
              corrupt_position <- integer(0..(threshold - 1)),
              byte_position <- integer(0..(secret_length - 1)),
              xor_value <- integer(1..255)
            ) do
        rng = make_rng(seed)
        shares = Shamir.split_secret(threshold, count, secret, rng)

        subset =
          Enum.map(subset_indices(count, threshold, subset_seed), &Enum.at(shares, &1))

        corrupted = corrupt_byte(Enum.at(subset, corrupt_position), byte_position, xor_value)
        subset = List.replace_at(subset, corrupt_position, corrupted)

        assert Shamir.recover_secret(threshold, subset) == {:error, :invalid_digest}
      end
    end
  end
end
