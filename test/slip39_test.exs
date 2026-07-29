defmodule Bitcoinex.SLIP39Test do
  use ExUnit.Case
  use ExUnitProperties

  alias Bitcoinex.ExtendedKey
  alias Bitcoinex.SLIP39
  alias Bitcoinex.SLIP39.Encoding
  alias Bitcoinex.SLIP39.Share

  doctest Bitcoinex.SLIP39

  # Official SLIP-39 test vectors, byte-identical to
  # https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json
  # (sha256: 13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4).
  # Each vector is [description, mnemonics, master_secret_hex, xprv]; the 15
  # valid vectors have a non-empty master_secret_hex and use passphrase
  # "TREZOR"; the 30 invalid vectors have an empty master_secret_hex.
  @vectors_path Path.join(__DIR__, "data/slip39_vectors.json")
  @external_resource @vectors_path
  @vectors @vectors_path |> File.read!() |> JSON.decode!()

  @secret_16 Base.decode16!("4142434445464748494a4b4c4d4e4f50", case: :lower)
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

  # Maps each invalid official vector's description to the specific error
  # atom combine_mnemonics/2 must return for it.
  defp expected_error(description) do
    cond do
      description =~ "invalid checksum" -> :invalid_checksum
      description =~ "invalid padding" -> :invalid_padding
      description =~ "greater group threshold than group counts" -> :invalid_group_threshold
      description =~ "different identifiers" -> :mismatching_shares
      description =~ "different iteration exponents" -> :mismatching_shares
      description =~ "mismatching group thresholds" -> :mismatching_shares
      description =~ "mismatching group counts" -> :mismatching_shares
      description =~ "mismatching member thresholds" -> :mismatching_shares
      description =~ "duplicate member indices" -> :duplicate_member_index
      description =~ "invalid digest" -> :invalid_digest
      description =~ "Insufficient number of groups" -> :insufficient_groups
      description =~ "insufficient number of members" -> :insufficient_member_shares
      description =~ "Basic sharing 2-of-3" -> :insufficient_member_shares
      description =~ "insufficient length" -> :invalid_mnemonic_length
      description =~ "invalid master secret length" -> :invalid_secret_length
    end
  end

  describe "official vectors" do
    test "vector file contains 15 valid and 30 invalid vectors" do
      assert length(@vectors) == 45
      assert Enum.count(@vectors, fn [_d, _m, ms_hex, _x] -> ms_hex != "" end) == 15
      assert Enum.count(@vectors, fn [_d, _m, ms_hex, _x] -> ms_hex == "" end) == 30
    end

    test "all valid vectors recover the master secret and derive the xprv" do
      for [description, mnemonics, ms_hex, xprv] <- @vectors, ms_hex != "" do
        ms = Base.decode16!(ms_hex, case: :lower)

        assert SLIP39.combine_mnemonics(mnemonics, "TREZOR") == {:ok, ms},
               "vector failed: #{description}"

        assert {:ok, xkey} = ExtendedKey.seed_to_master_private_key(ms)

        assert ExtendedKey.display_extended_key(xkey) == xprv,
               "xprv mismatch for vector: #{description}"
      end
    end

    test "all invalid vectors return the specific error atom for their description" do
      for [description, mnemonics, ms_hex, _xprv] <- @vectors, ms_hex == "" do
        assert SLIP39.combine_mnemonics(mnemonics, "TREZOR") ==
                 {:error, expected_error(description)},
               "vector failed: #{description}"
      end
    end
  end

  describe "generate_mnemonics/4 + combine_mnemonics/2 round-trips" do
    test "single group 2-of-3: every 2-subset recovers the secret" do
      rng = make_rng(1)

      assert {:ok, [shares]} = SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, rng: rng)
      assert length(shares) == 3

      for subset <- combinations(shares, 2) do
        assert SLIP39.combine_mnemonics(subset) == {:ok, @secret_16}
      end
    end

    test "multi-group 2-of-[(2,3),(3,5),(1,1)]: exact-threshold subsets of any 2 groups" do
      rng = make_rng(2)

      assert {:ok, [g0, g1, g2]} =
               SLIP39.generate_mnemonics(2, [{2, 3}, {3, 5}, {1, 1}], @secret_32,
                 passphrase: "TREZOR",
                 rng: rng
               )

      assert length(g0) == 3
      assert length(g1) == 5
      assert length(g2) == 1

      # groups 0 + 1
      assert SLIP39.combine_mnemonics(Enum.take(g0, 2) ++ Enum.take(g1, 3), "TREZOR") ==
               {:ok, @secret_32}

      # groups 0 + 2, a different member subset of group 0
      assert SLIP39.combine_mnemonics([Enum.at(g0, 0), Enum.at(g0, 2)] ++ g2, "TREZOR") ==
               {:ok, @secret_32}

      # groups 1 + 2, a different member subset of group 1
      assert SLIP39.combine_mnemonics(
               g2 ++ [Enum.at(g1, 4), Enum.at(g1, 1), Enum.at(g1, 3)],
               "TREZOR"
             ) == {:ok, @secret_32}
    end

    test "16 groups of (1,1) with group threshold 16" do
      rng = make_rng(3)
      groups = List.duplicate({1, 1}, 16)

      assert {:ok, group_mnemonics} = SLIP39.generate_mnemonics(16, groups, @secret_16, rng: rng)

      all_shares = List.flatten(group_mnemonics)
      assert length(all_shares) == 16
      assert SLIP39.combine_mnemonics(all_shares) == {:ok, @secret_16}
    end

    test "share order does not matter" do
      rng = make_rng(4)

      assert {:ok, [g0, g1]} =
               SLIP39.generate_mnemonics(2, [{2, 3}, {2, 2}], @secret_16, rng: rng)

      subset = Enum.take(g0, 2) ++ g1

      for shuffled <- [Enum.reverse(subset), Enum.shuffle(subset), Enum.shuffle(subset)] do
        assert SLIP39.combine_mnemonics(shuffled) == {:ok, @secret_16}
      end
    end

    test "extendable: true and extendable: false both round-trip" do
      for extendable <- [true, false] do
        rng = make_rng(5)

        assert {:ok, [shares]} =
                 SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16,
                   extendable: extendable,
                   rng: rng
                 )

        assert {:ok, %Share{extendable: ^extendable}} = Share.decode(hd(shares))
        assert SLIP39.combine_mnemonics(Enum.take(shares, 2)) == {:ok, @secret_16}
      end
    end

    test "explicit identifier and iteration exponent are threaded through" do
      rng = make_rng(6)

      assert {:ok, [shares]} =
               SLIP39.generate_mnemonics(1, [{2, 2}], @secret_16,
                 identifier: 12_345,
                 iteration_exponent: 1,
                 extendable: false,
                 rng: rng
               )

      assert {:ok, %Share{identifier: 12_345, iteration_exponent: 1}} = Share.decode(hd(shares))
      assert SLIP39.combine_mnemonics(shares) == {:ok, @secret_16}
    end

    test "wrong passphrase yields a different master secret, not an error" do
      rng = make_rng(7)

      assert {:ok, [shares]} =
               SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, passphrase: "TREZOR", rng: rng)

      subset = Enum.take(shares, 2)

      assert SLIP39.combine_mnemonics(subset, "TREZOR") == {:ok, @secret_16}

      # SLIP-39 plausible deniability: a wrong passphrase silently decrypts
      # to a different master secret.
      assert {:ok, wrong_ms} = SLIP39.combine_mnemonics(subset, "NOT TREZOR")
      assert wrong_ms != @secret_16
      assert byte_size(wrong_ms) == byte_size(@secret_16)
    end
  end

  describe "generate_mnemonics/4 validation" do
    test "master secret shorter than 16 bytes returns {:error, :invalid_secret_length}" do
      assert SLIP39.generate_mnemonics(1, [{2, 3}], :binary.copy(<<1>>, 15)) ==
               {:error, :invalid_secret_length}
    end

    test "master secret of odd length returns {:error, :invalid_secret_length}" do
      assert SLIP39.generate_mnemonics(1, [{2, 3}], :binary.copy(<<1>>, 17)) ==
               {:error, :invalid_secret_length}
    end

    test "group threshold above the group count returns {:error, :invalid_group_threshold}" do
      assert SLIP39.generate_mnemonics(3, [{2, 3}, {2, 3}], @secret_16) ==
               {:error, :invalid_group_threshold}
    end

    test "group threshold of 0 returns {:error, :invalid_group_threshold}" do
      assert SLIP39.generate_mnemonics(0, [{2, 3}], @secret_16) ==
               {:error, :invalid_group_threshold}
    end

    test "more than 16 groups returns {:error, :invalid_group_threshold}" do
      assert SLIP39.generate_mnemonics(1, List.duplicate({1, 1}, 17), @secret_16) ==
               {:error, :invalid_group_threshold}
    end

    test "member threshold above the member count returns {:error, :invalid_member_threshold}" do
      assert SLIP39.generate_mnemonics(1, [{3, 2}], @secret_16) ==
               {:error, :invalid_member_threshold}
    end

    test "member threshold of 1 with more than 1 share returns {:error, :invalid_member_threshold}" do
      assert SLIP39.generate_mnemonics(1, [{1, 2}], @secret_16) ==
               {:error, :invalid_member_threshold}
    end

    test "non-printable-ASCII passphrase returns {:error, :invalid_passphrase}" do
      assert SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, passphrase: "café") ==
               {:error, :invalid_passphrase}

      assert SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, passphrase: <<7>>) ==
               {:error, :invalid_passphrase}
    end

    test "out-of-range identifier returns {:error, :invalid_identifier}" do
      # the wire format truncates identifiers to 15 bits: an unvalidated
      # identifier of 40_000 would encode as 7232 while the Feistel salt
      # used 40_000, so recombination would silently yield a wrong secret
      for bad <- [40_000, 0x8000, -1, :zero, "0"] do
        assert SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, identifier: bad) ==
                 {:error, :invalid_identifier}
      end
    end

    test "identifier boundary values are accepted and round-trip" do
      for identifier <- [0, 0x7FFF] do
        assert {:ok, [mnemonics]} =
                 SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16,
                   identifier: identifier,
                   rng: make_rng(41)
                 )

        assert SLIP39.combine_mnemonics(Enum.take(mnemonics, 2)) == {:ok, @secret_16}
      end
    end

    test "out-of-range iteration exponent returns {:error, :invalid_iteration_exponent}" do
      # the wire format truncates the exponent to 4 bits: e = 16 would
      # encode as 0 while encryption used 10_000 <<< 16 iterations
      for bad <- [16, -1, 1.0] do
        assert SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, iteration_exponent: bad) ==
                 {:error, :invalid_iteration_exponent}
      end
    end
  end

  describe "combine_mnemonics/2 validation" do
    test "empty mnemonic list returns {:error, :empty_mnemonic_set}" do
      assert SLIP39.combine_mnemonics([]) == {:error, :empty_mnemonic_set}
    end

    test "non-printable-ASCII passphrase returns {:error, :invalid_passphrase}" do
      assert SLIP39.combine_mnemonics(["any mnemonic"], "café") == {:error, :invalid_passphrase}
      assert SLIP39.combine_mnemonics(["any mnemonic"], <<7>>) == {:error, :invalid_passphrase}
    end

    test "more groups than the group threshold returns {:error, :too_many_groups}" do
      rng = make_rng(8)

      assert {:ok, groups} =
               SLIP39.generate_mnemonics(2, [{1, 1}, {1, 1}, {1, 1}], @secret_16, rng: rng)

      assert SLIP39.combine_mnemonics(List.flatten(groups)) == {:error, :too_many_groups}
    end

    test "fewer groups than the group threshold returns {:error, :insufficient_groups}" do
      rng = make_rng(9)

      assert {:ok, [g0, _g1]} =
               SLIP39.generate_mnemonics(2, [{2, 2}, {2, 2}], @secret_16, rng: rng)

      assert SLIP39.combine_mnemonics(g0) == {:error, :insufficient_groups}
    end

    test "more member shares than the member threshold returns {:error, :too_many_member_shares}" do
      rng = make_rng(10)

      assert {:ok, [shares]} = SLIP39.generate_mnemonics(1, [{2, 3}], @secret_16, rng: rng)
      assert SLIP39.combine_mnemonics(shares) == {:error, :too_many_member_shares}
    end

    test "fewer member shares than the member threshold returns {:error, :insufficient_member_shares}" do
      rng = make_rng(11)

      assert {:ok, [shares]} = SLIP39.generate_mnemonics(1, [{3, 5}], @secret_16, rng: rng)

      assert SLIP39.combine_mnemonics(Enum.take(shares, 2)) ==
               {:error, :insufficient_member_shares}
    end

    test "shares from different share sets return {:error, :mismatching_shares}" do
      assert {:ok, [[share_a | _]]} =
               SLIP39.generate_mnemonics(1, [{2, 2}], @secret_16, rng: make_rng(12))

      assert {:ok, [[_, share_b]]} =
               SLIP39.generate_mnemonics(1, [{2, 2}], @secret_16, rng: make_rng(13))

      assert SLIP39.combine_mnemonics([share_a, share_b]) == {:error, :mismatching_shares}
    end

    test "a share with group_index >= group_count returns {:error, :invalid_group_index}" do
      # Hand-build a checksum-valid 1-of-1 mnemonic claiming group_count 1 but
      # group_index 15 — SLIP-39 generation assigns group x-coordinates
      # 0..G-1, so this share can never be produced legitimately. Before the
      # group-index check it decoded and recovered a master secret.
      # id=7945, ext=0, e=0, group_index=15, gt-1=0, gc-1=0, mi=0, mt-1=0,
      # 2 pad bits, 16-byte value = 170 bits = 17 words.
      data_bits = <<7945::15, 0::1, 0::4, 15::4, 0::4, 0::4, 0::4, 0::4, 0::2, 0::128>>
      data_words = for <<idx::10 <- data_bits>>, do: idx

      mnemonic =
        (data_words ++ Encoding.rs1024_create_checksum(data_words, false))
        |> Encoding.indices_to_words()
        |> Enum.join(" ")

      assert Share.decode(mnemonic) == {:error, :invalid_group_index}
      assert SLIP39.combine_mnemonics([mnemonic]) == {:error, :invalid_group_index}
    end
  end

  # 1 <= t <= n <= 4, excluding the forbidden t == 1 && n > 1 case.
  defp group_spec_generator do
    gen all(
          member_threshold <- integer(1..4),
          member_count <-
            if(member_threshold == 1,
              do: constant(1),
              else: integer(member_threshold..4)
            )
        ) do
      {member_threshold, member_count}
    end
  end

  describe "properties" do
    property "full-stack round-trip: exact-threshold shuffled subsets recover the secret" do
      check all(
              master_secret <- one_of([binary(length: 16), binary(length: 32)]),
              groups <- list_of(group_spec_generator(), min_length: 1, max_length: 4),
              group_threshold <- integer(1..length(groups)),
              seed <- integer(0..1_000_000),
              max_runs: 25
            ) do
        rng = make_rng(seed)

        assert {:ok, group_mnemonics} =
                 SLIP39.generate_mnemonics(group_threshold, groups, master_secret,
                   iteration_exponent: 0,
                   rng: rng
                 )

        subset =
          group_mnemonics
          |> Enum.zip(groups)
          |> Enum.shuffle()
          |> Enum.take(group_threshold)
          |> Enum.flat_map(fn {mnemonics, {member_threshold, _member_count}} ->
            mnemonics |> Enum.shuffle() |> Enum.take(member_threshold)
          end)
          |> Enum.shuffle()

        assert SLIP39.combine_mnemonics(subset) == {:ok, master_secret}
      end
    end
  end
end
