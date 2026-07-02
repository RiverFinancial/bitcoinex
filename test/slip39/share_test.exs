defmodule Bitcoinex.SLIP39.ShareTest do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.SLIP39.Share

  alias Bitcoinex.SLIP39.Encoding
  alias Bitcoinex.SLIP39.Share
  alias Bitcoinex.Utils

  # Official trezor/python-shamir-mnemonic vectors:
  # [description, mnemonics, ms_hex, xprv] per entry.
  @vectors_path Path.join(__DIR__, "../data/slip39_vectors.json")
  @vectors JSON.decode!(File.read!(@vectors_path))

  defp vector_mnemonic(index) do
    [_description, [mnemonic | _], _ms, _xprv] = Enum.at(@vectors, index)
    mnemonic
  end

  describe "decode/1 official vectors" do
    test "vector 1: valid mnemonic without sharing (128 bits, 20 words)" do
      assert {:ok, share} = Share.decode(vector_mnemonic(0))

      assert share == %Share{
               identifier: 7945,
               extendable: false,
               iteration_exponent: 0,
               group_index: 0,
               group_threshold: 1,
               group_count: 1,
               member_index: 0,
               member_threshold: 1,
               share_value: Base.decode16!("11bc609d21747c49ba78c0701293e417", case: :lower)
             }
    end

    test "vector 42: valid extendable mnemonic without sharing (128 bits)" do
      # pins the extendable-flag wire path with a named assertion
      assert {:ok, share} = Share.decode(vector_mnemonic(41))
      assert share.extendable == true
      assert byte_size(share.share_value) == 16
      assert Share.encode(share) == vector_mnemonic(41)
    end

    test "vector 4: basic sharing 2-of-3 (128 bits)" do
      assert {:ok, share} = Share.decode(vector_mnemonic(3))

      assert share == %Share{
               identifier: 25_653,
               extendable: false,
               iteration_exponent: 2,
               group_index: 0,
               group_threshold: 1,
               group_count: 1,
               member_index: 2,
               member_threshold: 2,
               share_value: Base.decode16!("08fb14b66e692e25dfe2edf53289ed62", case: :lower)
             }
    end

    test "vector 17: threshold number of groups and members (128 bits)" do
      assert {:ok, share} = Share.decode(vector_mnemonic(16))

      assert share == %Share{
               identifier: 9497,
               extendable: false,
               iteration_exponent: 0,
               group_index: 3,
               group_threshold: 2,
               group_count: 4,
               member_index: 0,
               member_threshold: 2,
               share_value: Base.decode16!("44e95c567b0b73d470f78e2cc4f206ee", case: :lower)
             }
    end

    test "vector 20: valid mnemonic without sharing (256 bits, 33 words)" do
      mnemonic = vector_mnemonic(19)
      assert length(String.split(mnemonic)) == 33

      assert {:ok, share} = Share.decode(mnemonic)

      assert share == %Share{
               identifier: 29_172,
               extendable: false,
               iteration_exponent: 0,
               group_index: 0,
               group_threshold: 1,
               group_count: 1,
               member_index: 0,
               member_threshold: 1,
               share_value:
                 Base.decode16!(
                   "d772fee46424e100bec16d165f1fcc346d1e8d909da580f9f9f04ea5c788d212",
                   case: :lower
                 )
             }

      assert byte_size(share.share_value) == 32
    end

    test "encode/1 round-trips every decodable mnemonic across all 45 vectors" do
      assert length(@vectors) == 45

      decoded_count =
        for [_description, mnemonics, _ms, _xprv] <- @vectors,
            mnemonic <- mnemonics,
            reduce: 0 do
          acc ->
            case Share.decode(mnemonic) do
              {:ok, share} ->
                assert Share.encode(share) == mnemonic
                acc + 1

              {:error, _reason} ->
                acc
            end
        end

      # Sanity: the valid vectors alone contribute plenty of decodable shares.
      assert decoded_count > 45
    end
  end

  describe "decode/1 errors" do
    test "vector 2 (invalid checksum) returns {:error, :invalid_checksum}" do
      assert Share.decode(vector_mnemonic(1)) == {:error, :invalid_checksum}
    end

    test "mutated checksum word returns {:error, :invalid_checksum}" do
      mnemonic = vector_mnemonic(0)
      words = String.split(mnemonic)
      mutated = words |> List.replace_at(19, "academic") |> Enum.join(" ")

      assert mutated != mnemonic
      assert Share.decode(mutated) == {:error, :invalid_checksum}
    end

    test "vector 3 (invalid padding) returns {:error, :invalid_padding}" do
      assert Share.decode(vector_mnemonic(2)) == {:error, :invalid_padding}
    end

    test "21-word mnemonic returns {:error, :invalid_padding}" do
      # rem((21 - 7) * 10, 16) == 12 > 8, so 21-word mnemonics are invalid
      # even with a correct checksum.
      data = List.duplicate(0, 18)
      indices = data ++ Encoding.rs1024_create_checksum(data, false)
      mnemonic = indices |> Encoding.indices_to_words() |> Enum.join(" ")

      assert Share.decode(mnemonic) == {:error, :invalid_padding}
    end

    test "vector 39 (insufficient length, 19 words) returns {:error, :invalid_mnemonic_length}" do
      mnemonic = vector_mnemonic(38)

      assert length(String.split(mnemonic)) == 19
      assert Share.decode(mnemonic) == {:error, :invalid_mnemonic_length}
    end

    test "short mnemonics return {:error, :invalid_mnemonic_length}" do
      assert Share.decode("academic academic academic") == {:error, :invalid_mnemonic_length}
    end

    test "vectors 10 and 29 (group threshold > group count) return {:error, :invalid_group_threshold}" do
      assert Share.decode(vector_mnemonic(9)) == {:error, :invalid_group_threshold}
      assert Share.decode(vector_mnemonic(28)) == {:error, :invalid_group_threshold}
    end

    test "word not in list returns {:error, :word_not_in_list}" do
      mnemonic = vector_mnemonic(0)
      mutated = mnemonic |> String.split() |> List.replace_at(0, "bitcoin") |> Enum.join(" ")

      assert Share.decode(mutated) == {:error, :word_not_in_list}
    end
  end

  describe "wire format" do
    test "thresholds and counts are stored minus 1 on the wire" do
      share = %Share{
        identifier: 0x1234,
        extendable: true,
        iteration_exponent: 5,
        group_index: 7,
        group_threshold: 2,
        group_count: 3,
        member_index: 9,
        member_threshold: 4,
        share_value: :binary.copy(<<0xAB>>, 16)
      }

      {:ok, indices} = share |> Share.encode() |> String.split() |> Encoding.words_to_indices()

      <<identifier::15, ext_bit::1, iteration_exponent::4, group_index::4,
        group_threshold_wire::4, group_count_wire::4, member_index::4, member_threshold_wire::4,
        _rest::bitstring>> = Utils.int_list_to_bits(indices, 10)

      assert identifier == 0x1234
      assert ext_bit == 1
      assert iteration_exponent == 5
      assert group_index == 7
      assert group_threshold_wire == 1
      assert group_count_wire == 2
      assert member_index == 9
      assert member_threshold_wire == 3
    end

    test "16-byte share value encodes to 20 words, 32-byte to 33 words" do
      base = %Share{
        identifier: 1,
        extendable: false,
        iteration_exponent: 0,
        group_index: 0,
        group_threshold: 1,
        group_count: 1,
        member_index: 0,
        member_threshold: 1,
        share_value: :binary.copy(<<0>>, 16)
      }

      assert base |> Share.encode() |> String.split() |> length() == 20

      share_256 = %Share{base | share_value: :binary.copy(<<0>>, 32)}
      assert share_256 |> Share.encode() |> String.split() |> length() == 33
    end
  end

  defp share_generator do
    gen all(
          identifier <- integer(0..0x7FFF),
          extendable <- boolean(),
          iteration_exponent <- integer(0..15),
          group_index <- integer(0..15),
          group_count <- integer(1..16),
          group_threshold <- integer(1..group_count),
          member_index <- integer(0..15),
          member_threshold <- integer(1..16),
          value_length <- member_of([16, 32]),
          share_value <- binary(length: value_length)
        ) do
      %Share{
        identifier: identifier,
        extendable: extendable,
        iteration_exponent: iteration_exponent,
        group_index: group_index,
        group_threshold: group_threshold,
        group_count: group_count,
        member_index: member_index,
        member_threshold: member_threshold,
        share_value: share_value
      }
    end
  end

  describe "properties" do
    property "decode(encode(share)) round-trips any valid share" do
      check all(share <- share_generator()) do
        assert share |> Share.encode() |> Share.decode() == {:ok, share}
      end
    end

    property "mutating 1-3 words of a valid share always fails to decode" do
      check all(
              share <- share_generator(),
              offsets <- list_of(integer(1..1023), min_length: 1, max_length: 3),
              position_picks <- list_of(integer(0..10_000), length: 3)
            ) do
        mnemonic = Share.encode(share)
        {:ok, indices} = mnemonic |> String.split() |> Encoding.words_to_indices()
        word_count = length(indices)

        positions =
          position_picks
          |> Enum.map(&rem(&1, word_count))
          |> Enum.uniq()
          |> Enum.take(length(offsets))

        mutated_indices =
          positions
          |> Enum.zip(offsets)
          |> Enum.reduce(indices, fn {position, offset}, acc ->
            List.update_at(acc, position, &rem(&1 + offset, 1024))
          end)

        assert mutated_indices != indices

        mutated = mutated_indices |> Encoding.indices_to_words() |> Enum.join(" ")
        assert {:error, _reason} = Share.decode(mutated)
      end
    end

    property "decode never raises on arbitrary strings" do
      check all(input <- StreamData.string([0x0..0xD7FF, 0xE000..0x10FFFF], max_length: 300)) do
        assert match?({:ok, _}, Share.decode(input)) or
                 match?({:error, _}, Share.decode(input))
      end
    end

    property "decode never raises on random valid-word sequences" do
      check all(indices <- list_of(integer(0..1023), min_length: 0, max_length: 40)) do
        mnemonic = indices |> Encoding.indices_to_words() |> Enum.join(" ")

        assert match?({:ok, _}, Share.decode(mnemonic)) or
                 match?({:error, _}, Share.decode(mnemonic))
      end
    end
  end
end
