defmodule Bitcoinex.SLIP39.EncodingTest do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.SLIP39.Encoding

  alias Bitcoinex.SLIP39.Encoding

  describe "rs1024_polymod/1" do
    test "matches the SLIP-39 reference implementation on fixed word arrays" do
      # Expected values computed with the reference polymod (trezor
      # python-shamir-mnemonic rs1024_polymod) over the same inputs.
      assert Encoding.rs1024_polymod(Enum.to_list(0..9)) == 488_197_068
      assert Encoding.rs1024_polymod(:binary.bin_to_list("shamir")) == 608_866_019
    end
  end

  describe "rs1024_create_checksum/2 and rs1024_verify_checksum/2" do
    test "create then verify round-trips for ext in {true, false}" do
      data = [5, 470, 8, 1023, 0, 512, 33, 777, 90, 101, 202, 303, 404]

      for ext <- [true, false] do
        checksum = Encoding.rs1024_create_checksum(data, ext)

        assert length(checksum) == 3
        assert Enum.all?(checksum, &(&1 in 0..1023))
        assert Encoding.rs1024_verify_checksum(data ++ checksum, ext)
      end
    end

    test "checksums differ between customization strings" do
      data = [5, 470, 8, 1023, 0, 512, 33, 777, 90, 101, 202, 303, 404]

      checksum_orig = Encoding.rs1024_create_checksum(data, false)
      checksum_ext = Encoding.rs1024_create_checksum(data, true)

      assert checksum_orig != checksum_ext
      refute Encoding.rs1024_verify_checksum(data ++ checksum_orig, true)
      refute Encoding.rs1024_verify_checksum(data ++ checksum_ext, false)
    end

    test "verify fails when any 1, 2, or 3 words are mutated" do
      data = [5, 470, 8, 1023, 0, 512, 33, 777, 90, 101, 202, 303, 404]

      for ext <- [true, false] do
        words = data ++ Encoding.rs1024_create_checksum(data, ext)
        last = length(words) - 1

        # Every single-word mutation is detected, at every position.
        for pos <- 0..last do
          mutated = List.update_at(words, pos, &Bitwise.bxor(&1, 1))
          refute Encoding.rs1024_verify_checksum(mutated, ext)
        end

        # Sampled 2- and 3-word mutations are detected.
        two_word_mutations = for i <- 0..last, j <- 0..last, i < j, do: [i, j]

        three_word_mutations =
          for i <- 0..last, j <- 0..last, k <- 0..last, i < j and j < k, do: [i, j, k]

        for positions <- two_word_mutations ++ three_word_mutations do
          mutated =
            Enum.reduce(positions, words, fn pos, acc ->
              List.update_at(acc, pos, &Bitwise.bxor(&1, 3))
            end)

          refute Encoding.rs1024_verify_checksum(mutated, ext)
        end
      end
    end
  end

  describe "indices_to_words/1 and words_to_indices/1" do
    test "round-trips all 1024 indices" do
      indices = Enum.to_list(0..1023)
      words = Encoding.indices_to_words(indices)

      assert {:ok, indices} == Encoding.words_to_indices(words)
    end

    test "unknown word returns {:error, :word_not_in_list}" do
      assert Encoding.words_to_indices(["academic", "notaword"]) ==
               {:error, :word_not_in_list}

      assert Encoding.words_to_indices(["ACADEMIC"]) == {:error, :word_not_in_list}
    end
  end

  describe "word list" do
    test "has exactly 1024 unique entries, all of length 4-8" do
      words = Encoding.indices_to_words(Enum.to_list(0..1023))

      assert length(words) == 1024
      assert length(Enum.uniq(words)) == 1024
      assert Enum.all?(words, &(String.length(&1) in 4..8))
    end
  end
end
