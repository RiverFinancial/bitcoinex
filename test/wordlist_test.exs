defmodule Bitcoinex.WordlistTest do
  use ExUnit.Case
  doctest Bitcoinex.Wordlist

  alias Bitcoinex.Wordlist

  @priv_dir :code.priv_dir(:bitcoinex)
  @bip39_path Path.join(@priv_dir, "bip39_english.txt")
  @slip39_path Path.join(@priv_dir, "slip39_english.txt")

  describe "load!/2" do
    test "loads the BIP-39 english word list with 2048 unique words" do
      {words, index} = Wordlist.load!(@bip39_path, 2048)

      assert tuple_size(words) == 2048
      assert map_size(index) == 2048
    end

    test "loads the SLIP-39 word list with 1024 unique words" do
      {words, index} = Wordlist.load!(@slip39_path, 1024)

      assert tuple_size(words) == 1024
      assert map_size(index) == 1024
    end

    test "index map inverts the words tuple" do
      for path <- [@bip39_path, @slip39_path],
          count = if(path == @bip39_path, do: 2048, else: 1024) do
        {words, index} = Wordlist.load!(path, count)

        for {word, i} <- index do
          assert elem(words, i) == word
        end
      end
    end

    test "raises on wrong expected count" do
      assert_raise ArgumentError, ~r/expected 42/, fn ->
        Wordlist.load!(@bip39_path, 42)
      end
    end

    test "raises on missing file" do
      assert_raise File.Error, fn ->
        Wordlist.load!(Path.join(@priv_dir, "nonexistent.txt"), 1)
      end
    end
  end

  describe "SLIP-39 word list constraints" do
    # per SLIP-0039: word lengths 4-8, unique 4-letter prefixes, sorted
    test "every word is 4 to 8 letters" do
      {words, _index} = Wordlist.load!(@slip39_path, 1024)

      for word <- Tuple.to_list(words) do
        assert String.length(word) in 4..8
      end
    end

    test "all 4-letter prefixes are unique" do
      {words, _index} = Wordlist.load!(@slip39_path, 1024)

      prefixes = words |> Tuple.to_list() |> Enum.map(&String.slice(&1, 0, 4))
      assert length(Enum.uniq(prefixes)) == 1024
    end

    test "words are sorted alphabetically" do
      {words, _index} = Wordlist.load!(@slip39_path, 1024)

      word_list = Tuple.to_list(words)
      assert word_list == Enum.sort(word_list)
    end
  end
end
