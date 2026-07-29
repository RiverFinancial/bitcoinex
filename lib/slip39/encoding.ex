defmodule Bitcoinex.SLIP39.Encoding do
  @moduledoc """
  SLIP-39 RS1024 checksum and word packing.

  Implements the Reed-Solomon code over GF(1024) used by SLIP-39 mnemonics
  (guarantees detection of up to 3 word errors) and the conversion between
  10-bit word indices and words from the SLIP-39 word list.
  """

  import Bitwise

  @wordlist_path Path.join(__DIR__, "../../priv/slip39_english.txt")
  @external_resource @wordlist_path
  {words, index} = Bitcoinex.Wordlist.load!(@wordlist_path, 1024)
  @wordlist words
  @word_index index

  @customization_string_orig "shamir"
  @customization_string_extendable "shamir_extendable"

  @gen [
    0xE0E040,
    0x1C1C080,
    0x3838100,
    0x7070200,
    0xE0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x3F3F120
  ]

  @doc """
  rs1024_polymod computes the RS1024 polynomial modulus over a list of
  10-bit values, mirroring the bech32 polymod but with the SLIP-39
  generator over GF(1024).
  """
  @spec rs1024_polymod(list(non_neg_integer())) :: non_neg_integer()
  def rs1024_polymod(values) do
    Enum.reduce(
      values,
      1,
      fn value, acc ->
        b = acc >>> 20
        acc = Bitwise.bxor((acc &&& 0xFFFFF) <<< 10, value)

        @gen
        |> Enum.with_index()
        |> Enum.reduce(acc, fn {gen_val, i}, in_acc ->
          right_side =
            if (b >>> i &&& 1) != 0 do
              gen_val
            else
              0
            end

          Bitwise.bxor(in_acc, right_side)
        end)
      end
    )
  end

  @doc """
  rs1024_create_checksum returns the 3 checksum words (10-bit values) for
  the given data words. `ext` selects the customization string:
  "shamir_extendable" when true, "shamir" otherwise.
  """
  @spec rs1024_create_checksum(list(0..1023), boolean()) :: list(0..1023)
  def rs1024_create_checksum(data, ext) do
    values = customization_values(ext) ++ data ++ [0, 0, 0]
    poly = values |> rs1024_polymod() |> Bitwise.bxor(1)
    for i <- 0..2, do: poly >>> (10 * (2 - i)) &&& 1023
  end

  @doc """
  rs1024_verify_checksum returns true if the data words (including the
  trailing 3 checksum words) have a valid RS1024 checksum under the
  customization string selected by `ext`.
  """
  @spec rs1024_verify_checksum(list(0..1023), boolean()) :: boolean()
  def rs1024_verify_checksum(data, ext) do
    rs1024_polymod(customization_values(ext) ++ data) == 1
  end

  @doc """
  indices_to_words maps each 10-bit word index to its SLIP-39 word.
  """
  @spec indices_to_words(list(0..1023)) :: list(String.t())
  def indices_to_words(indices) do
    Enum.map(indices, &elem(@wordlist, &1))
  end

  @doc """
  words_to_indices maps each SLIP-39 word to its 10-bit index. Returns
  `{:error, :word_not_in_list}` if any word is not in the word list.
  """
  @spec words_to_indices(list(String.t())) ::
          {:ok, list(0..1023)} | {:error, :word_not_in_list}
  def words_to_indices(words) do
    words
    |> Enum.reduce_while([], fn word, acc ->
      case Map.fetch(@word_index, word) do
        {:ok, idx} -> {:cont, [idx | acc]}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      :error -> {:error, :word_not_in_list}
      indices -> {:ok, Enum.reverse(indices)}
    end
  end

  defp customization_values(ext) do
    customization =
      if ext, do: @customization_string_extendable, else: @customization_string_orig

    :binary.bin_to_list(customization)
  end
end
