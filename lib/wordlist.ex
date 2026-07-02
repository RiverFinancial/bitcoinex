defmodule Bitcoinex.Wordlist do
  @moduledoc """
  Compile-time loader for the word lists bundled under priv/.

  Callers (BIP-39, SLIP-39) invoke `load!/2` from module attributes so a
  missing, truncated, or corrupted word list fails compilation rather than
  mis-encoding at runtime.
  """

  @doc """
  load! reads a newline-separated word list and returns `{words, index}`
  where `words` is a tuple for O(1) `elem/2` access and `index` maps each
  word to its position.

  Raises if the file is missing, the word count differs from
  `expected_count`, or the list contains duplicate words. These are
  compile-time programmer errors, so no result tuple is returned.
  """
  @spec load!(Path.t(), pos_integer()) :: {tuple(), %{String.t() => non_neg_integer()}}
  def load!(path, expected_count) do
    words =
      path
      |> File.read!()
      |> String.split("\n", trim: true)

    count = length(words)

    if count != expected_count do
      raise ArgumentError, "word list #{path} has #{count} words, expected #{expected_count}"
    end

    index = words |> Enum.with_index() |> Map.new()

    if map_size(index) != expected_count do
      raise ArgumentError, "word list #{path} contains duplicate words"
    end

    {List.to_tuple(words), index}
  end
end
