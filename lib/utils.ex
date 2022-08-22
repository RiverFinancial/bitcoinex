defmodule Bitcoinex.Utils do
  @moduledoc """
  Contains useful utility functions used in Bitcoinex.
  """

  use Bitwise, only_operators: true

  @spec sha256(iodata()) :: binary
  def sha256(str) do
    :crypto.hash(:sha256, str)
  end

  def tagged_hash(tag, str) do
    tag_hash = sha256(tag)
    sha256(tag_hash <> tag_hash <> str)
  end

  @spec replicate(term(), integer()) :: list(term())
  def replicate(_num, 0) do
    []
  end

  def replicate(x, num) when x > 0 do
    for _ <- 1..num, do: x
  end

  @spec double_sha256(iodata()) :: binary
  def double_sha256(preimage) do
    :crypto.hash(
      :sha256,
      :crypto.hash(:sha256, preimage)
    )
  end

  @spec hash160(iodata()) :: binary
  def hash160(preimage) do
    :crypto.hash(
      :ripemd160,
      :crypto.hash(:sha256, preimage)
    )
  end

  @typedoc """
    The pad_type describes the padding to use.
  """
  @type pad_type :: :leading | :trailing

  @doc """
  pads binary according to the byte length and the padding type. A binary can be padded with leading or trailing zeros.
  """
  @spec pad(bin :: binary, byte_len :: integer, pad_type :: pad_type) :: binary
  def pad(bin, byte_len, _pad_type) when is_binary(bin) and byte_size(bin) == byte_len do
    bin
  end

  def pad(bin, byte_len, pad_type) when is_binary(bin) and pad_type == :leading do
    pad_len = 8 * byte_len - byte_size(bin) * 8
    <<0::size(pad_len)>> <> bin
  end

  def pad(bin, byte_len, pad_type) when is_binary(bin) and pad_type == :trailing do
    pad_len = 8 * byte_len - byte_size(bin) * 8
    bin <> <<0::size(pad_len)>>
  end

  @spec int_to_big(non_neg_integer(), non_neg_integer()) :: binary
  def int_to_big(i, p) do
    i
    |> :binary.encode_unsigned()
    |> pad(p, :leading)
  end

  def int_to_little(i, p) do
    i
    |> :binary.encode_unsigned(:little)
    |> pad(p, :trailing)
  end

  def little_to_int(i), do: :binary.decode_unsigned(i, :little)

  def encode_int(i) when i > 0 do
    cond do
      i < 0xFD -> :binary.encode_unsigned(i)
      i <= 0xFFFF -> <<0xFD>> <> int_to_little(i, 2)
      i <= 0xFFFFFFFF -> <<0xFE>> <> int_to_little(i, 4)
      i <= 0xFFFFFFFFFFFFFFFF -> <<0xFF>> <> int_to_little(i, 8)
      true -> {:error, "invalid integer size"}
    end
  end

  def hex_to_bin(str) do
    str
    |> String.downcase()
    |> Base.decode16(case: :lower)
    |> case do
      # In case of error, its already binary or its invalid
      :error -> {:error, "invalid string"}
      # valid binary
      {:ok, bin} -> bin
    end
  end

  # todo: better to just convert to ints and XOR them?
  @spec xor_bytes(binary, binary) :: binary
  def xor_bytes(bin0, bin1) do
    {bl0, bl1} = {:binary.bin_to_list(bin0), :binary.bin_to_list(bin1)}

    Enum.zip(bl0, bl1)
    |> Enum.map(fn {b0, b1} -> b0 ^^^ b1 end)
    |> :binary.list_to_bin()
  end
end
