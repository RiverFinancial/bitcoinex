defmodule Bitcoinex.Utils do
  @moduledoc """
  Contains useful utility functions used in Bitcoinex.
  """

  @spec sha256(iodata()) :: <<_::256>>
  def sha256(str) do
    :crypto.hash(:sha256, str)
  end

  @spec tagged_hash(binary, iodata()) :: <<_::256>>
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

  @spec double_sha256(iodata()) :: <<_::256>>
  def double_sha256(preimage) do
    :crypto.hash(
      :sha256,
      :crypto.hash(:sha256, preimage)
    )
  end

  @spec hash160(iodata()) :: <<_::160>>
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

  @spec flip_endianness(binary) :: binary
  def flip_endianness(bin) do
    bin
    |> :binary.decode_unsigned(:big)
    |> :binary.encode_unsigned(:little)
  end

  @spec int_to_big(non_neg_integer(), non_neg_integer()) :: binary
  def int_to_big(i, p) do
    i
    |> :binary.encode_unsigned()
    |> pad(p, :leading)
  end

  @spec int_to_little(non_neg_integer(), integer) :: binary
  def int_to_little(i, p) do
    i
    |> :binary.encode_unsigned(:little)
    |> pad(p, :trailing)
  end

  @spec little_to_int(binary) :: non_neg_integer
  def little_to_int(i), do: :binary.decode_unsigned(i, :little)

  @spec encode_int(non_neg_integer()) :: binary | {:error, <<_::160>>}
  def encode_int(i) when i > 0 do
    cond do
      i < 0xFD -> :binary.encode_unsigned(i)
      i <= 0xFFFF -> <<0xFD>> <> int_to_little(i, 2)
      i <= 0xFFFFFFFF -> <<0xFE>> <> int_to_little(i, 4)
      i <= 0xFFFFFFFFFFFFFFFF -> <<0xFF>> <> int_to_little(i, 8)
      true -> {:error, "invalid integer size"}
    end
  end

  @spec hex_to_bin(String.t()) :: binary | {:error, String.t()}
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
    |> Enum.map(fn {b0, b1} -> Bitwise.bxor(b0, b1) end)
    |> :binary.list_to_bin()
  end

  # ascending order
  @spec lexicographical_sort(binary, binary) :: {binary, binary}
  def lexicographical_sort(bin0, bin1) when is_binary(bin0) and is_binary(bin1) do
    if lexicographical_cmp(:binary.bin_to_list(bin0), :binary.bin_to_list(bin1)) do
      {bin0, bin1}
    else
      {bin1, bin0}
    end
  end

  # equality case
  @spec lexicographical_cmp(list(byte), list(byte)) :: boolean
  def lexicographical_cmp([], []), do: true

  def lexicographical_cmp([b0 | r0], [b1 | r1]) do
    cond do
      b0 == b1 ->
        lexicographical_cmp(r0, r1)

      b1 < b0 ->
        # initial order was incorrect, must be swapped
        false

      true ->
        # bin0, bin1 was the correct order
        true
    end
  end

  @doc """
    Returns the serialized variable length integer.
  """
  @spec serialize_compact_size_unsigned_int(non_neg_integer()) :: binary
  def serialize_compact_size_unsigned_int(compact_size) do
    cond do
      compact_size >= 0 and compact_size <= 0xFC ->
        <<compact_size::little-size(8)>>

      compact_size <= 0xFFFF ->
        <<0xFD>> <> <<compact_size::little-size(16)>>

      compact_size <= 0xFFFFFFFF ->
        <<0xFE>> <> <<compact_size::little-size(32)>>

      compact_size <= 0xFF ->
        <<0xFF>> <> <<compact_size::little-size(64)>>
    end
  end
end
