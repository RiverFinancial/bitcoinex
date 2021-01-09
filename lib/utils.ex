defmodule Bitcoinex.Utils do
  @moduledoc """
  Contains useful utility functions used in Bitcoinex.
  """

  @spec sha256(iodata()) :: binary
  def sha256(str) do
    :crypto.hash(:sha256, str)
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
  @spec hash160(iodata()) :: binary
  def hash160(str) do
    :crypto.hash(:ripemd160, str)
    |> :crypto.hash(:sha256)
  end

  # is this efficient? It would be better to use streams
  @spec read_varint(binary, integer) :: integer 
  def read_varint(data, pos) do
    case :binary.at(data, pos) do
      0xfd -> 
        :binary.part(data, pos+1, 2)
      0xfe ->
        :binary.part(data, pos+1, 4)
      0xff ->
        :binary.part(data, pos+1, 8)
      -> :binary.at(data, pos)
    end
    |> :binary.decode_unsigned(:little)
  end

  @spec encode_varint(integer) :: binary
  def encode_varint(i) do
    cond do
      i == 0xfd ->
        :binary.encode_unsigned(i)
      i < 0x10000 ->
        <<0xfd>> <> :binary.encode_unsigned(i, :little)
      i < 0x100000000 ->
        <<0xfe>> <> :binary.encode_unsigned(i, :little)
      i < 0x10000000000000000 ->
        <<0xff>> <> :binary.encode_unsigned(i, :little)
    end

end
