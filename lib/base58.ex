defmodule Bitcoinex.Base58 do
  @moduledoc """
  ref: https://github.com/titan098/erl-base58/blob/master/src/base58.erl
  """

  @type address_type :: :p2sh | :p2pkh
  @base58_alphabets ~c(123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
  @type byte_list :: list(byte())
  import Bitcoinex.Utils, only: [replicate: 2]

  @spec int_to_bin(integer()) :: binary
  def int_to_bin(x), do: do_int_to_bin(x, [])

  @spec bin_to_int(binary()) :: integer
  def bin_to_int(bin) when bin != "" do
    do_bin_to_int(bin |> to_charlist, 0)
  end

  @spec str_to_bin(String.t()) :: binary()
  def str_to_bin(""), do: <<>>

  def str_to_bin(base58_str) do
    base58_bin = :binary.encode_unsigned(bin_to_int(base58_str))
    pad_zero(base58_str, base58_bin)
  end

  @spec bin_to_str(binary | list(byte)) :: String.t()
  def bin_to_str(<<>>), do: ""

  def bin_to_str(base58_bin) when is_binary(base58_bin) do
    base58_str = int_to_bin(:binary.decode_unsigned(base58_bin))
    # Bitcoin Base58 converts every byte of zeros (0x00) at the start of a number to a 1.
    pad_one(:erlang.binary_to_list(base58_bin), base58_str)
  end

  def bin_to_str(base58_bytes_list) when is_list(base58_bytes_list) do
    base58_bytes_list
    |> :binary.list_to_bin()
    |> bin_to_str
  end

  @spec bin_to_base58check(list(byte) | binary(), Bitcoinex.Network.network_name(), address_type) ::
          String.t()
  def bin_to_base58check(bin, network_name, address_type) when is_binary(bin) do
    bin
    |> :binary.bin_to_list()
    |> bin_to_base58check(network_name, address_type)
  end

  def bin_to_base58check(byte_list, network_name, address_type) when is_list(byte_list) do
    network = Bitcoinex.Network.get_network(network_name)

    decimal_prefix =
      case address_type do
        :p2sh ->
          network.p2sh_version_decimal_prefix

        :p2pkh ->
          network.p2pkh_version_decimal_prefix
      end

    do_bin_to_base58check(byte_list, decimal_prefix)
  end

  defp do_bin_to_base58check(chars, magic_byte) do
    chars = [magic_byte | chars]

    leadingzbytes =
      case Enum.find_index(chars, fn x -> x != 0 end) do
        nil ->
          0

        idx ->
          idx
      end

    checksum = Enum.slice(bin_double_sha256(chars), 0..3)

    Enum.join(replicate("1", leadingzbytes), "") <>
      encode_base(decode_base(chars ++ checksum, 256), 58)
  end

  defp decode_base(byte_list, 256) when is_list(byte_list) do
    Enum.reduce(
      byte_list,
      0,
      fn byte, acc ->
        acc * 256 + byte
      end
    )
  end

  defp do_encode(0, _, _, acc) do
    :binary.list_to_bin(acc)
  end

  defp do_encode(val, base, code_char_list, acc) do
    code = Enum.at(code_char_list, rem(val, base))
    do_encode(div(val, base), base, code_char_list, [code | acc])
  end

  defp encode_base(val, 58) when is_integer(val) do
    do_encode(val, 58, @base58_alphabets, [])
  end

  defp bin_double_sha256(chars) do
    hash = :crypto.hash(:sha256, chars)
    # hash is <<118, 134, ... >>
    :binary.bin_to_list(:crypto.hash(:sha256, hash))
  end

  defp do_int_to_bin(0, []), do: [@base58_alphabets |> hd] |> to_string
  defp do_int_to_bin(0, acc), do: acc |> to_string

  defp do_int_to_bin(x, acc) do
    do_int_to_bin(div(x, 58), [Enum.at(@base58_alphabets, rem(x, 58)) | acc])
  end

  defp do_bin_to_int([], acc), do: acc

  defp do_bin_to_int([c | cs], acc) do
    do_bin_to_int(cs, acc * 58 + Enum.find_index(@base58_alphabets, &(&1 == c)))
  end

  defp pad_zero(<<?1, rest::binary>>, base58_bin) do
    pad_zero(rest, <<0, base58_bin::binary>>)
  end

  defp pad_zero(_, base58_bin) do
    base58_bin
  end

  defp pad_one([0 | rest], base58_bin) do
    pad_one(rest, "1" <> base58_bin)
  end

  defp pad_one(_, base58_bin) do
    base58_bin
  end
end
