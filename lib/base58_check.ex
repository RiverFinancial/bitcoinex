defmodule Bitcoinex.Base58Check do
  @moduledoc """
    Some code inspired by:
    https://github.com/comboy/bitcoin-elixir/blob/develop/lib/bitcoin/base58_check.ex
  """

  @type address_type :: :p2sh | :p2pkh
  @base58_encode_list ~c(123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
  @base58_decode_map @base58_encode_list |> Enum.with_index |> Enum.into(%{})

  @base58_0 <<?1>>
  @type byte_list :: list(byte())

  @doc """
    Decode a base58 check encoded string into a byte array and validate checksum
  """
  @spec decode(binary) :: {:ok, binary} | {:error, atom}
  def decode(<<body_and_checksum::binary>>) do
    body_and_checksum
    |> decode_base!()
    |> validate_checksum()
  end

  def decode(""), do: ""

  def validate_checksum(data) do
    [decoded_body, checksum] =
       data
       |> :binary.bin_to_list()
       |> Enum.split(-4)
       |> Tuple.to_list()
       |> Enum.map(& :binary.list_to_bin(&1))

    case checksum == binary_slice(bin_double_sha256(decoded_body), 0..3) do
      false -> {:error, :invalid_checksum}
      true -> {:ok, decoded_body}
    end
  end

  def decode_base!(@base58_0), do: <<0>>

  def decode_base!(@base58_0 <> body) when byte_size(body) > 0 do
    decode_base!(@base58_0) <> decode_base!(body)
  end

  def decode_base!(""), do: ""


  @doc """
    Decode a base58 encoded string into a byte array
  """
  def decode_base!(bin) do
    bin
    |> :binary.bin_to_list
    |> Enum.map(& @base58_decode_map[&1])
    |> Integer.undigits(58)
    |> :binary.encode_unsigned
  end

  @doc """
    Encode a byte array into a base58check encoded string
  """
  @spec encode(binary) :: String.t
  def encode(bin) do
    bin
    |> append_checksum()
    |> encode_base()
  end

  def encode_base(""), do: ""

  def encode_base(<<0>> <> tail) do
    @base58_0 <> encode_base(tail)
  end

  @doc """
    Encode a byte array into a base58 encoded string
  """
  @spec encode_base(binary) :: String.t
  def encode_base(bin) do
    bin
    |> :binary.decode_unsigned
    |> Integer.digits(58)
    |> Enum.map(& Enum.fetch!(@base58_encode_list, &1))
    |> List.to_string()
  end

  defp append_checksum(body) do
    body <> checksum(body)
  end

  defp checksum(body) do
    body
    |> bin_double_sha256()
    |> binary_slice(0..3)
  end

  defp bin_double_sha256(preimage) do
    :crypto.hash(:sha256,
      :crypto.hash(:sha256, preimage))
  end

  defp binary_slice(data, range) do
    data
    |> :binary.bin_to_list()
    |> Enum.slice(range)
    |> :binary.list_to_bin()
  end

end
