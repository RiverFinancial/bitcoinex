defmodule Bitcoinex.Secp256k1.Point do
  @moduledoc """
  Contains the x, y, and z of an elliptic curve point.
  """

  @type t :: %__MODULE__{
          x: integer(),
          y: integer(),
          z: integer()
        }

  @enforce_keys [
    :x,
    :y
  ]
  defstruct [:x, :y, z: 0]

  defguard is_point(term)
           when is_map(term) and :erlang.map_get(:__struct__, term) == __MODULE__ and
                  :erlang.is_map_key(:x, term) and :erlang.is_map_key(:y, term) and
                  :erlang.is_map_key(:z, term)

  @doc """
  parse_public_key parses a public key
  """
  #@spec parse_public_key(sec) :: %__MODULE__
  def parse_public_key(<<0x04, x::binary-size(32), y::binary-size(32)>>) do
    %__MODULE__{x: :binary.decode_unsigned(x), y: :binary.decode_unsigned(y)}
  end

  def parse_public_key(<<prefix::binary-size(1), x_bytes::binary-size(32)>>) do
    x = :binary.decode_unsigned(x_bytes)
    case rem(:binary.decode_unsigned(prefix), 2) do
      0 -> 
        {:ok, y} = Bitcoinex.Secp256k1.get_y(x, false)
        %__MODULE__{x: x, y: y}
      1 ->
        {:ok, y} = Bitcoinex.Secp256k1.get_y(x, true)
        %__MODULE__{x: x, y: y}
    end
  end

  @doc """
  serialize_public_key serializes a compressed public key to binary
  """
  @spec sec(t()) :: binary
  def sec(%__MODULE__{x: x, y: y}) do
    case rem(y, 2) do
      0 ->
        <<0x02>> <> pad(:binary.encode_unsigned(x), 32, :leading)
      1 ->
        <<0x03>> <> pad(:binary.encode_unsigned(x), 32, :leading)
    end
  end

  @doc """
  serialize_public_key serializes a compressed public key to string
  """
  @spec serialize_public_key(t()) :: String.t()
  def serialize_public_key(pubkey) do
    pubkey
    |> sec()
    |> Base.encode16(case: :lower)
  end
end
