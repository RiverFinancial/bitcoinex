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
  serialize_public_key serializes a compressed public key
  """
  @spec serialize_public_key(t()) :: String.t()
  def serialize_public_key(%__MODULE__{x: x, y: y}) do
    case rem(y, 2) do
      0 ->
        Base.encode16(<<0x02>> <> pad(:binary.encode_unsigned(x)), case: :lower)

      1 ->
        Base.encode16(<<0x03>> <> pad(:binary.encode_unsigned(x)), case: :lower)
    end
  end

  @doc """
  pads binary to 32 bytes
  """
  @spec pad(bin :: binary) :: binary
  def pad(bin) when is_binary(bin) and byte_size(bin) != 32 do
    pad_len = 256 - byte_size(bin) * 8
    <<0::size(pad_len)>> <> bin
  end

  def pad(bin) do
    bin
  end
end
