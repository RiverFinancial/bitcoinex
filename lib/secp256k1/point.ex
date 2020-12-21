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

  @doc """
  serialize_public_key serializes a compressed public key
  """
  @spec serialize_public_key(t()) :: String.t()
  def serialize_public_key(p) do
    case rem(p.y, 2) do
      0 ->
        Base.encode16(<<0x02>> <> pad(:binary.encode_unsigned(p.x)), case: :lower)

      1 ->
        Base.encode16(<<0x03>> <> pad(:binary.encode_unsigned(p.x)), case: :lower)
    end
  end

  @doc """
  pads binary to 32 bytes
  """
  @spec pad(bin :: binary) :: binary
  def pad(bin) when byte_size(bin) != 32 do
    pad_len = 256 - byte_size(bin) * 8
    <<0::size(pad_len)>> <> bin
  end

  def pad(bin) do
    bin
  end
end
