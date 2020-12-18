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
        Base.encode16(<<0x02>> <> :binary.encode_unsigned(p.x), case: :lower)

      1 ->
        Base.encode16(<<0x03>> <> :binary.encode_unsigned(p.x), case: :lower)
    end
  end
end
