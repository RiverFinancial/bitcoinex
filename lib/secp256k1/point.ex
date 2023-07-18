defmodule Bitcoinex.Secp256k1.Point do
  @moduledoc """
  Contains the x, y, and z of an elliptic curve point.
  """

  import Bitwise
  alias Bitcoinex.Utils
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.Params

  @p Params.curve().p

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
    is_inf returns whether or not point P is
    the point at infinity, ie. P.x == P.y == 0
  """
  @spec is_inf(t()) :: boolean
  def is_inf(%__MODULE__{x: 0, y: 0}), do: true
  def is_inf(_), do: false

  @doc """
  parse_public_key parses a public key
  """
  @spec parse_public_key(binary) :: {:ok, t()} | {:error, String.t()}
  def parse_public_key(<<0x04, x::binary-size(32), y::binary-size(32)>>) do
    {:ok, %__MODULE__{x: :binary.decode_unsigned(x), y: :binary.decode_unsigned(y)}}
  end

  # Above matches with uncompressed keys. Below matches with compressed keys
  def parse_public_key(<<prefix::binary-size(1), x_bytes::binary-size(32)>>) do
    x = :binary.decode_unsigned(x_bytes)

    case :binary.decode_unsigned(prefix) do
      2 ->
        case Bitcoinex.Secp256k1.get_y(x, false) do
          {:ok, y} -> {:ok, %__MODULE__{x: x, y: y}}
          _ -> {:error, "invalid public key"}
        end

      3 ->
        case Bitcoinex.Secp256k1.get_y(x, true) do
          {:ok, y} -> {:ok, %__MODULE__{x: x, y: y}}
          _ -> {:error, "invalid public key"}
        end

      _ ->
        {:error, "invalid public key"}
    end
  end

  # Allow parse_public_key to parse SEC strings
  def parse_public_key(key) do
    key
    |> String.downcase()
    |> Base.decode16!(case: :lower)
    |> parse_public_key()
  end

  @doc """
    lift_x returns the Point P where P.x = x
    and P.y is even.
  """
  @spec lift_x(integer | binary) :: {:ok, t()} | {:error, String.t()}
  def lift_x(x) when is_integer(x) and x >= @p, do: {:error, "invalid x value (too large)"}

  def lift_x(x) when is_integer(x) do
    case Secp256k1.get_y(x, false) do
      {:ok, y} ->
        {:ok, %__MODULE__{x: x, y: y}}

      err ->
        err
    end
  end

  # parse 32-byte binary
  def lift_x(<<x::binary-size(32)>>) do
    x
    |> :binary.decode_unsigned()
    |> lift_x
  end

  # attempt to parse x-only pubkey from hex
  def lift_x(x) when is_binary(x) do
    case Utils.hex_to_bin(x) do
      {:error, msg} ->
        {:error, msg}

      x_bytes ->
        lift_x(x_bytes)
    end
  end

  @doc """
  sec serializes a compressed public key to binary
  """
  @spec sec(t()) :: binary
  def sec(%__MODULE__{x: x, y: y}) do
    case rem(y, 2) do
      0 ->
        <<0x02>> <> Bitcoinex.Utils.pad(:binary.encode_unsigned(x), 32, :leading)

      1 ->
        <<0x03>> <> Bitcoinex.Utils.pad(:binary.encode_unsigned(x), 32, :leading)
    end
  end

  @doc """
    x_bytes returns the binary encoding of the x value of the point
  """
  @spec x_bytes(t()) :: binary
  def x_bytes(%__MODULE__{x: x}) do
    Bitcoinex.Utils.pad(:binary.encode_unsigned(x), 32, :leading)
  end

  @doc """
    x_hex returns the hex-encoded x value of the point
  """
  @spec x_hex(t()) :: String.t()
  def x_hex(p) do
    p
    |> x_bytes()
    |> Base.encode16(case: :lower)
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

  @doc """
    has_even_y returns true if y is
    even and false if y is odd
  """
  @spec has_even_y(t()) :: boolean
  def has_even_y(%__MODULE__{y: y}) do
    (y &&& 1) == 0
  end
end
