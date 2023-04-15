defmodule Bitcoinex.Secp256k1.PrivateKey do
  @moduledoc """
   	Contains an integer used to create a Point and sign.
  """
  alias Bitcoinex.Secp256k1.{Params, Math, Point}
  alias Bitcoinex.Base58
  alias Bitcoinex.Utils

  @n Params.curve().n

  @max_privkey @n - 1

  @type t :: %__MODULE__{
          d: non_neg_integer()
        }

  @enforce_keys [
    :d
  ]
  defstruct [:d]

  def validate(%__MODULE__{d: d}) do
    if d > @max_privkey do
      {:error, "invalid private key out of range."}
    else
      {:ok, %__MODULE__{d: d}}
    end
  end

  @doc """
    new creates a private key from an integer
  """
  @spec new(non_neg_integer()) :: {:ok, t()} | {:error, String.t()}
  def new(d) do
    validate(%__MODULE__{d: d})
  end

  @doc """
    to_point calculate Point from private key or integer
  """
  @spec to_point(t() | non_neg_integer()) :: Point.t() | {:error, String.t()}
  def to_point(prvkey = %__MODULE__{}) do
    case validate(prvkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, %__MODULE__{d: d}} ->
        g = %Point{x: Params.curve().g_x, y: Params.curve().g_y, z: 0}
        Math.multiply(g, d)
    end
  end

  def to_point(d) when is_integer(d) do
    case new(d) do
      {:ok, sk} ->
        to_point(sk)

      {:error, msg} ->
        {:error, msg}
    end
  end

  @spec negate(t()) :: t()
  def negate(%__MODULE__{d: d}) do
    %__MODULE__{d: @n - d}
  end

  @doc """
   serialize_private_key serializes a private key into hex
  """
  @spec serialize_private_key(t()) :: String.t()
  def serialize_private_key(prvkey = %__MODULE__{}) do
    case validate(prvkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, %__MODULE__{d: d}} ->
        d
        |> :binary.encode_unsigned()
        |> Utils.pad(32, :leading)
        |> Base.encode16(case: :lower)
    end
  end

  @spec to_hex(Bitcoinex.Secp256k1.PrivateKey.t()) :: String.t()
  def to_hex(%__MODULE__{d: d}) do
    d
    |> :binary.encode_unsigned()
    |> Utils.pad(32, :leading)
    |> Base.encode16(case: :lower)
  end

  @doc """
  wif returns the base58check encoded private key as a string
  assumes all keys are compressed
  """
  @spec wif!(t(), Bitcoinex.Network.network_name()) :: String.t()
  def wif!(prvkey = %__MODULE__{}, network_name) do
    case validate(prvkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, %__MODULE__{d: d}} ->
        d
        |> :binary.encode_unsigned()
        |> Utils.pad(32, :leading)
        |> wif_prefix(network_name)
        |> compressed_suffix()
        |> Base58.encode()
    end
  end

  def parse_wif!(wif_str) do
    {:ok, privkey, _, _} = parse_wif(wif_str)
    privkey
  end

  @doc """
  returns the base58check encoded private key as a string
  assumes all keys are compressed
  """
  @spec parse_wif(String.t()) :: {:ok, t(), atom, boolean}
  def parse_wif(wif_str) do
    {state, bin} = Base58.decode(wif_str)

    case state do
      :error -> {:error, bin}
      :ok -> parse_wif_bin(bin)
    end
  end

  # parse compressed
  @spec parse_wif_bin(binary) :: {:ok, t(), atom, boolean}
  def parse_wif_bin(<<prefix::binary-size(1), wif::binary-size(32), 0x01>>) do
    {state, network_name} = wif_prefix(prefix)

    if state == :error do
      {:error, network_name}
    else
      secret = :binary.decode_unsigned(wif)

      case validate(%__MODULE__{d: secret}) do
        {:error, msg} ->
          {:error, msg}

        {:ok, %__MODULE__{d: d}} ->
          {:ok, %__MODULE__{d: d}, network_name, true}
      end
    end
  end

  # parse uncompressed
  def parse_wif_bin(<<prefix::binary-size(1), wif::binary-size(32)>>) do
    {state, network_name} = wif_prefix(prefix)

    if state == :error do
      {:error, network_name}
    else
      secret = :binary.decode_unsigned(wif)

      case validate(%__MODULE__{d: secret}) do
        {:error, msg} ->
          {:error, msg}

        {:ok, %__MODULE__{d: d}} ->
          {:ok, %__MODULE__{d: d}, network_name, false}
      end
    end
  end

  defp compressed_suffix(binary), do: binary <> <<0x01>>
  # encoding
  defp wif_prefix(binary, :mainnet), do: <<0x80>> <> binary
  defp wif_prefix(binary, :testnet), do: <<0xEF>> <> binary
  defp wif_prefix(binary, :regtest), do: <<0xEF>> <> binary
  # decoding
  defp wif_prefix(<<0x80>>), do: {:ok, :mainnet}
  defp wif_prefix(<<0xEF>>), do: {:ok, :testnet}
  defp wif_prefix(_), do: {:error, "unrecognized network prefix for WIF"}
end
