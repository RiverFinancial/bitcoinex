defmodule Bitcoinex.Secp256k1.PrivateKey do
  @moduledoc """
   	Contains an integer used to create a Point and sign.
  """
  alias Bitcoinex.Secp256k1.{Params, Math, Point, Signature}
  alias Bitcoinex.Base58

  @max_privkey Params.curve().n - 1

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
  @spec new(non_neg_integer()) :: {:ok, t()}
  def new(d) do
    validate(%__MODULE__{d: d})
  end

  @doc """
    to_point calculate Point from private key
  """
  @spec to_point(t()) :: Point.t()
  def to_point(prvkey = %__MODULE__{}) do
    case validate(prvkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, %__MODULE__{d: d}} ->
        g = %Point{x: Params.curve().g_x, y: Params.curve().g_y, z: 0}
        Math.multiply(g, d)
    end
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
        |> Bitcoinex.Utils.pad(32, :leading)
        |> Base.encode16(case: :lower)
    end
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
        |> Bitcoinex.Utils.pad(32, :leading)
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

  def deterministic_k(%__MODULE__{d: d}, raw_z) do
    # RFC 6979 https://tools.ietf.org/html/rfc6979#section-3.2
    k = :binary.list_to_bin(List.duplicate(<<0x00>>, 32))
    v = :binary.list_to_bin(List.duplicate(<<0x01>>, 32))
    n = Params.curve().n
    z = lower_z(raw_z, n)
    # 3.2(d) - pad z and privkey for use
    sighash = Bitcoinex.Utils.pad(:binary.encode_unsigned(z), 32, :leading)
    secret = Bitcoinex.Utils.pad(:binary.encode_unsigned(d), 32, :leading)
    # 3.2(d) - hmac with key k
    k = :crypto.mac(:hmac, :sha256, k, v <> <<0x00>> <> secret <> sighash)
    # 3.2(e) - update v
    v = :crypto.mac(:hmac, :sha256, k, v)
    # 3.2(f) - update k
    k = :crypto.mac(:hmac, :sha256, k, v <> <<0x01>> <> secret <> sighash)
    # 3.2(g) - update v
    v = :crypto.mac(:hmac, :sha256, k, v)
    # 3.2(h) - algorithm
    final_k = find_candidate(k, v, n)
    %__MODULE__{d: final_k}
  end

  defp find_candidate(k, v, n) do
    # RFC 6979 https://tools.ietf.org/html/rfc6979#section-3.2
    v = :crypto.mac(:hmac, :sha256, k, v)
    candidate = :binary.decode_unsigned(v)
    # 3.2(h).3 - check candidate in [1,n-1] and r != 0
    if candidate >= 1 and candidate < n and to_point(%__MODULE__{d: candidate}).x != 0 do
      candidate
    else
      # if candidate is invalid
      k = :crypto.mac(:hmac, :sha256, k, v <> <<0x00>>)
      v = :crypto.mac(:hmac, :sha256, k, v)
      find_candidate(k, v, n)
    end
  end

  defp lower_z(z, n) do
    if z > n, do: z - n, else: z
  end

  @doc """
  sign returns an ECDSA signature using the privkey and z
  where privkey is a PrivateKey object and z is an integer.
  The nonce is derived using RFC6979.
  """
  @spec sign(t(), integer) :: Signature.t()
  def sign(privkey, z) do
    case validate(privkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, privkey} ->
        k = deterministic_k(privkey, z)
        n = Params.curve().n
        sig_r = to_point(k).x
        inv_k = Math.inv(k.d, n)
        sig_s = Math.modulo((z + sig_r * privkey.d) * inv_k, n)

        if sig_s > n / 2 do
          %Signature{r: sig_r, s: n - sig_s}
        else
          %Signature{r: sig_r, s: sig_s}
        end
    end
  end

  @doc """
  sign_message returns an ECDSA signature using the privkey and "Bitcoin Signed Message: <msg>"
  where privkey is a PrivateKey object and msg is a binary message to be hashed.
  The message is hashed using hash256 (double SHA256) and the nonce is derived
  using RFC6979.
  """
  @spec sign_message(t(), binary) :: Signature.t()
  def sign_message(privkey, msg) do
    z =
      ("Bitcoin Signed Message:\n" <> msg)
      |> Bitcoinex.Utils.double_sha256()
      |> :binary.decode_unsigned()

    sign(privkey, z)
  end
end
