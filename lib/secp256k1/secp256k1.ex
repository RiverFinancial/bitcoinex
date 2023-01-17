defmodule Bitcoinex.Secp256k1 do
  @moduledoc """
  General Secp256k1 curve operations.
  libsecp256k1: https://github.com/bitcoin-core/secp256k1

  Currently supports ECDSA public key recovery.

  In the future, we will NIF for critical operations. However, it is more portable to have a native elixir version.
  """
  import Bitwise
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}

  defmodule Signature do
    @moduledoc """
    Contains r,s in signature.
    """
    alias Bitcoinex.Utils

    @type t :: %__MODULE__{
            r: pos_integer(),
            s: pos_integer()
          }

    @enforce_keys [
      :r,
      :s
    ]
    defstruct [:r, :s]

    @spec parse_signature(binary) ::
            {:ok, t()} | {:error, String.t()}
    @doc """
    accepts a compact signature and returns a Signature containing r,s
    """
    def parse_signature(<<r::binary-size(32), s::binary-size(32)>>) do
      # Get r,s from signature.
      r = :binary.decode_unsigned(r)
      s = :binary.decode_unsigned(s)

      # Verify that r,s are integers in [1, n-1] where n is the integer order of G.
      cond do
        r < 1 ->
          {:error, "invalid signature"}

        r > Params.curve().n - 1 ->
          {:error, "invalid signature"}

        s < 1 ->
          {:error, "invalid signature"}

        s > Params.curve().n - 1 ->
          {:error, "invalid signature"}

        true ->
          {:ok, %Signature{r: r, s: s}}
      end
    end

    # attempt to parse 64-byte string
    def parse_signature(compact_sig) when is_binary(compact_sig) do
      case Utils.hex_to_bin(compact_sig) do
        {:error, msg} ->
          {:error, msg}

        sig_bytes ->
          parse_signature(sig_bytes)
      end
    end

    def parse_signature(_), do: {:error, "invalid signature size"}

    @doc """
    der_parse_signature parses a DER binary to a Signature
    """
    # @spec der_parse_signature(binary) :: {:ok, Signature.()} | {:error, String.t()}
    def der_parse_signature(<<0x30>> <> der_sig) when is_binary(der_sig) do
      sig_len = :binary.at(der_sig, 0)

      if sig_len + 1 != byte_size(der_sig) do
        {:error, "invalid signature length"}
      else
        case parse_sig_key(der_sig, 1) do
          {:error, err} ->
            {:error, err}

          {r, s_pos} ->
            case parse_sig_key(der_sig, s_pos) do
              {:error, err} ->
                {:error, err}

              {s, sig_len} ->
                if sig_len != byte_size(der_sig) do
                  {:error, "invalid signature: signature is too long"}
                else
                  {:ok, %Signature{r: r, s: s}}
                end
            end
        end
      end
    end

    def der_parse_signature(_), do: {:error, "invalid signature"}

    defp parse_sig_key(data, pos) do
      if :binary.at(data, pos) != 0x02 do
        {:error, "invalid signature key marker"}
      else
        k_len = :binary.at(data, pos + 1)
        len_k = :binary.part(data, pos + 2, k_len)
        {:binary.decode_unsigned(len_k), pos + 2 + k_len}
      end
    end

    @spec serialize_signature(t()) :: binary
    def serialize_signature(%__MODULE__{r: r, s: s}) do
      :binary.encode_unsigned(r) <> :binary.encode_unsigned(s)
    end

    @doc """
    der_serialize_signature returns the DER serialization of an ecdsa signature
    """
    @spec der_serialize_signature(Signature.t()) :: binary
    def der_serialize_signature(%Signature{r: r, s: s}) do
      r_bytes = serialize_sig_key(r)
      s_bytes = serialize_sig_key(s)
      <<0x30>> <> len_as_bytes(r_bytes <> s_bytes) <> r_bytes <> s_bytes
    end

    def der_serialize_signature(_), do: {:error, "Signature object required"}

    defp serialize_sig_key(k) do
      k
      |> :binary.encode_unsigned()
      |> lstrip(<<0x00>>)
      |> add_high_bit()
      |> prefix_key()
    end

    defp len_as_bytes(data), do: :binary.encode_unsigned(byte_size(data))

    defp lstrip(<<head::binary-size(1)>> <> tail, val) do
      if head == val, do: lstrip(tail, val), else: head <> tail
    end

    defp add_high_bit(k_bytes) do
      unless (:binary.at(k_bytes, 0) &&& 0x80) == 0 do
        <<0x00>> <> k_bytes
      else
        k_bytes
      end
    end

    defp prefix_key(k_bytes), do: <<0x02>> <> len_as_bytes(k_bytes) <> k_bytes
  end

  @doc """
  Returns the y-coordinate of a secp256k1 curve point (P) using the x-coordinate.
  To get P(y), we solve for y in this equation: y^2 = x^3 + 7.
  """
  @spec get_y(integer, boolean) :: {:ok, integer} | {:error, String.t()}
  def get_y(x, is_y_odd) do
    # x^3 + 7
    y_sq =
      :crypto.mod_pow(x, 3, Params.curve().p)
      |> :binary.decode_unsigned()
      |> Kernel.+(7 |> Math.modulo(Params.curve().p))

    # Solve for y.
    y =
      :crypto.mod_pow(y_sq, Integer.floor_div(Params.curve().p + 1, 4), Params.curve().p)
      |> :binary.decode_unsigned()

    y =
      case rem(y, 2) == 1 do
        ^is_y_odd ->
          y

        _ ->
          Params.curve().p - y
      end

    # Check.
    if y_sq != :crypto.mod_pow(y, 2, Params.curve().p) |> :binary.decode_unsigned() do
      {:error, "invalid sq root"}
    else
      {:ok, y}
    end
  end

  @doc """
    force_even_y returns the negated private key
    if the associated Point has an odd y. Otherwise
    it returns the private key
  """
  @spec force_even_y(PrivateKey.t()) :: PrivateKey.t() | {:error, String.t()}
  def force_even_y(%PrivateKey{} = privkey) do
    case PrivateKey.to_point(privkey) do
      {:error, msg} ->
        {:error, msg}

      pubkey ->
        if Point.is_inf(pubkey) do
          {:error, "pubkey is infinity. bad luck"}
        end

        if Point.has_even_y(pubkey) do
          privkey
        else
          %PrivateKey{d: Params.curve().n - privkey.d}
        end
    end
  end

  @doc """
    verify_point verifies that a given point is on the secp256k1
    curve
  """
  @spec verify_point(Point.t()) :: bool
  def verify_point(%Point{x: x, y: y}) do
    y_odd = rem(y, 2) == 1
    {:ok, new_y} = get_y(x, y_odd)
    y == new_y
  end
end
