defmodule Bitcoinex.Secp256k1 do
  @moduledoc """
  ECDSA Secp256k1 curve operations.
  libsecp256k1: https://github.com/bitcoin-core/secp256k1

  Currently supports ECDSA public key recovery.

  In the future, we will NIF for critical operations. However, it is more portable to have a native elixir version.
  """
  use Bitwise, only_operators: true
  alias Bitcoinex.Secp256k1.{Math, Params, Point}

  @generator_point %Point{
    x: Params.curve().g_x,
    y: Params.curve().g_y
  }

  defmodule Signature do
    @moduledoc """
    Contains r,s in signature.
    """

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

    def parse_signature(compact_sig) when is_binary(compact_sig),
      do: {:error, "invalid signature size"}

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

    @doc """
    der_serialize_signature returns the DER serialization of an ecdsa signature
    """
    @spec der_serialize_signature(Signature.t()) :: :binary
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
  ecdsa_recover_compact does ECDSA public key recovery.
  """
  @spec ecdsa_recover_compact(binary, binary, integer) ::
          {:ok, binary} | {:error, String.t()}
  def ecdsa_recover_compact(msg, compact_sig, recoveryId) do
    # Parse r and s from the signature.
    case Signature.parse_signature(compact_sig) do
      {:ok, sig} ->
        # Find the iteration.

        # R(x) = (n * i) + r
        # where n is the order of the curve and R is from the signature.
        r_x = Params.curve().n * Integer.floor_div(recoveryId, 2) + sig.r

        # Check that R(x) is on the curve.
        if r_x > Params.curve().p do
          {:error, "R(x) is not on the curve"}
        else
          # Decompress to get R(y).
          case get_y(r_x, rem(recoveryId, 2) == 1) do
            {:ok, r_y} ->
              # R(x,y)
              point_r = %Point{x: r_x, y: r_y}

              # Point Q is the recovered public key.
              # We satisfy this equation: Q = r^-1(sR-eG)
              inv_r = Math.inv(sig.r, Params.curve().n)
              inv_r_s = (inv_r * sig.s) |> Math.modulo(Params.curve().n)

              # R*s
              point_sr = Math.multiply(point_r, inv_r_s)

              # Find e using the message hash.
              e =
                :binary.decode_unsigned(msg)
                |> Kernel.*(-1)
                |> Math.modulo(Params.curve().n)
                |> Kernel.*(inv_r |> Math.modulo(Params.curve().n))

              # G*e
              point_ge = Math.multiply(@generator_point, e)

              # R*e * G*e
              point_q = Math.add(point_sr, point_ge)

              # Returns serialized compressed public key.
              {:ok, Point.serialize_public_key(point_q)}

            {:error, error} ->
              {:error, error}
          end
        end

      {:error, e} ->
        {:error, e}
    end
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
  verify whether the signature is valid for the given message hash and public key
  """
  @spec verify_signature(Point.t(), integer, Signature.t()) :: boolean
  def verify_signature(pubkey, sighash, %Signature{r: r, s: s}) do
    n = Params.curve().n
    s_inv = Math.inv(s, n)
    u = Math.modulo(sighash * s_inv, n)
    v = Math.modulo(r * s_inv, n)
    total = Math.add(Math.multiply(@generator_point, u), Math.multiply(pubkey, v))
    total.x == r
  end
end
