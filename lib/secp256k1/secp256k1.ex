defmodule Bitcoinex.Secp256k1 do
  @moduledoc """
  ECDSA Secp256k1 curve operations.
  libsecp256k1: https://github.com/bitcoin-core/secp256k1

  Currently supports ECDSA public key recovery.

  In the future, we will NIF for critical operations. However, it is more portable to have a native elixir version.
  """
  use Bitwise, only_operators: true
  alias Bitcoinex.Secp256k1.{Math, Params, Point}

  defmodule Signature do
    defstruct [:r, :s]

    @spec parse_signature(binary) ::
            {:ok, Signature} | {:error, String.t()}
    def parse_signature(compact_sig) when byte_size(compact_sig) != 65,
      do: {:error, "invalid signature size"}

    def parse_signature(compact_sig) do
      # Get R and S from signature
      <<_::binary-size(1), r::binary-size(32), s::binary-size(32), _rest::bytes>> = compact_sig
      {:ok, %Signature{r: :binary.decode_unsigned(r), s: :binary.decode_unsigned(s)}}
    end

    def get_iteration(compact_sig) do
      :binary.part(compact_sig, {0, 1})
      |> :binary.decode_unsigned()
      |> Kernel.-(27) &&& ~~~4
    end
  end

  @spec ecdsa_recover_compact(binary, binary, integer) ::
          {:ok, binary} | {:error, String.t()}
  # ecdsa_recover_compact does ECDSA public key recovery.
  def ecdsa_recover_compact(msg, compact_sig, recoveryId) do
    # Assign header byte to signature using recoveryID
    compact_sig = <<recoveryId + 27 + 4>> <> compact_sig

    # Parse R and S from the signature.
    case Signature.parse_signature(compact_sig) do
      {:ok, sig} ->
        # Find the iteration.
        iteration = Signature.get_iteration(compact_sig)

        # R(x) = (n * i) + R
        # where n is the order of the curve and R is from the signature.
        r_x = Params.curve().n * Integer.floor_div(iteration, 2) + sig.r

        # Check that R(x) is on the curve.
        if r_x > Params.curve().p do
          {:error, "R(x) is not on the curve"}
        else
          # Decompress the point to get R(y).
          case get_y(r_x, rem(iteration, 2) == 1) do
            {:ok, r_y} ->
              # Point R(x,y) using the signature.
              point_r = %Point{x: r_x, y: r_y}

              # Q = r^-1(sR-eG) 
              inv_r = Math.inv(sig.r, Params.curve().n)
              inv_r_s = (inv_r * sig.s) |> Math.modulo(Params.curve().n)

              # s*R
              point_sr = Math.multiply(point_r, inv_r_s)

              # Find e using the message hash.
              e =
                :binary.decode_unsigned(msg)
                |> Kernel.*(-1)
                |> Math.modulo(Params.curve().n)
                |> Kernel.*(inv_r |> Math.modulo(Params.curve().n))

              # Generator Point.
              # TODO, move somewhere else.
              point_g = %Point{
                x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
              }

              # G*x
              point_gx = Math.multiply(point_g, e)

              #  s*R * G*x 
              point_q = Math.add(point_sr, point_gx)

              {:ok, Point.serialize_public_key(point_q)}

            {:error, error} ->
              {:error, error}
          end
        end

      {:error, e} ->
        {:error, e}
    end
  end

  # Returns the y-coordinate of a secp256k1 curve point using the x-coordinate.
  def get_y(x, y_bit) do
    # y^2 = x^3 + 7
    y_sq =
      :crypto.mod_pow(x, 3, Params.curve().p)
      |> :binary.decode_unsigned()
      |> Kernel.+(7 |> Math.modulo(Params.curve().p))

    # Solve for y.
    y =
      :crypto.mod_pow(y_sq, Integer.floor_div(Params.curve().p + 1, 4), Params.curve().p)
      |> :binary.decode_unsigned()

    y =
      if rem(y, 2) == 1 != y_bit do
        Params.curve().p - y
      else
        y
      end

    if y_sq != :crypto.mod_pow(y, 2, Params.curve().p) |> :binary.decode_unsigned() do
      {:error, "invalid sq root"}
    else
      {:ok, y}
    end
  end
end
