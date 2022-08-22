defmodule Bitcoinex.Secp256k1.Schnorr do
  @moduledoc """
  Schnorr-specific secp256k1 operations
  """
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey, Signature}
  alias Bitcoinex.Utils

  @n Params.curve().n

  @generator_point %Point{
    x: Params.curve().g_x,
    y: Params.curve().g_y
  }

  @spec sign(PrivateKey.t(), non_neg_integer(), non_neg_integer()) :: {:ok, Signature.t()} | {:error, String.t()}
  def sign(privkey, z, aux) do
    case PrivateKey.validate(privkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, privkey} ->
        z_bytes = Utils.int_to_big(z, 32)
        aux_bytes = Utils.int_to_big(aux, 32)
        d_point = PrivateKey.to_point(privkey)
        d = Secp256k1.force_even_y(privkey)
        d_bytes = Utils.int_to_big(d.d, 32)
        tagged_aux_hash = tagged_hash_aux(aux_bytes)
        t = Utils.xor_bytes(d_bytes, tagged_aux_hash)

        {:ok, k0} =
          tagged_hash_nonce(t <> Point.x_bytes(d_point) <> z_bytes)
          |> :binary.decode_unsigned()
          |> Math.modulo(@n)
          |> PrivateKey.new

        if k0.d == 0 do
          {:error, "invalid aux randomness"}
        else
          r_point = PrivateKey.to_point(k0)
          k = Secp256k1.force_even_y(k0)

          e =
            tagged_hash_challenge(Point.x_bytes(r_point) <> Point.x_bytes(d_point) <> z_bytes)
            |> :binary.decode_unsigned()
            |> Math.modulo(@n)

          sig_s =
            k.d + (d.d * e)
            |> Math.modulo(@n)

          {:ok, %Signature{r: r_point.x, s: sig_s}}
      end
    end
  end

  defp tagged_hash_aux(aux), do: Utils.tagged_hash("BIP0340/aux", aux)
  defp tagged_hash_nonce(nonce), do: Utils.tagged_hash("BIP0340/nonce", nonce)
  defp tagged_hash_challenge(chal), do: Utils.tagged_hash("BIP0340/challenge", chal)

  @doc """
    verify whether the schnorr signature is valid for the given message hash and public key
  """
  @spec verify_signature(Point.t(), non_neg_integer, Signature.t()) :: boolean | {:error, String.t()}
  def verify_signature(pubkey, z, %Signature{r: r, s: s}) do
    if r >= Params.curve().p || s >= Params.curve().n, do: {:error, "invalid signature"}

    r_bytes = Utils.int_to_big(r, 32)
    z_bytes = Utils.int_to_big(z, 32)
    e =
      tagged_hash_challenge(r_bytes <> Point.x_bytes(pubkey) <> z_bytes)
      |> :binary.decode_unsigned()
      |> Math.modulo(@n)

    r_point =
      @generator_point
      |> Math.multiply(s)
      |> Math.add(Math.multiply(pubkey, Params.curve().n - e))

    !Point.is_inf(r_point) && Point.has_even_y(r_point) && r_point.x == r
  end
end
