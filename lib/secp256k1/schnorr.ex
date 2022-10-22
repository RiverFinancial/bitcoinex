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

  @spec sign(PrivateKey.t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, Signature.t()} | {:error, String.t()}
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
          |> PrivateKey.new()

        if k0.d == 0 do
          {:error, "invalid aux randomness"}
        else
          r_point = PrivateKey.to_point(k0)
          k = Secp256k1.force_even_y(k0)

          e = calculate_e(r_point, d_point, z_bytes)

          sig_s = calculate_s(k, d, e)

          {:ok, %Signature{r: r_point.x, s: sig_s}}
        end
    end
  end

  @spec tweaked_sign(PrivateKey.t(), non_neg_integer, non_neg_integer, Point.t()) ::
          {:ok, Signature.t(), Point.t()} | {:error, String.t()}
  def tweaked_sign(privkey, z, aux, pubtweak) do
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
          |> PrivateKey.new()

        if k0.d == 0 do
          {:error, "invalid aux randomness"}
        else
          r_point = PrivateKey.to_point(k0)
          k = Secp256k1.force_even_y(k0)

          tweaked_r_point = Math.add(r_point, pubtweak)

          e = calculate_e(Point.x_bytes(tweaked_r_point), Point.x_bytes(d_point), z_bytes)

          sig_s = calculate_s(k, d, e)

          {:ok, %Signature{r: r_point.x, s: sig_s}, pubtweak}
        end
    end
  end

  defp tagged_hash_aux(aux), do: Utils.tagged_hash("BIP0340/aux", aux)
  defp tagged_hash_nonce(nonce), do: Utils.tagged_hash("BIP0340/nonce", nonce)
  defp tagged_hash_challenge(chal), do: Utils.tagged_hash("BIP0340/challenge", chal)

  defp calculate_s(k, d, e) do
    (k.d + d.d * e)
    |> Math.modulo(@n)
  end

  defp calculate_e(nonce_bytes, pubkey_bytes, msg_bytes) do
    tagged_hash_challenge(nonce_bytes <> pubkey_bytes <> msg_bytes)
    |> :binary.decode_unsigned()
    |> Math.modulo(@n)
  end

  def validate_r(r_point, rx) do
    !Point.is_inf(r_point) && Point.has_even_y(r_point) && r_point.x == rx
  end

  @doc """
    verify whether the schnorr signature is valid for the given message hash and public key
  """
  @spec verify_signature(Point.t(), non_neg_integer, Signature.t()) ::
          boolean | {:error, String.t()}
  def verify_signature(pubkey, z, %Signature{r: r, s: s}) do
    if r >= Params.curve().p || s >= Params.curve().n, do: {:error, "invalid signature"}

    r_bytes = Utils.int_to_big(r, 32)
    z_bytes = Utils.int_to_big(z, 32)

    e = calculate_e(r_bytes, Point.x_bytes(pubkey), z_bytes)

    r_point =
      @generator_point
      |> Math.multiply(s)
      |> Math.add(Math.multiply(pubkey, Params.curve().n - e))

    validate_r(r_point, r)
  end

  @spec verify_tweaked_signature(Point.t(), non_neg_integer, Signature.t(), Point.t()) ::
          boolean | {:error, String.t()}
  def verify_tweaked_signature(pubkey, z, %Signature{r: r, s: s}, pubtweak) do
    if r >= Params.curve().p || s >= Params.curve().n, do: {:error, "invalid signature"}

    case Point.lift_x(r) do
      {:error, err} ->
        {:error, err}

      {:ok, given_r_point} ->
        tweaked_point = Math.add(given_r_point, pubtweak)

        z_bytes = Utils.int_to_big(z, 32)

        e = calculate_e(Point.x_bytes(tweaked_point), Point.x_bytes(pubkey), z_bytes)

        r_point =
          @generator_point
          |> Math.multiply(s)
          |> Math.add(Math.multiply(pubkey, Params.curve().n - e))

        validate_r(r_point, r)
    end
  end

  @spec extract_tweak(Point.t(), non_neg_integer, Signature.t(), Signature.t()) ::
          {:ok, non_neg_integer} | {:error, String.t()}
  def extract_tweak(pubkey, z, %Signature{s: s}, %Signature{r: tweaked_r, s: tweaked_s}) do
    tweaked_r_bytes = Utils.int_to_big(tweaked_r, 32)

    z_bytes = Utils.int_to_big(z, 32)
    e = calculate_e(tweaked_r_bytes, Point.x_bytes(pubkey), z_bytes)

    tweaked_r_point =
      @generator_point
      |> Math.multiply(tweaked_s)
      |> Math.add(Math.multiply(pubkey, Params.curve().n - e))

    if validate_r(tweaked_r_point, tweaked_r) do
      if tweaked_s < s do
        {:error, "invalid tweak"}
      else
        {:ok, tweaked_s - s}
      end
    else
      {:error, "failed to extract tweak due to invalid signature"}
    end
  end

  @spec extract_tweaked_signature(Point.t(), non_neg_integer, Signature.t(), non_neg_integer) ::
          {:ok, Signature.t()} | {:error, String.t()}
  def extract_tweaked_signature(pubkey, z, %Signature{r: r, s: s}, tweak) do
    case Point.lift_x(r) do
      {:error, err} ->
        {:error, err}

      {:ok, r_point} ->
        tweak_point = PrivateKey.to_point(tweak)

        tweaked_r = Math.add(r_point, tweak_point).x
        tweaked_s = tweak + s

        r_bytes = Utils.int_to_big(r, 32)
        z_bytes = Utils.int_to_big(z, 32)
        e = calculate_e(r_bytes, Point.x_bytes(pubkey), z_bytes)

        tweaked_r_point =
          @generator_point
          |> Math.multiply(tweaked_s)
          |> Math.add(Math.multiply(pubkey, Params.curve().n - e))

        if validate_r(tweaked_r_point, tweaked_r) do
          {:ok, %Signature{r: tweaked_r, s: tweaked_s}}
        else
          {:error, "tweak does not produce valid signature"}
        end
    end
  end
end
