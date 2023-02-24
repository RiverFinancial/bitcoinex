defmodule Bitcoinex.Secp256k1.Schnorr do
  @moduledoc """
  Schnorr-specific secp256k1 operations
  """
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey, Signature}
  alias Bitcoinex.Utils

  @n Params.curve().n
  @p Params.curve().p

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

        case Secp256k1.force_even_y(privkey) do
          {:error, msg} ->
            {:error, msg}

          d ->
            d_bytes = Utils.int_to_big(d.d, 32)
            tagged_aux_hash = tagged_hash_aux(aux_bytes)
            t = Utils.xor_bytes(d_bytes, tagged_aux_hash)

            {:ok, k0} = calculate_k(t, d_point, z_bytes)

            if k0.d == 0 do
              {:error, "invalid aux randomness"}
            else
              r_point = PrivateKey.to_point(k0)

              case Secp256k1.force_even_y(k0) do
                {:error, msg} ->
                  {:error, msg}

                k ->
                  e = calculate_e(Point.x_bytes(r_point), Point.x_bytes(d_point), z_bytes)
                  sig_s = calculate_s(k, d, e)

                  {:ok, %Signature{r: r_point.x, s: sig_s}}
              end
            end
        end
    end
  end

  defp tagged_hash_aux(aux), do: Utils.tagged_hash("BIP0340/aux", aux)
  defp tagged_hash_nonce(nonce), do: Utils.tagged_hash("BIP0340/nonce", nonce)
  defp tagged_hash_challenge(chal), do: Utils.tagged_hash("BIP0340/challenge", chal)

  defp calculate_r(pubkey, s, e) do
    @generator_point
    |> Math.multiply(s)
    |> Math.add(Math.multiply(pubkey, Params.curve().n - e))
  end

  defp calculate_s(k, d, e) do
    (k.d + d.d * e)
    |> Math.modulo(@n)
  end

  defp calculate_k(t, d_point, z_bytes) do
    {:ok, k0} =
      tagged_hash_nonce(t <> Point.x_bytes(d_point) <> z_bytes)
      |> :binary.decode_unsigned()
      |> Math.modulo(@n)
      |> PrivateKey.new()

    if k0.d == 0 do
      {:error, "invalid aux randomness"}
    else
      {:ok, Secp256k1.force_even_y(k0)}
    end
  end

  defp calculate_e(nonce_bytes, pubkey_bytes, msg_bytes) do
    tagged_hash_challenge(nonce_bytes <> pubkey_bytes <> msg_bytes)
    |> :binary.decode_unsigned()
    |> Math.modulo(@n)
  end

  # this is just like validate_r but without the R.y evenness check
  defp partial_validate_r(r_point, rx) do
    cond do
      Point.is_inf(r_point) ->
        {:error, "R point is infinite"}

      r_point.x != rx ->
        {:error, "x's do not match #{r_point.x} vs #{rx}"}

      true ->
        true
    end
  end

  defp validate_r(r_point, rx) do
    cond do
      Point.is_inf(r_point) ->
        # {:error, "R point is infinite"}
        false

      !Point.has_even_y(r_point) ->
        # {:error, "R point is not even"}
        false

      r_point.x != rx ->
        # {:error, "x's do not match #{r_point.x} vs #{rx}"}
        false

      true ->
        true
    end
  end

  @doc """
    verify_signature verifies whether the Schnorr signature is valid for the given message hash and public key
  """
  @spec verify_signature(Point.t(), non_neg_integer, Signature.t()) ::
          boolean | {:error, String.t()}
  def verify_signature(_pubkey, _z, %Signature{r: r, s: s})
      when r >= @p or s >= @n,
      do: {:error, "invalid signature"}

  def verify_signature(pubkey, z, %Signature{r: r, s: s}) do
    r_bytes = Utils.int_to_big(r, 32)
    z_bytes = Utils.int_to_big(z, 32)
    e = calculate_e(r_bytes, Point.x_bytes(pubkey), z_bytes)

    r_point = calculate_r(pubkey, s, e)

    validate_r(r_point, r)
  end

  # negate a secret
  defp conditional_negate(d, true), do: %PrivateKey{d: d} |> PrivateKey.negate()
  defp conditional_negate(d, false), do: %PrivateKey{d: d}

  # negate a point (switches parity of P.y)
  defp conditional_negate_point(point, true), do: Point.negate(point)
  defp conditional_negate_point(point, false), do: point

  # Adaptor/Encrypted Signatures

  @doc """
    encrypted_sign signs a message hash z with Private Key sk but encrypts the signature using the tweak_point
    as the encryption key. The signer need not know the decryption key / tweak itself, which can later be used
    to decrypt the signature into a valid Schnorr signature. This produces an Adaptor Signature.
  """
  @spec encrypted_sign(PrivateKey.t(), non_neg_integer(), non_neg_integer(), Point.t()) ::
          {:ok, Signature.t(), boolean}
  def encrypted_sign(sk = %PrivateKey{}, z, aux, tweak_point = %Point{}) do
    z_bytes = Utils.int_to_big(z, 32)
    aux_bytes = Utils.int_to_big(aux, 32)
    d_point = PrivateKey.to_point(sk)

    d = Secp256k1.force_even_y(sk)
    d_bytes = Utils.int_to_big(d.d, 32)
    tagged_aux_hash = tagged_hash_aux(aux_bytes)
    t = Utils.xor_bytes(d_bytes, tagged_aux_hash)
    # TODO always add tweak_point to the nonce to commit to it as well
    {:ok, k0} = calculate_k(t, d_point, z_bytes)

    r_point = PrivateKey.to_point(k0)
    # ensure that tweak_point has even Y
    tweaked_r_point = Math.add(r_point, tweak_point)
    # ensure (R+T).y is even, if not, negate it, negate k, and set was_negated = true
    {tweaked_r_point, was_negated} = make_point_even(tweaked_r_point)
    k = conditional_negate(k0.d, was_negated)

    e = calculate_e(Point.x_bytes(tweaked_r_point), Point.x_bytes(d_point), z_bytes)
    s = calculate_s(k, d, e)
    # we return Signature{R+T,s}, not a valid signature since s is untweaked.
    {:ok, %Signature{r: tweaked_r_point.x, s: s}, was_negated}
  end

  @doc """
    verify_encrypted_signature verifies that an encrypted signature commits to a tweak_point / encryption key.
    This is different from a regular Schnorr signature verification, as encrypted signatures are not valid Schnorr Signatures.
  """
  @spec verify_encrypted_signature(
          Signature.t(),
          Point.t(),
          non_neg_integer(),
          Point.t(),
          boolean
        ) :: boolean
  def verify_encrypted_signature(
        %Signature{r: tweaked_r, s: s},
        pk = %Point{},
        z,
        tweak_point = %Point{},
        was_negated
      ) do
    z_bytes = Utils.int_to_big(z, 32)

    {:ok, tweaked_r_point} = Point.lift_x(tweaked_r)
    # This is subtracting the tweak_point (T) from the tweaked_point (R + T) to get the original R
    tweak_point = conditional_negate_point(tweak_point, !was_negated)
    r_point = Math.add(tweaked_r_point, tweak_point)

    e = calculate_e(Point.x_bytes(tweaked_r_point), Point.x_bytes(pk), z_bytes)
    r_point2 = calculate_r(pk, s, e)
    partial_validate_r(r_point, r_point2.x)
  end

  defp make_point_even(point) do
    if Point.has_even_y(point) do
      {point, false}
    else
      {Point.negate(point), true}
    end
  end

  @doc """
    decrypt_signature uses the tweak/decryption key to transform an
    adaptor/encrypted signature into a final, valid Schnorr signature.
  """
  @spec decrypt_signature(Signature.t(), PrivateKey.t(), boolean) :: Signature.t()
  def decrypt_signature(%Signature{r: r, s: s}, tweak, was_negated) do
    # force even on tweak is a backup. the passed tweak should already be properly negated
    tweak = conditional_negate(tweak.d, was_negated)
    final_s = Math.modulo(tweak.d + s, @n)
    %Signature{r: r, s: final_s}
  end

  @doc """
    recover_decryption_key recovers the tweak or decryption key by
    subtracting final_sig.s - encrypted_sig.s (mod n). The tweak is
    negated if the original R+T point was negated during signing.
  """
  @spec recover_decryption_key(Signature.t(), Signature.t(), boolean) ::
          PrivateKey.t() | {:error, String.t()}
  def recover_decryption_key(%Signature{r: enc_r}, %Signature{r: r}, _, _) when enc_r != r,
    do: {:error, "invalid signature pair"}

  def recover_decryption_key(
        _encrypted_sig = %Signature{s: enc_s},
        _sig = %Signature{s: s},
        was_negated
      ) do
    t = Math.modulo(s - enc_s, @n)
    conditional_negate(t, was_negated)
  end
end
