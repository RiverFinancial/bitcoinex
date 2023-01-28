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
                  e = calculate_e(Point.x_bytes(r_point) <> Point.x_bytes(d_point) <> z_bytes)
                  sig_s = calculate_s(k,d,e)

                  {:ok, %Signature{r: r_point.x, s: sig_s}}
              end
            end
        end
    end
  end

  @spec sign_for_tweak(PrivateKey.t(), non_neg_integer, non_neg_integer, Point.t()) ::
          {:ok, Signature.t(), Point.t(), bool} | {:error, String.t()}
  def sign_for_tweak(privkey, z, aux, tweak_point) do
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
          tweaked_r_point = Math.add(r_point, tweak_point)
          # we must ensure that R+T, the final signature's nonce point has even y
          {k, was_negated} = get_k_for_even_tweaked_nonce(k0, tweaked_r_point)
          r_point = PrivateKey.to_point(k)
          tweaked_r_point = Math.add(r_point, tweak_point)

          e = calculate_e(Point.x_bytes(tweaked_r_point), Point.x_bytes(d_point), z_bytes)
          sig_s = calculate_s(k, d, e)

          {:ok, %Signature{r: r_point.x, s: sig_s}, tweak_point, was_negated}
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

  # returns new_k, was_negated
  defp get_k_for_even_tweaked_nonce(k, tweaked_point) do
    if Point.has_even_y(tweaked_point) do
      IO.puts("k unchanged\n")
      {k, false}
    else
      IO.puts("k changed\n")
      {PrivateKey.negate(k), true}
    end
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

  defp validate_r(r_point, rx) do
    cond do
      Point.is_inf(r_point) ->
        {:error, "R point is infinite"}
      !Point.has_even_y(r_point) ->
        {:error, "R point is not even"}
      r_point.x != rx ->
        {:error, "x's do not match #{r_point.x} vs #{rx}"}
      true -> true
    end
  end

  @doc """
    verify whether the schnorr signature is valid for the given message hash and public key
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

  @spec verify_untweaked_signature(Point.t(), non_neg_integer, Signature.t(), Point.t(), boolean) ::
          boolean | {:error, String.t()}
  def verify_untweaked_signature(_, _, %Signature{r: r, s: s}, _, _) when r >= @p || s >= @n, do: {:error, "invalid signature"}
  def verify_untweaked_signature(pubkey, z, %Signature{r: r, s: s}, tweak_point, was_negated) do
    z_bytes = Utils.int_to_big(z, 32)
    case Point.lift_x(r) do
      {:error, err} ->
        {:error, err}

      {:ok, given_r_point} ->
        case get_even_tweaked_point(given_r_point, tweak_point, was_negated) do
          {:error, err} ->
            {:error, err}

          {:ok, tweaked_point} ->
            e = calculate_e(Point.x_bytes(tweaked_point), Point.x_bytes(pubkey), z_bytes)
            r_point = calculate_r(pubkey, s, e)
            validate_r(r_point, r)
        end
    end
  end

  # bool is was_negated.
  defp get_even_tweaked_point(r_point, tweak_point, false) do
    Math.add(given_r_point, tweak_point)
  end
  defp get_even_tweaked_point(r_point, tweak_point, true) do
    # force tweaked_point to have even y
    tweaked_point = get_even_tweaked_point(r_point, tweak_point, false)
    case Point.lift_x(tweaked_point.x) do
      {:ok, tweaked_point} -> {:ok, tweaked_point}
      {:error, err} -> {:error, err}
    end
  end

  @spec tweak_signature(Signature.t(), non_neg_integer | PrivateKey.t()) :: Signature.t()
  def tweak_signature(sig, t = %PrivateKey{}), do: tweak_signature(sig, t.d)
  def tweak_signature(%Signature{r: r, s: s}, tweak, was_negated) do
    t = get_even_tweak(tweak, was_negated)
    t_point = PrivateKey.to_point(t)
    {:ok, r_point} = Point.lift_x(r)
    tw_s = Math.modulo(tweak+s, @n)
    %Signature{r: Math.add(r_point, t_point).x, s: tw_s}
  end

  def get_even_tweak(tweak, false) do
    {:ok, t} = PrivateKey.new(tweak)
    t
  end
  def get_even_tweak(tweak, true) do
    tweak
    |> get_even_tweak(false)
    |> PrivateKey.negate()
  end

  @doc """
    extract_tweak takes a signer pubkey, message hash z, untweaked signature (adaptor signature),
    and a completed signature, verifies the signature, and then returns the revealed tweak secret
  """
  @spec extract_tweak(Point.t(), non_neg_integer, Signature.t(), Signature.t()) ::
          {:ok, non_neg_integer} | {:error, String.t()}
  def extract_tweak(pubkey, z, %Signature{s: s}, tweaked_sig = %Signature{s: tweaked_s}) do
    if verify_signature(pubkey, z, tweaked_sig) do
      if tweaked_s < s do
        {:error, "invalid tweak"}

      else
        {:ok, tweaked_s - s}
      end

    else
      {:error, "failed to extract tweak due to invalid signature"}
    end
  end

  @doc """
    extract_tweaked_signature takes a signer pubkey, message hash z, untweaked signature (adaptor signature),
    and a tweak secret, and uses it to verify the adaptor signature, and returns the complete signature
  """
  @spec extract_tweaked_signature(
          Point.t(),
          non_neg_integer,
          Signature.t(),
          non_neg_integer | PrivateKey.t()
        ) ::
          {:ok, Signature.t()} | {:error, String.t()}
  def extract_tweaked_signature(pubkey, z, sig, t = %PrivateKey{}),
    do: extract_tweaked_signature(pubkey, z, sig, t.d)

  def extract_tweaked_signature(pubkey, z, %Signature{r: r, s: s}, tweak) do
    case Point.lift_x(r) do
      {:error, err} ->
        {:error, err}

      {:ok, r_point} ->
        tweaked_s = tweak + s

        tweak_point = PrivateKey.to_point(tweak)
        tweaked_r_point = Math.add(r_point, tweak_point)

        tweaked_sig = %Signature{r: tweaked_r_point.x, s: tweaked_s}

        if verify_signature(pubkey, z, tweaked_sig) do
          {:ok, %Signature{r: tweaked_r_point.x, s: tweaked_s}}
        else
          {:error, "tweak does not produce valid signature"}
        end
    end
  end
end
