defmodule Bitcoinex.Secp256k1.Ecdsa do
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey, Signature}

  @n Params.curve().n

  @generator_point %Point{
    x: Params.curve().g_x,
    y: Params.curve().g_y
  }

  @doc """
    deterministic_k implements rfc6979 and returns
    a deterministic k value for signatures
  """
  @spec deterministic_k(PrivateKey.t(), non_neg_integer()) :: PrivateKey.t()
  def deterministic_k(%PrivateKey{d: d}, raw_z) do
    # RFC 6979 https://tools.ietf.org/html/rfc6979#section-3.2
    k = :binary.list_to_bin(List.duplicate(<<0x00>>, 32))
    v = :binary.list_to_bin(List.duplicate(<<0x01>>, 32))
    n = @n
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
    %PrivateKey{d: final_k}
  end

  defp find_candidate(k, v, n) do
    # RFC 6979 https://tools.ietf.org/html/rfc6979#section-3.2
    v = :crypto.mac(:hmac, :sha256, k, v)
    candidate = :binary.decode_unsigned(v)
    # 3.2(h).3 - check candidate in [1,n-1] and r != 0
    if candidate >= 1 and candidate < n do
      case PrivateKey.to_point(%PrivateKey{d: candidate}) do
        {:error, _msg} ->
          find_next_candidate(k, v, n)

        pk ->
          if pk.x != 0 do
            candidate
          else
            find_next_candidate(k, v, n)
          end
      end
    else
      # if candidate is invalid
      find_next_candidate(k, v, n)
    end
  end

  defp find_next_candidate(k, v, n) do
    k = :crypto.mac(:hmac, :sha256, k, v <> <<0x00>>)
    v = :crypto.mac(:hmac, :sha256, k, v)
    find_candidate(k, v, n)
  end

  defp lower_z(z, n) do
    if z > n, do: z - n, else: z
  end

  @doc """
    sign returns an ECDSA signature using the privkey and z
    where privkey is a PrivateKey object and z is an integer.
    The nonce is derived using RFC6979.
  """
  @spec sign(PrivateKey.t(), integer) :: Signature.t()
  def sign(privkey, z) do
    case PrivateKey.validate(privkey) do
      {:error, msg} ->
        {:error, msg}

      {:ok, privkey} ->
        k = deterministic_k(privkey, z)

        case PrivateKey.to_point(k) do
          {:error, msg} ->
            {:error, msg}

          pk ->
            sig_r = pk.x
            inv_k = Math.inv(k.d, @n)
            sig_s = Math.modulo((z + sig_r * privkey.d) * inv_k, @n)

            if sig_s > @n / 2 do
              %Signature{r: sig_r, s: @n - sig_s}
            else
              %Signature{r: sig_r, s: sig_s}
            end
        end
    end
  end

  @signed_message_magic "Bitcoin Signed Message:\n"

  @doc """
  message_digest returns the 32-byte digest used by the standard Bitcoin
  signed-message scheme (Bitcoin Core `signmessage`, Electrum, etc.).
  The preimage is:

      compact_size(24) || "Bitcoin Signed Message:\\n" || compact_size(byte_size(msg)) || msg

  and the digest is the double-SHA256 of that preimage.
  """
  @spec message_digest(binary) :: binary
  def message_digest(msg) when is_binary(msg) do
    Bitcoinex.Utils.double_sha256(
      compact_size(byte_size(@signed_message_magic)) <>
        @signed_message_magic <> compact_size(byte_size(msg)) <> msg
    )
  end

  defp compact_size(len),
    do: Bitcoinex.Transaction.Utils.serialize_compact_size_unsigned_int(len)

  @doc """
  sign_message returns an ECDSA signature over the standard Bitcoin
  signed-message digest of msg (see message_digest/1), where privkey is a
  PrivateKey object and msg is a binary message. The nonce is derived using
  RFC6979, so the resulting signature is compatible with (and verifiable by)
  Bitcoin Core, Electrum, and other wallets.
  """
  @spec sign_message(PrivateKey.t(), binary) :: Signature.t()
  def sign_message(privkey, msg) do
    z =
      msg
      |> message_digest()
      |> :binary.decode_unsigned()

    sign(privkey, z)
  end

  @doc """
  verify_message verifies that signature is a valid Bitcoin signed-message
  signature by pubkey over msg (see message_digest/1). Verification is
  performed via public key recovery, so it accepts signatures produced by
  sign_message/2 as well as by other wallets (Bitcoin Core, Electrum, etc.).
  """
  @spec verify_message(Point.t(), binary, Signature.t()) :: boolean
  def verify_message(%Point{} = pubkey, msg, %Signature{} = signature) do
    digest = message_digest(msg)
    compact_sig = Signature.serialize_signature(signature)
    pubkey_hex = Point.serialize_public_key(pubkey)

    Enum.any?(0..3, fn recovery_id ->
      case ecdsa_recover_compact(digest, compact_sig, recovery_id) do
        {:ok, recovered_pubkey} -> recovered_pubkey == pubkey_hex
        {:error, _} -> false
      end
    end)
  end

  @doc """
    verify whether the ecdsa signature is valid
    for the given message hash and public key
  """
  @spec verify_signature(Point.t(), integer, Signature.t()) :: boolean
  def verify_signature(pubkey, sighash, %Signature{r: r, s: s}) do
    s_inv = Math.inv(s, @n)
    u = Math.modulo(sighash * s_inv, @n)
    v = Math.modulo(r * s_inv, @n)
    total = Math.add(Math.multiply(@generator_point, u), Math.multiply(pubkey, v))
    total.x == r
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
        r_x = @n * Integer.floor_div(recoveryId, 2) + sig.r

        # Check that R(x) is on the curve.
        if r_x > Params.curve().p do
          {:error, "R(x) is not on the curve"}
        else
          # Decompress to get R(y).
          case Secp256k1.get_y(r_x, rem(recoveryId, 2) == 1) do
            {:ok, r_y} ->
              # R(x,y)
              point_r = %Point{x: r_x, y: r_y}

              # Point Q is the recovered public key.
              # We satisfy this equation: Q = r^-1(sR-eG)
              inv_r = Math.inv(sig.r, @n)
              inv_r_s = (inv_r * sig.s) |> Math.modulo(@n)

              # R*s
              point_sr = Math.multiply(point_r, inv_r_s)

              # Find e using the message hash.
              e =
                :binary.decode_unsigned(msg)
                |> Kernel.*(-1)
                |> Math.modulo(@n)
                |> Kernel.*(inv_r |> Math.modulo(@n))

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
end
