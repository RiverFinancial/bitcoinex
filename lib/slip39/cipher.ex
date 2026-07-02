defmodule Bitcoinex.SLIP39.Cipher do
  @moduledoc """
  SLIP-39 master secret encryption.

  Implements the four-round balanced Feistel cipher that SLIP-39 uses to
  transform a master secret (MS) into an encrypted master secret (EMS) under a
  passphrase, and back. The round function is PBKDF2-HMAC-SHA256 keyed by the
  round index and passphrase, salted with the share identifier (unless the
  share set is extendable, in which case the salt is empty).

  Note that SLIP-39 passphrase decryption cannot fail: decrypting with a wrong
  passphrase silently yields a different master secret.
  """

  import Bitwise

  alias Bitcoinex.Utils

  @base_iteration_count 10_000
  @round_count 4
  @customization_string_orig "shamir"

  @doc """
  Encrypts a master secret into an encrypted master secret.

  `ms` must be of even length. The per-round PBKDF2 iteration count is
  `2500 <<< iteration_exponent`. `identifier` is only used in the salt when
  `extendable` is `false`.
  """
  @spec encrypt(binary, binary, 0..15, 0..0x7FFF, boolean) :: binary
  def encrypt(ms, passphrase, iteration_exponent, identifier, extendable)
      when rem(byte_size(ms), 2) == 0 and byte_size(ms) > 0 do
    feistel(
      ms,
      Enum.to_list(0..(@round_count - 1)),
      passphrase,
      iteration_exponent,
      identifier,
      extendable
    )
  end

  @doc """
  Decrypts an encrypted master secret back into the master secret.

  Inverse of `encrypt/5` for identical `(passphrase, iteration_exponent,
  identifier, extendable)`; runs the Feistel rounds in reverse order.
  """
  @spec decrypt(binary, binary, 0..15, 0..0x7FFF, boolean) :: binary
  def decrypt(ems, passphrase, iteration_exponent, identifier, extendable)
      when rem(byte_size(ems), 2) == 0 and byte_size(ems) > 0 do
    feistel(
      ems,
      Enum.to_list((@round_count - 1)..0//-1),
      passphrase,
      iteration_exponent,
      identifier,
      extendable
    )
  end

  defp feistel(data, round_indices, passphrase, iteration_exponent, identifier, extendable) do
    half = div(byte_size(data), 2)
    <<l::binary-size(half), r::binary-size(half)>> = data

    salt =
      if extendable do
        <<>>
      else
        @customization_string_orig <> <<identifier::16>>
      end

    iterations = div(@base_iteration_count <<< iteration_exponent, @round_count)

    {l, r} =
      Enum.reduce(round_indices, {l, r}, fn i, {l, r} ->
        {r, Utils.xor_bytes(l, round_function(i, passphrase, salt, iterations, r))}
      end)

    r <> l
  end

  defp round_function(i, passphrase, salt, iterations, r) do
    Utils.pbkdf2(:sha256, <<i>> <> passphrase, salt <> r, iterations, byte_size(r))
  end
end
