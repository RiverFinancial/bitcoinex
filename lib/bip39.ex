defmodule Bitcoinex.BIP39 do
  @moduledoc """
    Includes BIP-39 mnemonic encoding, validation, and seed derivation.

    Converts between entropy and mnemonic sentences, derives the BIP-39
    binary seed via PBKDF2-HMAC-SHA512, and derives a BIP-32 master
    extended private key from a mnemonic.

    Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
  """
  alias Bitcoinex.{ExtendedKey, Utils}

  @wordlist_path Path.join(__DIR__, "../priv/bip39_english.txt")
  @external_resource @wordlist_path
  {words, index} = Bitcoinex.Wordlist.load!(@wordlist_path, 2048)
  @wordlist words
  @word_index index

  @entropy_byte_lengths [16, 20, 24, 28, 32]
  @word_counts [12, 15, 18, 21, 24]

  @pbkdf2_iterations 2048
  @seed_byte_length 64

  @type error ::
          :invalid_entropy_length
          | :invalid_word_count
          | :word_not_in_list
          | :invalid_checksum

  @doc """
    entropy_to_mnemonic encodes entropy of 16, 20, 24, 28, or 32 bytes
    into a mnemonic sentence of 12, 15, 18, 21, or 24 words, appending
    the ENT/32-bit SHA-256 checksum per BIP-39.

    ## Examples

      iex> Bitcoinex.BIP39.entropy_to_mnemonic(<<0::128>>)
      {:ok, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}
  """
  @spec entropy_to_mnemonic(binary) :: {:ok, String.t()} | {:error, error()}
  def entropy_to_mnemonic(entropy)
      when is_binary(entropy) and byte_size(entropy) in @entropy_byte_lengths do
    checksum_len = div(bit_size(entropy), 32)
    <<checksum::bitstring-size(checksum_len), _::bitstring>> = Utils.sha256(entropy)
    bits = <<entropy::bitstring, checksum::bitstring>>

    mnemonic = for <<i::11 <- bits>>, do: elem(@wordlist, i)

    {:ok, Enum.join(mnemonic, " ")}
  end

  def entropy_to_mnemonic(entropy) when is_binary(entropy) do
    {:error, :invalid_entropy_length}
  end

  @doc """
    mnemonic_to_entropy decodes a mnemonic sentence back into its entropy,
    validating the word count, every word's membership in the word list,
    and the checksum.

    Words must be separated by exactly one space with no leading or
    trailing whitespace, matching the reference implementation. Seed
    derivation is byte-exact over the mnemonic string, so accepting
    non-canonical spacing here would validate mnemonics that derive
    keys no other wallet reproduces.
  """
  @spec mnemonic_to_entropy(String.t()) :: {:ok, binary} | {:error, error()}
  def mnemonic_to_entropy(mnemonic) when is_binary(mnemonic) do
    words = String.split(mnemonic, " ")

    with :ok <- validate_word_count(words),
         {:ok, indices} <- words_to_indices(words) do
      indices
      |> Utils.int_list_to_bits(11)
      |> validate_checksum()
    end
  end

  @doc """
    valid? returns whether the mnemonic sentence decodes to entropy with
    a valid checksum.
  """
  @spec valid?(String.t()) :: boolean
  def valid?(mnemonic) when is_binary(mnemonic) do
    match?({:ok, _}, mnemonic_to_entropy(mnemonic))
  end

  @doc """
    to_seed derives the 64-byte BIP-39 seed from a mnemonic sentence and
    an optional passphrase using PBKDF2-HMAC-SHA512 with 2048 iterations.
    Both the mnemonic and the passphrase are NFKD-normalized.

    Per BIP-39, seed derivation accepts any string, so the checksum is
    not validated here. Use `valid?/1` or `to_master_private_key/3` when
    validation is required.
  """
  @spec to_seed(String.t(), binary) :: binary
  def to_seed(mnemonic, passphrase \\ "") when is_binary(mnemonic) and is_binary(passphrase) do
    Utils.pbkdf2(
      :sha512,
      nfkd(mnemonic),
      "mnemonic" <> nfkd(passphrase),
      @pbkdf2_iterations,
      @seed_byte_length
    )
  end

  @doc """
    to_master_private_key derives a BIP-32 master extended private key
    from a mnemonic sentence and an optional passphrase. The mnemonic's
    checksum is validated before derivation.
  """
  @prv_prefix_atoms [:xprv, :tprv]

  @spec to_master_private_key(String.t(), binary, atom) ::
          {:ok, ExtendedKey.t()} | {:error, error() | String.t()}
  def to_master_private_key(mnemonic, passphrase \\ "", prefix \\ :xprv)
      when is_binary(mnemonic) and is_binary(passphrase) do
    with :ok <- validate_prefix(prefix),
         {:ok, _entropy} <- mnemonic_to_entropy(mnemonic) do
      mnemonic
      |> to_seed(passphrase)
      |> ExtendedKey.seed_to_master_private_key(prefix)
    end
  end

  defp validate_prefix(prefix) do
    if prefix in @prv_prefix_atoms do
      :ok
    else
      {:error, "invalid extended private key prefix"}
    end
  end

  defp validate_word_count(words) do
    if length(words) in @word_counts do
      :ok
    else
      {:error, :invalid_word_count}
    end
  end

  defp words_to_indices(words) do
    indices =
      Enum.reduce_while(words, [], fn word, acc ->
        case Map.fetch(@word_index, word) do
          {:ok, i} -> {:cont, [i | acc]}
          :error -> {:halt, :word_not_in_list}
        end
      end)

    case indices do
      :word_not_in_list -> {:error, :word_not_in_list}
      indices -> {:ok, Enum.reverse(indices)}
    end
  end

  defp validate_checksum(bits) do
    entropy_len = div(bit_size(bits) * 32, 33)
    entropy_byte_len = div(entropy_len, 8)
    checksum_len = div(entropy_len, 32)

    <<entropy::binary-size(entropy_byte_len), checksum::bitstring-size(checksum_len)>> = bits
    <<expected::bitstring-size(checksum_len), _::bitstring>> = Utils.sha256(entropy)

    if checksum == expected do
      {:ok, entropy}
    else
      {:error, :invalid_checksum}
    end
  end

  defp nfkd(str) do
    if String.valid?(str) do
      :unicode.characters_to_nfkd_binary(str)
    else
      raise ArgumentError, "mnemonic and passphrase must be valid UTF-8"
    end
  end
end
