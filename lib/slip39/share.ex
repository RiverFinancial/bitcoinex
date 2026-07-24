defmodule Bitcoinex.SLIP39.Share do
  @moduledoc """
  A single SLIP-39 share and its mnemonic codec.

  The struct stores thresholds and counts 1-based; the wire format stores
  them minus 1 in 4 bits each. `group_index` and `member_index` are stored
  as-is (0-based x-coordinates).
  """

  import Bitwise

  alias Bitcoinex.SLIP39.Encoding
  alias Bitcoinex.Utils

  @radix_bits 10
  @id_length_bits 15
  @checksum_length_words 3
  @metadata_length_words 7
  @min_mnemonic_length_words 20

  @enforce_keys [
    :identifier,
    :extendable,
    :iteration_exponent,
    :group_index,
    :group_threshold,
    :group_count,
    :member_index,
    :member_threshold,
    :share_value
  ]
  defstruct [
    :identifier,
    :extendable,
    :iteration_exponent,
    :group_index,
    :group_threshold,
    :group_count,
    :member_index,
    :member_threshold,
    :share_value
  ]

  @type t :: %__MODULE__{
          identifier: 0..0x7FFF,
          extendable: boolean(),
          iteration_exponent: 0..15,
          group_index: 0..15,
          group_threshold: 1..16,
          group_count: 1..16,
          member_index: 0..15,
          member_threshold: 1..16,
          share_value: binary()
        }

  @doc """
  encode serializes a share to its space-joined mnemonic string.

  It cannot fail on a well-formed struct, and the guard enforces exactly
  what "well-formed" means: every field is within the range its wire
  encoding allows, and `share_value` is a SLIP-39-valid length — a whole
  number of bytes, at least 128 bits (16 bytes), and a multiple of 16 bits
  (even byte count). An out-of-range struct is a programmer error and
  raises `FunctionClauseError` rather than silently truncating a field or
  emitting a mnemonic that cannot be decoded back.
  """
  @spec encode(t()) :: String.t()
  def encode(%__MODULE__{
        identifier: identifier,
        extendable: extendable,
        iteration_exponent: iteration_exponent,
        group_index: group_index,
        group_threshold: group_threshold,
        group_count: group_count,
        member_index: member_index,
        member_threshold: member_threshold,
        share_value: share_value
      })
      when identifier in 0..0x7FFF and is_boolean(extendable) and
             iteration_exponent in 0..15 and group_index in 0..15 and
             group_threshold in 1..16 and group_count in 1..16 and
             member_index in 0..15 and member_threshold in 1..16 and
             is_binary(share_value) and byte_size(share_value) >= 16 and
             rem(byte_size(share_value), 2) == 0 do
    pad_bits = rem(@radix_bits - rem(bit_size(share_value), @radix_bits), @radix_bits)
    ext_bit = if extendable, do: 1, else: 0
    group_threshold_minus1 = group_threshold - 1
    group_count_minus1 = group_count - 1
    member_threshold_minus1 = member_threshold - 1

    data_bits =
      <<identifier::15, ext_bit::1, iteration_exponent::4, group_index::4,
        group_threshold_minus1::4, group_count_minus1::4, member_index::4,
        member_threshold_minus1::4, 0::size(pad_bits), share_value::binary>>

    data_words = for <<idx::10 <- data_bits>>, do: idx
    words = data_words ++ Encoding.rs1024_create_checksum(data_words, extendable)

    words
    |> Encoding.indices_to_words()
    |> Enum.join(" ")
  end

  @doc """
  decode parses a space-joined mnemonic string into a share, verifying the
  RS1024 checksum, minimum length, padding, and group threshold.
  """
  @spec decode(String.t()) :: {:ok, t()} | {:error, atom()}
  def decode(mnemonic) when is_binary(mnemonic) do
    with {:ok, words} <- Encoding.words_to_indices(String.split(mnemonic)),
         :ok <- validate_length(words),
         :ok <- verify_checksum(words) do
      words
      |> Enum.take(length(words) - @checksum_length_words)
      |> unpack(length(words))
    end
  end

  defp validate_length(words) when length(words) >= @min_mnemonic_length_words, do: :ok
  defp validate_length(_words), do: {:error, :invalid_mnemonic_length}

  # The extendable bit selects the RS1024 customization string, so it is
  # peeked from the raw words before the checksum can be verified: it is
  # bit 15 of the 20 bits formed by the first two words.
  defp verify_checksum([word0, word1 | _] = words) do
    ext_bit = (word0 <<< @radix_bits ||| word1) >>> 4 &&& 1

    if Encoding.rs1024_verify_checksum(words, ext_bit == 1) do
      :ok
    else
      {:error, :invalid_checksum}
    end
  end

  defp unpack(data_words, word_count) do
    value_words = word_count - @metadata_length_words
    pad_bits = rem(value_words * @radix_bits, 16)

    if pad_bits > 8 do
      # Rules out e.g. 21-word mnemonics, where rem(140, 16) == 12.
      {:error, :invalid_padding}
    else
      # pad_bits <= 8 guarantees the trailing share value is a whole
      # number of bytes, so this match cannot fail.
      <<identifier::size(@id_length_bits), ext_bit::1, iteration_exponent::4, group_index::4,
        group_threshold_minus1::4, group_count_minus1::4, member_index::4,
        member_threshold_minus1::4, padding::size(pad_bits),
        share_value::binary>> = Utils.int_list_to_bits(data_words, @radix_bits)

      with :ok <- validate_padding(padding),
           :ok <- validate_group_threshold(group_threshold_minus1, group_count_minus1) do
        {:ok,
         %__MODULE__{
           identifier: identifier,
           extendable: ext_bit == 1,
           iteration_exponent: iteration_exponent,
           group_index: group_index,
           group_threshold: group_threshold_minus1 + 1,
           group_count: group_count_minus1 + 1,
           member_index: member_index,
           member_threshold: member_threshold_minus1 + 1,
           share_value: share_value
         }}
      end
    end
  end

  defp validate_padding(0), do: :ok
  defp validate_padding(_padding), do: {:error, :invalid_padding}

  defp validate_group_threshold(group_threshold_minus1, group_count_minus1)
       when group_threshold_minus1 > group_count_minus1,
       do: {:error, :invalid_group_threshold}

  defp validate_group_threshold(_group_threshold_minus1, _group_count_minus1), do: :ok
end
