defmodule Bitcoinex.PSBT do
  @moduledoc """
  Support for Partially Signed Bitcoin Transactions (PSBT).

  The format consists of key-value maps.
  Each map consists of a sequence of key-value records, terminated by a 0x00 byte.

  Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

  Known limitations (deliberate):

  * 65-byte (uncompressed) public keys in `partial_sig` and `bip32_derivation`
    records are rejected with `{:error, :uncompressed_public_key}`. BIP-174
    permits them, but they cannot be represented faithfully here, so they are
    refused outright rather than silently re-compressed.
  * Serialization always emits records in ascending key-type order with
    unknown records last (as Bitcoin Core does). `decode |> encode_b64` is
    byte-identical for canonically-ordered PSBTs; a PSBT whose records arrive
    in a different order decodes to the same struct but re-encodes canonically.
  """
  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Out

  @type t() :: %__MODULE__{
          global: Global.t(),
          inputs: list(In.t()),
          outputs: list(Out.t())
        }

  defstruct [
    :global,
    :inputs,
    :outputs
  ]

  @magic 0x70736274
  @separator 0xFF

  def separator, do: @separator

  @doc """
  Decodes a base64 encoded string into a PSBT.
  """
  @spec decode(String.t()) :: {:ok, t()} | {:error, term()}
  def decode(psbt_base64) when is_binary(psbt_base64) do
    case Base.decode64(psbt_base64) do
      {:ok, psbt_binary} ->
        safe_parse(psbt_binary)

      :error ->
        {:error, :decode_error}
    end
  end

  @doc """
    Decodes a binary-encoded PSBT file.
  """
  @spec from_file(String.t()) :: {:ok, t()} | {:error, term()}
  def from_file(filename) do
    filename
    |> File.read!()
    |> safe_parse()
  end

  # Parsing operates on untrusted input; a malformed binary (e.g. a value whose
  # declared length exceeds the remaining bytes) raises a MatchError/ArgumentError
  # during binary matching. Convert those into a clean error rather than crashing
  # the caller, while letting unexpected exceptions (real bugs) propagate.
  defp safe_parse(psbt_binary) do
    parse(psbt_binary)
  rescue
    _error in [MatchError, ArgumentError, FunctionClauseError] ->
      {:error, :invalid_psbt}
  end

  @spec serialize(t()) :: binary()
  defp serialize(packet) do
    global = Global.serialize_global(packet.global)
    inputs = In.serialize_inputs(packet.inputs)
    outputs = Out.serialize_outputs(packet.outputs)

    <<@magic::big-size(32)>> <>
      <<@separator::big-size(8)>> <>
      global <> inputs <> outputs
  end

  @doc """
    to_file writes a PSBT to file as binary.

    Returns `{:error, :missing_unsigned_tx}` for a PSBT without a global
    unsigned transaction: it is mandatory in v0, so serializing without one
    would emit a PSBT this module's own decoder rejects.
  """
  @spec to_file(t(), String.t()) :: :ok | {:error, File.posix() | :missing_unsigned_tx}
  def to_file(packet, filename) do
    case ensure_unsigned_tx(packet) do
      :ok -> File.write(filename, serialize(packet))
      error -> error
    end
  end

  @doc """
    Encodes a PSBT as base64.

    Returns `{:ok, base64}`, or `{:error, :missing_unsigned_tx}` for a PSBT
    without a global unsigned transaction (see `to_file/2`).
  """
  @spec encode_b64(t()) :: {:ok, String.t()} | {:error, :missing_unsigned_tx}
  def encode_b64(packet) do
    case ensure_unsigned_tx(packet) do
      :ok -> {:ok, packet |> serialize() |> Base.encode64()}
      error -> error
    end
  end

  defp ensure_unsigned_tx(%PSBT{global: %{unsigned_tx: unsigned_tx}})
       when unsigned_tx != nil,
       do: :ok

  defp ensure_unsigned_tx(_packet), do: {:error, :missing_unsigned_tx}

  @spec parse(binary()) :: {:ok, t()} | {:error, term()}
  defp parse(<<@magic::big-size(32), @separator::big-size(8), psbt::binary>>) do
    with {:ok, {global, psbt}} <- Global.parse_global(psbt),
         {:ok, input_count} <- input_count(global),
         {:ok, {inputs, psbt}} <- In.parse_inputs(psbt, input_count),
         output_count = length(global.unsigned_tx.outputs),
         {:ok, {outputs, remaining}} <- Out.parse_outputs(psbt, output_count),
         :ok <- ensure_fully_consumed(remaining) do
      {:ok,
       %PSBT{
         global: global,
         inputs: inputs,
         outputs: outputs
       }}
    end
  end

  defp parse(_), do: {:error, :invalid_magic}

  # BIP-174: a PSBT must be fully consumed; any bytes after the last output map
  # make it invalid.
  defp ensure_fully_consumed(<<>>), do: :ok
  defp ensure_fully_consumed(_remaining), do: {:error, :trailing_bytes}

  # PSBT v0 requires a global unsigned transaction; its input count fixes the
  # number of input maps that follow.
  defp input_count(global) do
    case global.unsigned_tx do
      nil -> {:error, :missing_unsigned_tx}
      unsigned_tx -> {:ok, length(unsigned_tx.inputs)}
    end
  end
end

defmodule Bitcoinex.PSBT.Utils do
  @moduledoc """
  Contains utility functions used throughout PSBT serialization.
  """
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @doc """
  Reads a single compact-size-prefixed value off the front of a binary.

  Returns `{:ok, value, remaining}`. The success tuple is tagged so that it
  cannot be confused with the error tuple: an untagged `{value, remaining}`
  is shape-identical to `{:error, reason}`, so a caller that skipped the
  error check would bind `value = :error` and carry on.

  BIP-174 requires compact size uints to be minimally encoded, so a
  non-minimal length is rejected: it cannot survive a re-serialize
  byte-for-byte, and a non-minimally encoded zero key length would produce
  an empty key that re-serializes as a map separator, silently corrupting
  the PSBT on re-encode.
  """
  @spec parse_compact_size_value(binary()) ::
          {:ok, binary(), binary()} | {:error, :non_canonical_compact_size}
  def parse_compact_size_value(key_value) do
    {value_length, remaining} = TxUtils.get_counter(key_value)
    prefix_size = byte_size(key_value) - byte_size(remaining)

    if byte_size(TxUtils.serialize_compact_size_unsigned_int(value_length)) == prefix_size do
      <<value::binary-size(value_length), remaining::binary>> = remaining
      {:ok, value, remaining}
    else
      {:error, :non_canonical_compact_size}
    end
  end

  @doc """
  Parses a sequence of key-value records terminated by the 0x00 map separator,
  dispatching each record to `parse_func`.

  Rejects duplicate keys within the map (BIP-174) with `{:error, :duplicate_key}`,
  and propagates any `{:error, reason}` raised by `parse_func`.

  Returns `{:ok, {accumulator, remaining_binary}}` on success.
  """
  @spec parse_key_value(binary(), struct(), function()) ::
          {:ok, {struct(), binary()}} | {:error, term()}
  def parse_key_value(psbt, accumulator, parse_func) do
    parse_key_value(psbt, accumulator, parse_func, MapSet.new())
  end

  defp parse_key_value(<<0x00, remaining::binary>>, accumulator, _parse_func, _seen_keys) do
    {:ok, {accumulator, remaining}}
  end

  defp parse_key_value(<<>>, _accumulator, _parse_func, _seen_keys) do
    {:error, :unexpected_end_of_data}
  end

  defp parse_key_value(psbt, accumulator, parse_func, seen_keys) do
    case parse_compact_size_value(psbt) do
      {:error, reason} ->
        {:error, reason}

      # Unreachable via canonical encoding (a zero key length is the map
      # separator, matched above), kept as a guard so an empty key can never
      # reach a parse_func or re-serialize as a separator.
      {:ok, <<>>, _remaining} ->
        {:error, :invalid_key_format}

      {:ok, key, remaining} ->
        if MapSet.member?(seen_keys, key) do
          {:error, :duplicate_key}
        else
          case parse_func.(key, remaining, accumulator) do
            {:error, reason} ->
              {:error, reason}

            {accumulator, remaining} ->
              parse_key_value(remaining, accumulator, parse_func, MapSet.put(seen_keys, key))
          end
        end
    end
  end

  @doc """
  Serializes a key-value record: compact-size key length, key, compact-size
  value length, value.
  """
  @spec serialize_kv(binary(), binary()) :: binary()
  def serialize_kv(key, value) do
    key_length = TxUtils.serialize_compact_size_unsigned_int(byte_size(key))
    value_length = TxUtils.serialize_compact_size_unsigned_int(byte_size(value))
    key_length <> key <> value_length <> value
  end

  @doc """
  Appends an item to a list-valued field, treating `nil` as the empty list.
  Preserves insertion order.
  """
  @spec append(list() | nil, term()) :: list()
  def append(nil, item), do: [item]
  def append(items, item) when is_list(items), do: items ++ [item]

  @doc """
  Serializes a repeatable (list-valued) field, mapping each item through
  `serialize_func`. A `nil` field serializes to nothing.
  """
  @spec serialize_repeatable(list() | nil, (term() -> binary())) :: binary()
  def serialize_repeatable(nil, _serialize_func), do: <<>>

  def serialize_repeatable(items, serialize_func) when is_list(items) do
    Enum.map_join(items, serialize_func)
  end

  @doc """
  Classifies an unrecognized key-value record: proprietary keys (leading byte
  0xFC) are collected into the `:proprietary` field, all others into `:unknown`.
  Returns `{field_name, record}` where record is `%{key: key, value: value}`.
  """
  @spec classify_unknown_record(binary(), binary()) ::
          {:proprietary | :unknown, %{key: binary(), value: binary()}}
  def classify_unknown_record(<<0xFC, _rest::binary>> = key, value) do
    {:proprietary, %{key: key, value: value}}
  end

  def classify_unknown_record(key, value) do
    {:unknown, %{key: key, value: value}}
  end
end

defmodule Bitcoinex.PSBT.Global do
  @moduledoc """
  Global properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Base58

  @type t() :: %__MODULE__{}

  defstruct [
    :unsigned_tx,
    :xpub,
    :version,
    :proprietary,
    :unknown
  ]

  @psbt_global_unsigned_tx 0x00
  @psbt_global_xpub 0x01
  @psbt_global_version 0xFB

  @spec parse_global(binary()) :: {:ok, {t(), binary()}} | {:error, term()}
  def parse_global(psbt) do
    PsbtUtils.parse_key_value(psbt, %Global{}, &parse/3)
  end

  # BIP-174: the global unsigned tx must be serialized in the legacy
  # (non-witness) format. Re-serializing without witnesses must reproduce the
  # exact bytes; a mismatch means the value carried a segwit marker/flag/witness
  # or any other non-canonical encoding (e.g. a non-minimal compact size).
  defp legacy_serialized?(txn, txn_bytes) do
    TxUtils.serialize(%{txn | witnesses: []}) == txn_bytes
  end

  # BIP-174: every input in the unsigned tx must have an empty scriptSig.
  defp all_script_sigs_empty?(txn) do
    Enum.all?(txn.inputs, fn input -> input.script_sig in [nil, ""] end)
  end

  # unsigned transaction
  defp parse(<<@psbt_global_unsigned_tx::big-size(8)>>, psbt, global) do
    case PsbtUtils.parse_compact_size_value(psbt) do
      {:error, reason} ->
        {:error, reason}

      {:ok, txn_bytes, psbt} ->
        case Transaction.decode(Base.encode16(txn_bytes, case: :lower)) do
          {:ok, txn} ->
            cond do
              not legacy_serialized?(txn, txn_bytes) ->
                {:error, :unsigned_tx_not_canonically_serialized}

              not all_script_sigs_empty?(txn) ->
                {:error, :unsigned_tx_has_script_sig}

              true ->
                {%Global{global | unsigned_tx: txn}, psbt}
            end

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp parse(<<@psbt_global_xpub::big-size(8), xpub::binary-size(78)>>, psbt, global) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      # BIP-174: the value is a 4-byte fingerprint followed by whole 32-bit
      # indexes — a trailing partial index is malformed, not ignorable (a
      # bitstring comprehension would silently drop it and alter the PSBT on
      # re-serialize).
      case value do
        <<master_fingerprint::little-unsigned-32, paths::binary>>
        when rem(byte_size(paths), 4) == 0 ->
          derivation = for <<index::little-unsigned-32 <- paths>>, do: index

          global_xpub =
            PsbtUtils.append(global.xpub, %{
              xpub: Base58.encode(xpub),
              master_pfp: master_fingerprint,
              derivation: derivation
            })

          {%Global{global | xpub: global_xpub}, psbt}

        _ ->
          {:error, :invalid_derivation}
      end
    end
  end

  # BIP-174: the version is a 32-bit little-endian unsigned int. The raw
  # 4 bytes are stored as-is here; interpretation is left to later stages.
  defp parse(<<@psbt_global_version::big-size(8)>>, psbt, global) do
    case PsbtUtils.parse_compact_size_value(psbt) do
      {:ok, <<_::little-unsigned-32>> = value, psbt} ->
        {%Global{global | version: value}, psbt}

      {:error, reason} ->
        {:error, reason}

      _ ->
        {:error, :invalid_version}
    end
  end

  # A key whose leading byte is a known global type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _global)
       when type in [@psbt_global_unsigned_tx, @psbt_global_xpub, @psbt_global_version] do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, global) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {field, record} = PsbtUtils.classify_unknown_record(key, value)
      {Map.update(global, field, [record], &PsbtUtils.append(&1, record)), psbt}
    end
  end

  @spec serialize_global(t()) :: binary()
  def serialize_global(global) do
    serialized =
      serialize_kv(:unsigned_tx, global.unsigned_tx) <>
        PsbtUtils.serialize_repeatable(global.xpub, &serialize_xpub/1) <>
        serialize_kv(:version, global.version) <>
        PsbtUtils.serialize_repeatable(global.proprietary, &serialize_record/1) <>
        PsbtUtils.serialize_repeatable(global.unknown, &serialize_record/1)

    serialized <> <<0x00::big-size(8)>>
  end

  defp serialize_kv(_field, nil), do: <<>>

  defp serialize_kv(:unsigned_tx, unsigned_tx) do
    PsbtUtils.serialize_kv(
      <<@psbt_global_unsigned_tx::big-size(8)>>,
      TxUtils.serialize(unsigned_tx)
    )
  end

  defp serialize_kv(:version, version) do
    PsbtUtils.serialize_kv(<<@psbt_global_version::big-size(8)>>, version)
  end

  defp serialize_xpub(xpub) do
    {:ok, key_data} = Base58.decode(xpub.xpub)

    derivation = for index <- xpub.derivation, into: <<>>, do: <<index::little-size(32)>>
    value = <<xpub.master_pfp::little-size(32)>> <> derivation

    PsbtUtils.serialize_kv(<<@psbt_global_xpub::big-size(8)>> <> key_data, value)
  end

  defp serialize_record(%{key: key, value: value}) do
    PsbtUtils.serialize_kv(key, value)
  end
end

defmodule Bitcoinex.PSBT.In do
  @moduledoc """
  Input properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @type t() :: %__MODULE__{}

  defstruct [
    :non_witness_utxo,
    :witness_utxo,
    :partial_sig,
    :sighash_type,
    :redeem_script,
    :witness_script,
    :bip32_derivation,
    :final_scriptsig,
    :final_scriptwitness,
    :por_commitment,
    :ripemd160,
    :sha256,
    :hash160,
    :hash256,
    :proprietary,
    :unknown
  ]

  @psbt_in_non_witness_utxo 0x00
  @psbt_in_witness_utxo 0x01
  @psbt_in_partial_sig 0x02
  @psbt_in_sighash_type 0x03
  @psbt_in_redeem_script 0x04
  @psbt_in_witness_script 0x05
  @psbt_in_bip32_derivation 0x06
  @psbt_in_final_scriptsig 0x07
  @psbt_in_final_scriptwitness 0x08
  @psbt_in_por_commitment 0x09
  @psbt_in_ripemd160 0x0A
  @psbt_in_sha256 0x0B
  @psbt_in_hash160 0x0C
  @psbt_in_hash256 0x0D

  @spec parse_inputs(binary(), non_neg_integer()) ::
          {:ok, {list(t()), binary()}} | {:error, term()}
  def parse_inputs(psbt, num_inputs) do
    parse_input(psbt, [], num_inputs)
  end

  defp parse_input(psbt, inputs, 0), do: {:ok, {Enum.reverse(inputs), psbt}}

  defp parse_input(psbt, inputs, num_inputs) do
    case PsbtUtils.parse_key_value(psbt, %In{}, &parse/3) do
      {:error, reason} ->
        {:error, reason}

      {:ok, {input, psbt}} ->
        parse_input(psbt, [input | inputs], num_inputs - 1)
    end
  end

  defp parse(<<@psbt_in_non_witness_utxo::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      # Like the global unsigned tx, the decoded utxo must reproduce the value
      # bytes exactly: a tx with non-minimal internal varints decodes fine but
      # re-serializes differently, silently breaking losslessness.
      case Transaction.decode(Base.encode16(value, case: :lower)) do
        {:ok, txn} ->
          if TxUtils.serialize(txn) == value do
            {%In{input | non_witness_utxo: txn}, psbt}
          else
            {:error, :invalid_non_witness_utxo}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # BIP-174: the value is the entire output in network serialization — bytes
  # beyond the scriptPubKey are malformed, not ignorable (dropping them would
  # also silently alter the PSBT on re-serialize). Like the tx-valued fields,
  # the parsed output must reproduce the value bytes exactly, so a non-minimal
  # scriptPubKey length is rejected too.
  defp parse(<<@psbt_in_witness_utxo::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      case Out.parse_output(value) do
        {:ok, out} ->
          if :erlang.list_to_binary(Out.serialize_outputs([out])) == value do
            {%In{input | witness_utxo: out}, psbt}
          else
            {:error, :invalid_witness_utxo}
          end

        {:error, _} ->
          {:error, :invalid_witness_utxo}
      end
    end
  end

  # partial_sig is repeatable: one record per signing pubkey (BIP-174 keys them
  # by pubkey), so a multisig input legitimately carries several.
  defp parse(<<@psbt_in_partial_sig::big-size(8), public_key::binary-size(33)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      partial_sig = %{
        public_key: Base.encode16(public_key, case: :lower),
        signature: Base.encode16(value, case: :lower)
      }

      {%In{input | partial_sig: PsbtUtils.append(input.partial_sig, partial_sig)}, psbt}
    end
  end

  # 65-byte (uncompressed) pubkeys are valid in BIP-174 but unsupported here:
  # `Secp256k1.Point` carries no compression flag, so an uncompressed key could
  # not be re-serialized faithfully. Reject with a distinct reason rather than
  # conflating it with a malformed key.
  defp parse(<<@psbt_in_partial_sig::big-size(8), _public_key::binary-size(65)>>, _psbt, _input) do
    {:error, :uncompressed_public_key}
  end

  # BIP-174: the sighash type is a 32-bit little-endian unsigned int. The raw
  # 4 bytes are stored as-is here; interpretation is left to later stages.
  defp parse(<<@psbt_in_sighash_type::big-size(8)>>, psbt, input) do
    case PsbtUtils.parse_compact_size_value(psbt) do
      {:ok, <<_::little-unsigned-32>> = value, psbt} ->
        {%In{input | sighash_type: value}, psbt}

      {:error, reason} ->
        {:error, reason}

      _ ->
        {:error, :invalid_sighash_type}
    end
  end

  defp parse(<<@psbt_in_redeem_script::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%In{input | redeem_script: Base.encode16(value, case: :lower)}, psbt}
    end
  end

  defp parse(<<@psbt_in_witness_script::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%In{input | witness_script: Base.encode16(value, case: :lower)}, psbt}
    end
  end

  defp parse(<<@psbt_in_bip32_derivation::big-size(8), public_key::binary-size(33)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      # BIP-174: 4-byte fingerprint + whole 32-bit indexes; a trailing partial
      # index is malformed, not ignorable (see the global xpub clause).
      case value do
        <<master_fingerprint::little-unsigned-32, paths::binary>>
        when rem(byte_size(paths), 4) == 0 ->
          derivation = for <<index::little-unsigned-32 <- paths>>, do: index

          bip32_derivation =
            PsbtUtils.append(input.bip32_derivation, %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: master_fingerprint,
              derivation: derivation
            })

          {%In{input | bip32_derivation: bip32_derivation}, psbt}

        _ ->
          {:error, :invalid_derivation}
      end
    end
  end

  defp parse(
         <<@psbt_in_bip32_derivation::big-size(8), _public_key::binary-size(65)>>,
         _psbt,
         _input
       ) do
    {:error, :uncompressed_public_key}
  end

  defp parse(<<@psbt_in_final_scriptsig::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%In{input | final_scriptsig: Base.encode16(value, case: :lower)}, psbt}
    end
  end

  # BIP-174: the value is the entire witness stack in network serialization —
  # bytes beyond the last stack item are malformed, not ignorable. Like the
  # tx-valued fields, the parsed stack must reproduce the value bytes exactly,
  # so a non-minimal stack count or item length is rejected too.
  defp parse(<<@psbt_in_final_scriptwitness::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      case Witness.parse_witness(value) do
        {:ok, witness} ->
          if Witness.serialize_witness([witness]) == value do
            {%In{input | final_scriptwitness: witness}, psbt}
          else
            {:error, :invalid_final_scriptwitness}
          end

        {:error, _} ->
          {:error, :invalid_final_scriptwitness}
      end
    end
  end

  defp parse(<<@psbt_in_por_commitment::big-size(8)>>, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%In{input | por_commitment: value}, psbt}
    end
  end

  defp parse(<<@psbt_in_ripemd160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    with {:ok, preimage, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      record = %{hash: hash, preimage: preimage}
      {%In{input | ripemd160: PsbtUtils.append(input.ripemd160, record)}, psbt}
    end
  end

  defp parse(<<@psbt_in_sha256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    with {:ok, preimage, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      record = %{hash: hash, preimage: preimage}
      {%In{input | sha256: PsbtUtils.append(input.sha256, record)}, psbt}
    end
  end

  defp parse(<<@psbt_in_hash160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    with {:ok, preimage, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      record = %{hash: hash, preimage: preimage}
      {%In{input | hash160: PsbtUtils.append(input.hash160, record)}, psbt}
    end
  end

  defp parse(<<@psbt_in_hash256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    with {:ok, preimage, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      record = %{hash: hash, preimage: preimage}
      {%In{input | hash256: PsbtUtils.append(input.hash256, record)}, psbt}
    end
  end

  # A key whose leading byte is a known input type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _input)
       when type in @psbt_in_non_witness_utxo..@psbt_in_hash256 do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, input) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {field, record} = PsbtUtils.classify_unknown_record(key, value)
      {Map.update(input, field, [record], &PsbtUtils.append(&1, record)), psbt}
    end
  end

  @spec serialize_inputs(list(t())) :: binary()
  def serialize_inputs(inputs) when is_list(inputs) do
    Enum.map_join(inputs, &serialize_input/1)
  end

  defp serialize_input(input) do
    serialized =
      serialize_kv(:non_witness_utxo, input.non_witness_utxo) <>
        serialize_kv(:witness_utxo, input.witness_utxo) <>
        PsbtUtils.serialize_repeatable(input.partial_sig, &serialize_partial_sig/1) <>
        serialize_kv(:sighash_type, input.sighash_type) <>
        serialize_kv(:redeem_script, input.redeem_script) <>
        serialize_kv(:witness_script, input.witness_script) <>
        PsbtUtils.serialize_repeatable(input.bip32_derivation, &serialize_bip32_derivation/1) <>
        serialize_kv(:final_scriptsig, input.final_scriptsig) <>
        serialize_kv(:final_scriptwitness, input.final_scriptwitness) <>
        serialize_kv(:por_commitment, input.por_commitment) <>
        serialize_hash_preimages(@psbt_in_ripemd160, input.ripemd160) <>
        serialize_hash_preimages(@psbt_in_sha256, input.sha256) <>
        serialize_hash_preimages(@psbt_in_hash160, input.hash160) <>
        serialize_hash_preimages(@psbt_in_hash256, input.hash256) <>
        PsbtUtils.serialize_repeatable(input.proprietary, &serialize_record/1) <>
        PsbtUtils.serialize_repeatable(input.unknown, &serialize_record/1)

    serialized <> <<0x00::big-size(8)>>
  end

  defp serialize_kv(_field, nil), do: <<>>

  defp serialize_kv(:non_witness_utxo, non_witness_utxo) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_non_witness_utxo::big-size(8)>>,
      TxUtils.serialize(non_witness_utxo)
    )
  end

  defp serialize_kv(:witness_utxo, witness_utxo) do
    script = Base.decode16!(witness_utxo.script_pub_key, case: :lower)

    value =
      <<witness_utxo.value::little-size(64)>> <>
        TxUtils.serialize_compact_size_unsigned_int(byte_size(script)) <> script

    PsbtUtils.serialize_kv(<<@psbt_in_witness_utxo::big-size(8)>>, value)
  end

  defp serialize_kv(:sighash_type, sighash_type) do
    PsbtUtils.serialize_kv(<<@psbt_in_sighash_type::big-size(8)>>, sighash_type)
  end

  defp serialize_kv(:redeem_script, redeem_script) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_redeem_script::big-size(8)>>,
      Base.decode16!(redeem_script, case: :lower)
    )
  end

  defp serialize_kv(:witness_script, witness_script) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_witness_script::big-size(8)>>,
      Base.decode16!(witness_script, case: :lower)
    )
  end

  defp serialize_kv(:final_scriptsig, final_scriptsig) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_final_scriptsig::big-size(8)>>,
      Base.decode16!(final_scriptsig, case: :lower)
    )
  end

  defp serialize_kv(:final_scriptwitness, final_scriptwitness) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_final_scriptwitness::big-size(8)>>,
      Witness.serialize_witness([final_scriptwitness])
    )
  end

  defp serialize_kv(:por_commitment, por_commitment) do
    PsbtUtils.serialize_kv(<<@psbt_in_por_commitment::big-size(8)>>, por_commitment)
  end

  defp serialize_bip32_derivation(bip32_derivation) do
    key_data = Base.decode16!(bip32_derivation.public_key, case: :lower)

    derivation =
      for index <- bip32_derivation.derivation, into: <<>>, do: <<index::little-size(32)>>

    value = <<bip32_derivation.pfp::little-size(32)>> <> derivation

    PsbtUtils.serialize_kv(<<@psbt_in_bip32_derivation::big-size(8)>> <> key_data, value)
  end

  defp serialize_partial_sig(partial_sig) do
    key_data = Base.decode16!(partial_sig.public_key, case: :lower)
    value = Base.decode16!(partial_sig.signature, case: :lower)
    PsbtUtils.serialize_kv(<<@psbt_in_partial_sig::big-size(8)>> <> key_data, value)
  end

  defp serialize_hash_preimages(_key_type, nil), do: <<>>

  defp serialize_hash_preimages(key_type, records) when is_list(records) do
    Enum.map_join(records, fn %{hash: hash, preimage: preimage} ->
      PsbtUtils.serialize_kv(<<key_type::big-size(8)>> <> hash, preimage)
    end)
  end

  defp serialize_record(%{key: key, value: value}) do
    PsbtUtils.serialize_kv(key, value)
  end
end

defmodule Bitcoinex.PSBT.Out do
  @moduledoc """
  Output properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils

  @type t() :: %__MODULE__{}

  defstruct [
    :redeem_script,
    :witness_script,
    :bip32_derivation,
    :proprietary,
    :unknown
  ]

  @psbt_out_redeem_script 0x00
  @psbt_out_witness_script 0x01
  @psbt_out_bip32_derivation 0x02

  @spec parse_outputs(binary(), non_neg_integer()) ::
          {:ok, {list(t()), binary()}} | {:error, term()}
  def parse_outputs(psbt, num_outputs) do
    parse_output(psbt, [], num_outputs)
  end

  defp parse_output(psbt, outputs, 0), do: {:ok, {Enum.reverse(outputs), psbt}}

  defp parse_output(psbt, outputs, num_outputs) do
    case PsbtUtils.parse_key_value(psbt, %Out{}, &parse/3) do
      {:error, reason} ->
        {:error, reason}

      {:ok, {output, psbt}} ->
        parse_output(psbt, [output | outputs], num_outputs - 1)
    end
  end

  defp parse(<<@psbt_out_redeem_script::big-size(8)>>, psbt, output) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%Out{output | redeem_script: Base.encode16(value, case: :lower)}, psbt}
    end
  end

  defp parse(<<@psbt_out_witness_script::big-size(8)>>, psbt, output) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {%Out{output | witness_script: Base.encode16(value, case: :lower)}, psbt}
    end
  end

  defp parse(
         <<@psbt_out_bip32_derivation::big-size(8), public_key::binary-size(33)>>,
         psbt,
         output
       ) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      # BIP-174: 4-byte fingerprint + whole 32-bit indexes; a trailing partial
      # index is malformed, not ignorable (see the global xpub clause).
      case value do
        <<master_fingerprint::little-unsigned-32, paths::binary>>
        when rem(byte_size(paths), 4) == 0 ->
          derivation = for <<index::little-unsigned-32 <- paths>>, do: index

          bip32_derivation =
            PsbtUtils.append(output.bip32_derivation, %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: master_fingerprint,
              derivation: derivation
            })

          {%Out{output | bip32_derivation: bip32_derivation}, psbt}

        _ ->
          {:error, :invalid_derivation}
      end
    end
  end

  defp parse(
         <<@psbt_out_bip32_derivation::big-size(8), _public_key::binary-size(65)>>,
         _psbt,
         _output
       ) do
    {:error, :uncompressed_public_key}
  end

  # A key whose leading byte is a known output type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _output)
       when type in @psbt_out_redeem_script..@psbt_out_bip32_derivation do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, output) do
    with {:ok, value, psbt} <- PsbtUtils.parse_compact_size_value(psbt) do
      {field, record} = PsbtUtils.classify_unknown_record(key, value)
      {Map.update(output, field, [record], &PsbtUtils.append(&1, record)), psbt}
    end
  end

  @spec serialize_outputs(list(t())) :: binary()
  def serialize_outputs(outputs) when is_list(outputs) do
    Enum.map_join(outputs, &serialize_output/1)
  end

  defp serialize_output(output) do
    serialized =
      serialize_kv(:redeem_script, output.redeem_script) <>
        serialize_kv(:witness_script, output.witness_script) <>
        PsbtUtils.serialize_repeatable(output.bip32_derivation, &serialize_bip32_derivation/1) <>
        PsbtUtils.serialize_repeatable(output.proprietary, &serialize_record/1) <>
        PsbtUtils.serialize_repeatable(output.unknown, &serialize_record/1)

    serialized <> <<0x00::big-size(8)>>
  end

  defp serialize_kv(_field, nil), do: <<>>

  defp serialize_kv(:redeem_script, redeem_script) do
    PsbtUtils.serialize_kv(
      <<@psbt_out_redeem_script::big-size(8)>>,
      Base.decode16!(redeem_script, case: :lower)
    )
  end

  defp serialize_kv(:witness_script, witness_script) do
    PsbtUtils.serialize_kv(
      <<@psbt_out_witness_script::big-size(8)>>,
      Base.decode16!(witness_script, case: :lower)
    )
  end

  defp serialize_bip32_derivation(bip32_derivation) do
    key_data = Base.decode16!(bip32_derivation.public_key, case: :lower)

    derivation =
      for index <- bip32_derivation.derivation, into: <<>>, do: <<index::little-size(32)>>

    value = <<bip32_derivation.pfp::little-size(32)>> <> derivation

    PsbtUtils.serialize_kv(<<@psbt_out_bip32_derivation::big-size(8)>> <> key_data, value)
  end

  defp serialize_record(%{key: key, value: value}) do
    PsbtUtils.serialize_kv(key, value)
  end
end
