defmodule Bitcoinex.PSBT do
  @moduledoc """
  Support for Partially Signed Bitcoin Transactions (PSBT).

  The format consists of key-value maps.
  Each map consists of a sequence of key-value records, terminated by a 0x00 byte.

  Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

  Only PSBT version 0 (BIP-174) is supported; version 2 (BIP-370) and the
  BIP-371 taproot fields are not. Public keys in `partial_sig` and
  `bip32_derivation` records must be 33-byte compressed SEC keys: decoded keys
  are stored as `Secp256k1.Point` structs, which re-serialize compressed, so
  legacy uncompressed (65-byte) keys are rejected rather than silently
  re-encoded to a different key.
  """
  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Witness

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

  @doc """
  Builds a PSBT from an unsigned transaction (the BIP-174 Creator role).

  The transaction must be unsigned: every input's scriptSig must be empty and it
  must carry no witnesses. Returns one empty input map per transaction input and
  one empty output map per transaction output.
  """
  @spec from_tx(Transaction.t()) :: {:ok, t()} | {:error, atom()}
  def from_tx(%Transaction{} = tx) do
    cond do
      Enum.any?(tx.inputs, fn input -> input.script_sig not in [nil, ""] end) ->
        {:error, :tx_not_unsigned}

      tx.witnesses not in [nil, []] ->
        {:error, :tx_not_unsigned}

      true ->
        {:ok,
         %PSBT{
           global: Global.from_unsigned_tx(tx),
           inputs: Enum.map(tx.inputs, fn _input -> In.new() end),
           outputs: Enum.map(tx.outputs, fn _output -> Out.new() end)
         }}
    end
  end

  @doc """
  Returns the txid of the PSBT's global unsigned transaction.
  """
  @spec txid(t()) :: {:ok, String.t()} | {:error, :no_unsigned_tx}
  def txid(%PSBT{global: %{unsigned_tx: nil}}), do: {:error, :no_unsigned_tx}
  def txid(%PSBT{global: %{unsigned_tx: tx}}), do: {:ok, Transaction.transaction_id(tx)}

  @doc """
  Adds a field to the PSBT's global map (the BIP-174 Updater role).
  See `Bitcoinex.PSBT.Global.add_field/3` for the accepted fields.
  """
  @spec add_global_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_global_field(%PSBT{} = psbt, field, value) do
    case Global.add_field(psbt.global, field, value) do
      {:ok, global} -> {:ok, %PSBT{psbt | global: global}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Adds a field to the input map at `index`.
  See `Bitcoinex.PSBT.In.add_field/3` for the accepted fields.
  """
  @spec add_input_field(t(), non_neg_integer(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_input_field(%PSBT{} = psbt, index, field, value) do
    case put_item_field(psbt.inputs, index, &In.add_field(&1, field, value)) do
      {:ok, inputs} -> {:ok, %PSBT{psbt | inputs: inputs}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Adds a field to the output map at `index`.
  See `Bitcoinex.PSBT.Out.add_field/3` for the accepted fields.
  """
  @spec add_output_field(t(), non_neg_integer(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_output_field(%PSBT{} = psbt, index, field, value) do
    case put_item_field(psbt.outputs, index, &Out.add_field(&1, field, value)) do
      {:ok, outputs} -> {:ok, %PSBT{psbt | outputs: outputs}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Combines two PSBTs into one (the BIP-174 Combiner role).

  Both PSBTs must describe the same global unsigned transaction (compared by
  txid), otherwise `{:error, :mismatched_tx}` is returned. Each map is merged
  field by field: singleton fields must agree where both are set, and repeatable
  fields are unioned by key. A record present in both maps under the same key
  but with a different value yields `{:error, :conflicting_field}`.

  Repeatable records are ordered canonically (by key), so `combine/2` is
  commutative for non-conflicting inputs and idempotent on a canonical PSBT
  (such as any PSBT that `combine/2` itself produced).
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(%PSBT{} = psbt_a, %PSBT{} = psbt_b) do
    if same_unsigned_tx?(psbt_a.global.unsigned_tx, psbt_b.global.unsigned_tx) do
      with {:ok, global} <- Global.combine(psbt_a.global, psbt_b.global),
           {:ok, inputs} <- combine_pairs(psbt_a.inputs, psbt_b.inputs, &In.combine/2),
           {:ok, outputs} <- combine_pairs(psbt_a.outputs, psbt_b.outputs, &Out.combine/2) do
        {:ok, %PSBT{global: global, inputs: inputs, outputs: outputs}}
      end
    else
      {:error, :mismatched_tx}
    end
  end

  # BIP-174 identifies a PSBT by its unsigned transaction. Compare by txid so
  # two PSBTs built for the same tx (e.g. one via decode, one via from_tx/1)
  # match regardless of incidental struct differences such as witnesses nil vs [].
  defp same_unsigned_tx?(tx_a, tx_b) do
    Transaction.transaction_id(tx_a) == Transaction.transaction_id(tx_b)
  end

  @doc """
  Finalizes every input that can be finalized (the BIP-174 Input Finalizer
  role), leaving the rest untouched (best-effort, matching Bitcoin Core). For
  each finalizable input it builds the `final_scriptsig` and/or
  `final_scriptwitness` from the collected signatures and scripts and removes
  the now-redundant fields.
  """
  @spec finalize(t()) :: t()
  def finalize(%PSBT{} = psbt) do
    inputs =
      psbt.inputs
      |> Enum.zip(psbt.global.unsigned_tx.inputs)
      |> Enum.map(fn {input, tx_input} -> In.finalize(input, tx_input) end)

    %PSBT{psbt | inputs: inputs}
  end

  @doc """
  Returns true if every input has been finalized.
  """
  @spec finalized?(t()) :: boolean()
  def finalized?(%PSBT{} = psbt), do: Enum.all?(psbt.inputs, &In.finalized?/1)

  @doc """
  Extracts the fully-signed network transaction from a finalized PSBT (the
  BIP-174 Transaction Extractor role). Returns `{:error, :not_finalized}` unless
  every input is finalized.
  """
  @spec extract_tx(t()) :: {:ok, Transaction.t()} | {:error, :not_finalized}
  def extract_tx(%PSBT{} = psbt) do
    if finalized?(psbt) do
      tx = psbt.global.unsigned_tx

      inputs =
        psbt.inputs
        |> Enum.zip(tx.inputs)
        |> Enum.map(fn {input, tx_input} ->
          %{tx_input | script_sig: extracted_script_sig(input)}
        end)

      {:ok, %Transaction{tx | inputs: inputs, witnesses: extracted_witnesses(psbt.inputs)}}
    else
      {:error, :not_finalized}
    end
  end

  defp extracted_script_sig(%{final_scriptsig: nil}), do: ""
  defp extracted_script_sig(%{final_scriptsig: script}), do: Bitcoinex.Script.to_hex(script)

  # Returns the witness list for the extracted tx, or nil if no input has a
  # witness (so the tx serializes in legacy format). Non-witness inputs get an
  # empty witness stack.
  defp extracted_witnesses(inputs) do
    if Enum.any?(inputs, fn input -> input.final_scriptwitness != nil end) do
      Enum.map(inputs, fn input ->
        input.final_scriptwitness || %Witness{txinwitness: []}
      end)
    else
      nil
    end
  end

  # Combines two equal-length lists of maps positionally, short-circuiting on
  # the first conflict.
  defp combine_pairs(maps_a, maps_b, combiner) do
    maps_a
    |> Enum.zip(maps_b)
    |> Enum.reduce_while({:ok, []}, fn {map_a, map_b}, {:ok, combined} ->
      case combiner.(map_a, map_b) do
        {:ok, merged} -> {:cont, {:ok, combined ++ [merged]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # Applies add_field_fun to the item at index, replacing it in the list.
  defp put_item_field(items, index, add_field_fun) do
    if index < 0 or index >= length(items) do
      {:error, :index_out_of_range}
    else
      case add_field_fun.(Enum.at(items, index)) do
        {:ok, item} -> {:ok, List.replace_at(items, index, item)}
        {:error, reason} -> {:error, reason}
      end
    end
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
  """
  @spec to_file(t(), String.t()) :: :ok | {:error, File.posix()}
  def to_file(packet, filename) do
    bin = serialize(packet)
    File.write(filename, bin)
  end

  @spec encode_b64(t()) :: String.t()
  def encode_b64(packet) do
    packet
    |> serialize()
    |> Base.encode64()
  end

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

defmodule Bitcoinex.PSBT.KeyOrigin do
  @moduledoc """
  A BIP-32 key origin as encoded in PSBT `xpub` and `bip32_derivation` fields:
  a 4-byte master key fingerprint followed by a derivation path.
  """
  alias Bitcoinex.ExtendedKey.DerivationPath

  @type t() :: %__MODULE__{
          fingerprint: binary(),
          derivation: DerivationPath.t()
        }

  @enforce_keys [:fingerprint, :derivation]
  defstruct [:fingerprint, :derivation]
end

defmodule Bitcoinex.PSBT.Utils do
  @moduledoc """
  Contains utility functions used throughout PSBT serialization.
  """
  alias Bitcoinex.{Base58, ExtendedKey}
  alias Bitcoinex.ExtendedKey.DerivationPath
  alias Bitcoinex.PSBT.KeyOrigin
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @doc """
  Reads a single compact-size-prefixed value off the front of a binary.
  """
  def parse_compact_size_value(key_value) do
    {value_length, key_value} = TxUtils.get_counter(key_value)
    <<value::binary-size(value_length), remaining::binary>> = key_value
    {value, remaining}
  end

  @doc """
  Parses a sequence of key-value records terminated by the 0x00 map separator,
  dispatching each record to `parse_func`.

  Rejects duplicate keys within the map (BIP-174) with `{:error, :duplicate_key}`,
  and propagates any `{:error, reason}` raised by `parse_func`.

  Returns `{:ok, {accumulator, remaining_binary}}` on success.
  """
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
    {key, remaining} = parse_compact_size_value(psbt)

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

  @doc """
  Serializes a key-value record: compact-size key length, key, compact-size
  value length, value.
  """
  def serialize_kv(key, value) do
    key_length = TxUtils.serialize_compact_size_unsigned_int(byte_size(key))
    value_length = TxUtils.serialize_compact_size_unsigned_int(byte_size(value))
    key_length <> key <> value_length <> value
  end

  @doc """
  Appends an item to a list-valued field, treating `nil` as the empty list.
  Preserves insertion order.
  """
  def append(nil, item), do: [item]
  def append(items, item) when is_list(items), do: items ++ [item]

  @doc """
  Serializes a repeatable (list-valued) field, mapping each item through
  `serialize_func`. A `nil` field serializes to nothing.
  """
  def serialize_repeatable(nil, _serialize_func), do: <<>>

  def serialize_repeatable(items, serialize_func) when is_list(items) do
    Enum.map_join(items, serialize_func)
  end

  @doc """
  Classifies an unrecognized key-value record: proprietary keys (leading byte
  0xFC) are collected into the `:proprietary` field, all others into `:unknown`.
  Returns `{field_name, record}` where record is `%{key: key, value: value}`.
  """
  def classify_unknown_record(<<0xFC, _rest::binary>> = key, value) do
    {:proprietary, %{key: key, value: value}}
  end

  def classify_unknown_record(key, value) do
    {:unknown, %{key: key, value: value}}
  end

  @doc """
  Parses the 78-byte raw extended key from a PSBT `xpub` key into an ExtendedKey.
  The PSBT encoding omits the Base58 checksum that `ExtendedKey` expects, so it
  is appended before parsing.
  """
  @spec parse_xpub_keydata(binary()) :: {:ok, ExtendedKey.t()} | {:error, term()}
  def parse_xpub_keydata(<<raw_extended_key::binary-size(78)>>) do
    ExtendedKey.parse_extended_key(Base58.append_checksum(raw_extended_key))
  end

  @doc """
  Serializes an ExtendedKey to the 78-byte raw form used in PSBT `xpub` keys
  (i.e. without the trailing 4-byte Base58 checksum).
  """
  @spec serialize_xpub_keydata(ExtendedKey.t()) :: binary()
  def serialize_xpub_keydata(xkey) do
    binary_part(ExtendedKey.serialize_extended_key(xkey), 0, 78)
  end

  @doc """
  Parses a key origin value: a 4-byte master fingerprint (stored verbatim, not
  reinterpreted) followed by little-endian uint32 derivation indexes.
  """
  @spec parse_key_origin(binary()) :: KeyOrigin.t()
  def parse_key_origin(<<fingerprint::binary-size(4), path::binary>>)
      when rem(byte_size(path), 4) == 0 do
    child_nums = for <<index::little-unsigned-32 <- path>>, do: index
    %KeyOrigin{fingerprint: fingerprint, derivation: %DerivationPath{child_nums: child_nums}}
  end

  @doc """
  Serializes a key origin: the 4-byte fingerprint followed by little-endian
  uint32 derivation indexes.
  """
  @spec serialize_key_origin(KeyOrigin.t()) :: binary()
  def serialize_key_origin(%KeyOrigin{fingerprint: fingerprint, derivation: derivation}) do
    path = for index <- derivation.child_nums, into: <<>>, do: <<index::little-size(32)>>
    fingerprint <> path
  end

  @doc """
  Combines two values for a singleton (non-repeatable) field (BIP-174 Combiner):
  takes whichever side is set, keeps the value if both agree, and returns
  `{:error, :conflicting_field}` if both are set and differ.
  """
  def combine_singleton(nil, value), do: {:ok, value}
  def combine_singleton(value, nil), do: {:ok, value}
  def combine_singleton(value, value), do: {:ok, value}
  def combine_singleton(_value_a, _value_b), do: {:error, :conflicting_field}

  @doc """
  Combines two repeatable (list-valued) fields into their union, identifying
  records by `key_fun`. Two records that share a key but differ in value are a
  `{:error, :conflicting_field}`. The union is sorted by key so the result is
  canonical and independent of argument order (the Combiner is commutative). An
  empty union normalizes back to `nil`.
  """
  def combine_repeatable(list_a, list_b, key_fun) do
    merged =
      Enum.reduce_while(to_list(list_b), {:ok, to_list(list_a)}, fn record, {:ok, accumulator} ->
        case Enum.find(accumulator, fn existing -> key_fun.(existing) == key_fun.(record) end) do
          nil ->
            {:cont, {:ok, accumulator ++ [record]}}

          existing ->
            if existing == record,
              do: {:cont, {:ok, accumulator}},
              else: {:halt, {:error, :conflicting_field}}
        end
      end)

    case merged do
      {:ok, []} -> {:ok, nil}
      {:ok, records} -> {:ok, Enum.sort_by(records, key_fun)}
      other -> other
    end
  end

  defp to_list(nil), do: []
  defp to_list(list) when is_list(list), do: list
end

defmodule Bitcoinex.PSBT.Global do
  @moduledoc """
  Global properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.KeyOrigin
  alias Bitcoinex.ExtendedKey
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils

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

  @doc """
  Builds a Global map wrapping an unsigned transaction.
  """
  @spec from_unsigned_tx(Transaction.t()) :: t()
  def from_unsigned_tx(%Transaction{} = tx) do
    %Global{unsigned_tx: %{tx | witnesses: nil}}
  end

  @doc """
  Adds a field to a Global map. Accepted fields:

    * `:unsigned_tx` — a `Transaction.t()`
    * `:xpub` — `%{xkey: ExtendedKey.t(), origin: KeyOrigin.t()}` (repeatable)
    * `:version` — a non-negative integer
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable)
  """
  @spec add_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_field(%Global{} = global, :unsigned_tx, %Transaction{} = tx) do
    {:ok, %Global{global | unsigned_tx: tx}}
  end

  def add_field(%Global{} = global, :xpub, %{xkey: %ExtendedKey{}, origin: %KeyOrigin{}} = xpub) do
    {:ok, %Global{global | xpub: PsbtUtils.append(global.xpub, xpub)}}
  end

  def add_field(%Global{} = global, :version, version)
      when is_integer(version) and version >= 0 do
    {:ok, %Global{global | version: version}}
  end

  def add_field(%Global{} = global, :proprietary, %{key: _, value: _} = record) do
    {:ok, %Global{global | proprietary: PsbtUtils.append(global.proprietary, record)}}
  end

  def add_field(%Global{} = global, :unknown, %{key: _, value: _} = record) do
    {:ok, %Global{global | unknown: PsbtUtils.append(global.unknown, record)}}
  end

  def add_field(%Global{}, _field, _value), do: {:error, :invalid_field}

  @doc """
  Combines two Global maps (BIP-174 Combiner). Callers guarantee the two
  `unsigned_tx` values are equal.
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(%Global{} = global_a, %Global{} = global_b) do
    with {:ok, version} <- PsbtUtils.combine_singleton(global_a.version, global_b.version),
         {:ok, xpub} <- PsbtUtils.combine_repeatable(global_a.xpub, global_b.xpub, &xpub_key/1),
         {:ok, proprietary} <-
           PsbtUtils.combine_repeatable(global_a.proprietary, global_b.proprietary, &record_key/1),
         {:ok, unknown} <-
           PsbtUtils.combine_repeatable(global_a.unknown, global_b.unknown, &record_key/1) do
      {:ok,
       %Global{
         global_a
         | version: version,
           xpub: xpub,
           proprietary: proprietary,
           unknown: unknown
       }}
    end
  end

  defp xpub_key(%{xkey: xkey}), do: PsbtUtils.serialize_xpub_keydata(xkey)
  defp record_key(%{key: key}), do: key

  @spec parse_global(binary()) :: {:ok, {t(), binary()}} | {:error, term()}
  def parse_global(psbt) do
    PsbtUtils.parse_key_value(psbt, %Global{}, &parse/3)
  end

  # BIP-174: the global unsigned tx must be serialized in the legacy
  # (non-witness) format. Re-serializing without witnesses must reproduce the
  # exact bytes; otherwise the input carried a segwit marker/flag/witness.
  defp legacy_serialized?(txn, txn_bytes) do
    TxUtils.serialize(%{txn | witnesses: []}) == txn_bytes
  end

  # BIP-174: every input in the unsigned tx must have an empty scriptSig.
  defp all_script_sigs_empty?(txn) do
    Enum.all?(txn.inputs, fn input -> input.script_sig in [nil, ""] end)
  end

  # unsigned transaction
  defp parse(<<@psbt_global_unsigned_tx::big-size(8)>>, psbt, global) do
    {txn_length, psbt} = TxUtils.get_counter(psbt)
    <<txn_bytes::binary-size(txn_length), psbt::binary>> = psbt

    case Transaction.decode(Base.encode16(txn_bytes, case: :lower)) do
      {:ok, txn} ->
        cond do
          not legacy_serialized?(txn, txn_bytes) ->
            {:error, :unsigned_tx_has_witness_serialization}

          not all_script_sigs_empty?(txn) ->
            {:error, :unsigned_tx_has_script_sig}

          true ->
            {%Global{global | unsigned_tx: txn}, psbt}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse(<<@psbt_global_xpub::big-size(8), raw_extended_key::binary-size(78)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case PsbtUtils.parse_xpub_keydata(raw_extended_key) do
      {:ok, xkey} ->
        xpub = %{xkey: xkey, origin: PsbtUtils.parse_key_origin(value)}
        {%Global{global | xpub: PsbtUtils.append(global.xpub, xpub)}, psbt}

      {:error, _reason} ->
        {:error, :invalid_xpub}
    end
  end

  defp parse(<<@psbt_global_version::big-size(8)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    <<version::little-unsigned-32>> = value
    {%Global{global | version: version}, psbt}
  end

  # A key whose leading byte is a known global type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _global)
       when type in [@psbt_global_unsigned_tx, @psbt_global_xpub, @psbt_global_version] do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {field, record} = PsbtUtils.classify_unknown_record(key, value)
    {Map.update(global, field, [record], &PsbtUtils.append(&1, record)), psbt}
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
    PsbtUtils.serialize_kv(<<@psbt_global_version::big-size(8)>>, <<version::little-size(32)>>)
  end

  defp serialize_xpub(%{xkey: xkey, origin: origin}) do
    key_data = PsbtUtils.serialize_xpub_keydata(xkey)
    value = PsbtUtils.serialize_key_origin(origin)
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
  alias Bitcoinex.Script
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.KeyOrigin
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Secp256k1.{Point, Signature}

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

  @valid_sighash_flags [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

  @doc """
  Returns an empty input map.
  """
  @spec new() :: t()
  def new(), do: %In{}

  @doc """
  Adds a field to an input map. Accepted fields:

    * `:non_witness_utxo` — a `Transaction.t()`
    * `:witness_utxo` — a `Transaction.Out.t()`
    * `:partial_sig` — `%{public_key: Point.t(), signature: Signature.t(), sighash: 0..255}` (repeatable)
    * `:sighash_type` — one of the valid sighash flag integers
    * `:redeem_script` / `:witness_script` / `:final_scriptsig` — a `Script.t()` or its hex/binary
    * `:bip32_derivation` — `%{public_key: Point.t(), origin: KeyOrigin.t()}` (repeatable)
    * `:final_scriptwitness` — a `Transaction.Witness.t()`
    * `:por_commitment` — a binary
    * `:ripemd160` / `:sha256` / `:hash160` / `:hash256` — `%{hash: binary(), preimage: binary()}` (repeatable)
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable)
  """
  @spec add_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_field(%In{} = input, :non_witness_utxo, %Transaction{} = tx) do
    {:ok, %In{input | non_witness_utxo: tx}}
  end

  def add_field(%In{} = input, :witness_utxo, %Out{} = utxo) do
    {:ok, %In{input | witness_utxo: utxo}}
  end

  def add_field(
        %In{} = input,
        :partial_sig,
        %{
          public_key: %Point{},
          signature: %Signature{},
          sighash: sighash
        } = record
      )
      when sighash in @valid_sighash_flags do
    {:ok, %In{input | partial_sig: PsbtUtils.append(input.partial_sig, record)}}
  end

  def add_field(%In{} = input, :sighash_type, sighash_type)
      when sighash_type in @valid_sighash_flags do
    {:ok, %In{input | sighash_type: sighash_type}}
  end

  def add_field(%In{} = input, :redeem_script, script) do
    with_script(script, fn script -> %In{input | redeem_script: script} end)
  end

  def add_field(%In{} = input, :witness_script, script) do
    with_script(script, fn script -> %In{input | witness_script: script} end)
  end

  def add_field(%In{} = input, :final_scriptsig, script) do
    with_script(script, fn script -> %In{input | final_scriptsig: script} end)
  end

  def add_field(
        %In{} = input,
        :bip32_derivation,
        %{public_key: %Point{}, origin: %KeyOrigin{}} = record
      ) do
    {:ok, %In{input | bip32_derivation: PsbtUtils.append(input.bip32_derivation, record)}}
  end

  def add_field(%In{} = input, :final_scriptwitness, %Witness{} = witness) do
    {:ok, %In{input | final_scriptwitness: witness}}
  end

  def add_field(%In{} = input, :por_commitment, por_commitment)
      when is_binary(por_commitment) do
    {:ok, %In{input | por_commitment: por_commitment}}
  end

  def add_field(%In{} = input, :ripemd160, %{hash: hash, preimage: preimage} = record)
      when byte_size(hash) == 20 and is_binary(preimage) do
    {:ok, %In{input | ripemd160: PsbtUtils.append(input.ripemd160, record)}}
  end

  def add_field(%In{} = input, :sha256, %{hash: hash, preimage: preimage} = record)
      when byte_size(hash) == 32 and is_binary(preimage) do
    {:ok, %In{input | sha256: PsbtUtils.append(input.sha256, record)}}
  end

  def add_field(%In{} = input, :hash160, %{hash: hash, preimage: preimage} = record)
      when byte_size(hash) == 20 and is_binary(preimage) do
    {:ok, %In{input | hash160: PsbtUtils.append(input.hash160, record)}}
  end

  def add_field(%In{} = input, :hash256, %{hash: hash, preimage: preimage} = record)
      when byte_size(hash) == 32 and is_binary(preimage) do
    {:ok, %In{input | hash256: PsbtUtils.append(input.hash256, record)}}
  end

  def add_field(%In{} = input, :proprietary, %{key: _, value: _} = record) do
    {:ok, %In{input | proprietary: PsbtUtils.append(input.proprietary, record)}}
  end

  def add_field(%In{} = input, :unknown, %{key: _, value: _} = record) do
    {:ok, %In{input | unknown: PsbtUtils.append(input.unknown, record)}}
  end

  def add_field(%In{}, _field, _value), do: {:error, :invalid_field}

  @doc """
  Combines two input maps (BIP-174 Combiner).
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(%In{} = input_a, %In{} = input_b) do
    with {:ok, non_witness_utxo} <-
           PsbtUtils.combine_singleton(input_a.non_witness_utxo, input_b.non_witness_utxo),
         {:ok, witness_utxo} <-
           PsbtUtils.combine_singleton(input_a.witness_utxo, input_b.witness_utxo),
         {:ok, sighash_type} <-
           PsbtUtils.combine_singleton(input_a.sighash_type, input_b.sighash_type),
         {:ok, redeem_script} <-
           PsbtUtils.combine_singleton(input_a.redeem_script, input_b.redeem_script),
         {:ok, witness_script} <-
           PsbtUtils.combine_singleton(input_a.witness_script, input_b.witness_script),
         {:ok, final_scriptsig} <-
           PsbtUtils.combine_singleton(input_a.final_scriptsig, input_b.final_scriptsig),
         {:ok, final_scriptwitness} <-
           PsbtUtils.combine_singleton(input_a.final_scriptwitness, input_b.final_scriptwitness),
         {:ok, por_commitment} <-
           PsbtUtils.combine_singleton(input_a.por_commitment, input_b.por_commitment),
         {:ok, partial_sig} <-
           PsbtUtils.combine_repeatable(
             input_a.partial_sig,
             input_b.partial_sig,
             &public_key_key/1
           ),
         {:ok, bip32_derivation} <-
           PsbtUtils.combine_repeatable(
             input_a.bip32_derivation,
             input_b.bip32_derivation,
             &public_key_key/1
           ),
         {:ok, ripemd160} <-
           PsbtUtils.combine_repeatable(input_a.ripemd160, input_b.ripemd160, &hash_key/1),
         {:ok, sha256} <-
           PsbtUtils.combine_repeatable(input_a.sha256, input_b.sha256, &hash_key/1),
         {:ok, hash160} <-
           PsbtUtils.combine_repeatable(input_a.hash160, input_b.hash160, &hash_key/1),
         {:ok, hash256} <-
           PsbtUtils.combine_repeatable(input_a.hash256, input_b.hash256, &hash_key/1),
         {:ok, proprietary} <-
           PsbtUtils.combine_repeatable(input_a.proprietary, input_b.proprietary, &record_key/1),
         {:ok, unknown} <-
           PsbtUtils.combine_repeatable(input_a.unknown, input_b.unknown, &record_key/1) do
      {:ok,
       %In{
         non_witness_utxo: non_witness_utxo,
         witness_utxo: witness_utxo,
         partial_sig: partial_sig,
         sighash_type: sighash_type,
         redeem_script: redeem_script,
         witness_script: witness_script,
         bip32_derivation: bip32_derivation,
         final_scriptsig: final_scriptsig,
         final_scriptwitness: final_scriptwitness,
         por_commitment: por_commitment,
         ripemd160: ripemd160,
         sha256: sha256,
         hash160: hash160,
         hash256: hash256,
         proprietary: proprietary,
         unknown: unknown
       }}
    end
  end

  defp public_key_key(%{public_key: public_key}), do: Point.sec(public_key)
  defp hash_key(%{hash: hash}), do: hash
  defp record_key(%{key: key}), do: key

  @doc """
  Returns true if this input has been finalized (has a final scriptSig and/or
  scriptWitness).
  """
  @spec finalized?(t()) :: boolean()
  def finalized?(%In{final_scriptsig: nil, final_scriptwitness: nil}), do: false
  def finalized?(%In{}), do: true

  @doc """
  Attempts to finalize this input (the BIP-174 Input Finalizer role), given the
  transaction input that references it (used to locate the scriptPubKey and to
  validate any non-witness UTXO). Returns the finalized input, or the input
  unchanged if it cannot be finalized (best-effort, matching Bitcoin Core).
  """
  @spec finalize(t(), Transaction.In.t()) :: t()
  def finalize(%In{} = input, tx_input) do
    with false <- finalized?(input),
         {:ok, script_pub_key} <- script_pub_key(input, tx_input),
         {:ok, final_scriptsig, final_scriptwitness} <- build_finalization(input, script_pub_key) do
      finalized_input(input, final_scriptsig, final_scriptwitness)
    else
      _ -> input
    end
  end

  # Resolves the scriptPubKey being spent, from the witness UTXO or, for a
  # non-witness UTXO, the referenced output (after checking the txid matches).
  defp script_pub_key(%In{witness_utxo: %Out{} = utxo}, _tx_input) do
    Script.parse_script(utxo.script_pub_key)
  end

  defp script_pub_key(%In{non_witness_utxo: %Transaction{} = tx}, tx_input) do
    if Transaction.transaction_id(tx) == tx_input.prev_txid do
      case Enum.at(tx.outputs, tx_input.prev_vout) do
        nil -> :error
        output -> Script.parse_script(output.script_pub_key)
      end
    else
      :error
    end
  end

  defp script_pub_key(_input, _tx_input), do: :error

  # Builds {final_scriptsig, final_scriptwitness} for the input's script type, or
  # :cannot_finalize if the collected data is insufficient or the type is
  # unsupported.
  defp build_finalization(input, script_pub_key) do
    case Script.get_script_type(script_pub_key) do
      :p2pkh -> finalize_p2pkh(input)
      :p2wpkh -> finalize_p2wpkh(input)
      :p2sh -> finalize_p2sh(input)
      :p2wsh -> finalize_p2wsh(input, input.witness_script)
      :multi -> finalize_bare_multisig(input, script_pub_key)
      _other -> :cannot_finalize
    end
  end

  defp finalize_p2pkh(input) do
    case single_signature(input) do
      {:ok, signature, public_key} ->
        {:ok, script_from_bytes(push_data(signature) <> push_data(public_key)), nil}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  defp finalize_p2wpkh(input) do
    case single_signature(input) do
      {:ok, signature, public_key} ->
        {:ok, nil, witness([signature, public_key])}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  defp finalize_p2sh(%In{redeem_script: nil}), do: :cannot_finalize

  defp finalize_p2sh(%In{redeem_script: redeem_script} = input) do
    redeem_bytes = Script.serialize_script(redeem_script)

    cond do
      Script.is_p2wpkh?(redeem_script) ->
        case single_signature(input) do
          {:ok, signature, public_key} ->
            {:ok, script_from_bytes(push_data(redeem_bytes)), witness([signature, public_key])}

          :cannot_finalize ->
            :cannot_finalize
        end

      Script.is_p2wsh?(redeem_script) ->
        case finalize_p2wsh(input, input.witness_script) do
          {:ok, nil, final_scriptwitness} ->
            {:ok, script_from_bytes(push_data(redeem_bytes)), final_scriptwitness}

          :cannot_finalize ->
            :cannot_finalize
        end

      Script.is_multi?(redeem_script) ->
        case multisig_signatures(redeem_script, input.partial_sig) do
          {:ok, signatures} ->
            scriptsig =
              <<0x00>> <>
                Enum.map_join(signatures, &push_data/1) <> push_data(redeem_bytes)

            {:ok, script_from_bytes(scriptsig), nil}

          :cannot_finalize ->
            :cannot_finalize
        end

      true ->
        :cannot_finalize
    end
  end

  defp finalize_p2wsh(_input, nil), do: :cannot_finalize

  defp finalize_p2wsh(input, witness_script) do
    case multisig_signatures(witness_script, input.partial_sig) do
      {:ok, signatures} ->
        stack_items = signatures ++ [Script.serialize_script(witness_script)]
        {:ok, nil, witness([<<>> | stack_items])}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  defp finalize_bare_multisig(input, script_pub_key) do
    case multisig_signatures(script_pub_key, input.partial_sig) do
      {:ok, signatures} ->
        {:ok, script_from_bytes(<<0x00>> <> Enum.map_join(signatures, &push_data/1)), nil}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  # Extracts exactly one signature and its pubkey for single-key script types.
  defp single_signature(%In{partial_sig: [partial_sig]}) do
    {:ok, signature_bytes(partial_sig), Point.sec(partial_sig.public_key)}
  end

  defp single_signature(_input), do: :cannot_finalize

  # Collects the m signatures required by a multisig script, in the order the
  # pubkeys appear in the script.
  defp multisig_signatures(multisig_script, partial_sigs) do
    if Script.is_multi?(multisig_script) do
      {:ok, required, public_keys} = Script.extract_multi_policy(multisig_script)

      signatures =
        public_keys
        |> Enum.map(&find_partial_sig(partial_sigs, &1))
        |> Enum.reject(&is_nil/1)
        |> Enum.map(&signature_bytes/1)

      if length(signatures) >= required do
        {:ok, Enum.take(signatures, required)}
      else
        :cannot_finalize
      end
    else
      :cannot_finalize
    end
  end

  defp find_partial_sig(partial_sigs, public_key) do
    Enum.find(partial_sigs || [], fn partial_sig ->
      Point.sec(partial_sig.public_key) == Point.sec(public_key)
    end)
  end

  defp signature_bytes(%{signature: signature, sighash: sighash}) do
    Signature.der_serialize_signature(signature) <> <<sighash>>
  end

  # Builds a witness stack from raw byte items.
  defp witness(items) do
    %Witness{txinwitness: Enum.map(items, &Base.encode16(&1, case: :lower))}
  end

  defp script_from_bytes(bytes) do
    {:ok, script} = Script.parse_script(Base.encode16(bytes, case: :lower))
    script
  end

  # Minimal Bitcoin script data push for the given bytes.
  defp push_data(data) do
    data_size = byte_size(data)

    cond do
      data_size < 0x4C -> <<data_size>> <> data
      data_size <= 0xFF -> <<0x4C, data_size>> <> data
      data_size <= 0xFFFF -> <<0x4D, data_size::little-size(16)>> <> data
      true -> <<0x4E, data_size::little-size(32)>> <> data
    end
  end

  # Keeps only the fields a finalized input retains (BIP-174): the UTXO records,
  # the final scriptSig/scriptWitness, and any proprietary/unknown records.
  defp finalized_input(input, final_scriptsig, final_scriptwitness) do
    %In{
      non_witness_utxo: input.non_witness_utxo,
      witness_utxo: input.witness_utxo,
      final_scriptsig: final_scriptsig,
      final_scriptwitness: final_scriptwitness,
      proprietary: input.proprietary,
      unknown: input.unknown
    }
  end

  # Normalizes a Script, hex string, or raw binary into a Script and applies it.
  defp with_script(%Script{} = script, put_fun), do: {:ok, put_fun.(script)}

  defp with_script(script, put_fun) when is_binary(script) do
    case Script.parse_script(script) do
      {:ok, script} -> {:ok, put_fun.(script)}
      {:error, _reason} -> {:error, :invalid_script}
    end
  end

  defp with_script(_script, _put_fun), do: {:error, :invalid_field}

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
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case Transaction.decode(Base.encode16(value, case: :lower)) do
      {:ok, txn} ->
        {%In{input | non_witness_utxo: txn}, psbt}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse(<<@psbt_in_witness_utxo::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    out = Out.output(value)
    {%In{input | witness_utxo: out}, psbt}
  end

  defp parse(
         <<@psbt_in_partial_sig::big-size(8), public_key_bytes::binary-size(33)>>,
         psbt,
         input
       ) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    with {:ok, public_key} <- Point.parse_public_key(public_key_bytes),
         {:ok, partial_sig} <- parse_partial_sig(public_key, value) do
      {%In{input | partial_sig: PsbtUtils.append(input.partial_sig, partial_sig)}, psbt}
    else
      {:error, _reason} -> {:error, :invalid_partial_sig}
    end
  end

  defp parse(<<@psbt_in_sighash_type::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    <<sighash_type::little-unsigned-32>> = value
    {%In{input | sighash_type: sighash_type}, psbt}
  end

  defp parse(<<@psbt_in_redeem_script::big-size(8)>>, psbt, input) do
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%In{input | redeem_script: script}, psbt}
    end
  end

  defp parse(<<@psbt_in_witness_script::big-size(8)>>, psbt, input) do
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%In{input | witness_script: script}, psbt}
    end
  end

  defp parse(
         <<@psbt_in_bip32_derivation::big-size(8), public_key_bytes::binary-size(33)>>,
         psbt,
         input
       ) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case Point.parse_public_key(public_key_bytes) do
      {:ok, public_key} ->
        record = %{public_key: public_key, origin: PsbtUtils.parse_key_origin(value)}
        {%In{input | bip32_derivation: PsbtUtils.append(input.bip32_derivation, record)}, psbt}

      {:error, _reason} ->
        {:error, :invalid_bip32_derivation}
    end
  end

  defp parse(<<@psbt_in_final_scriptsig::big-size(8)>>, psbt, input) do
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%In{input | final_scriptsig: script}, psbt}
    end
  end

  defp parse(<<@psbt_in_final_scriptwitness::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {%In{input | final_scriptwitness: Witness.witness(value)}, psbt}
  end

  defp parse(<<@psbt_in_por_commitment::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {%In{input | por_commitment: value}, psbt}
  end

  defp parse(<<@psbt_in_ripemd160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    record = %{hash: hash, preimage: preimage}
    {%In{input | ripemd160: PsbtUtils.append(input.ripemd160, record)}, psbt}
  end

  defp parse(<<@psbt_in_sha256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    record = %{hash: hash, preimage: preimage}
    {%In{input | sha256: PsbtUtils.append(input.sha256, record)}, psbt}
  end

  defp parse(<<@psbt_in_hash160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    record = %{hash: hash, preimage: preimage}
    {%In{input | hash160: PsbtUtils.append(input.hash160, record)}, psbt}
  end

  defp parse(<<@psbt_in_hash256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    record = %{hash: hash, preimage: preimage}
    {%In{input | hash256: PsbtUtils.append(input.hash256, record)}, psbt}
  end

  # A key whose leading byte is a known input type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _input)
       when type in @psbt_in_non_witness_utxo..@psbt_in_hash256 do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {field, record} = PsbtUtils.classify_unknown_record(key, value)
    {Map.update(input, field, [record], &PsbtUtils.append(&1, record)), psbt}
  end

  # Splits a PSBT partial_sig value into its DER signature and trailing sighash byte.
  defp parse_partial_sig(public_key, value) do
    signature_length = byte_size(value) - 1
    <<der_signature::binary-size(signature_length), sighash::8>> = value

    case Signature.der_parse_signature(der_signature) do
      {:ok, signature} ->
        {:ok, %{public_key: public_key, signature: signature, sighash: sighash}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Parses a length-prefixed script value into a Script struct.
  defp parse_script(psbt) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case Script.parse_script(Base.encode16(value, case: :lower)) do
      {:ok, script} -> {:ok, {script, psbt}}
      {:error, _reason} -> {:error, :invalid_script}
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
    PsbtUtils.serialize_kv(
      <<@psbt_in_sighash_type::big-size(8)>>,
      <<sighash_type::little-size(32)>>
    )
  end

  defp serialize_kv(:redeem_script, script) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_redeem_script::big-size(8)>>,
      Script.serialize_script(script)
    )
  end

  defp serialize_kv(:witness_script, script) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_witness_script::big-size(8)>>,
      Script.serialize_script(script)
    )
  end

  defp serialize_kv(:final_scriptsig, script) do
    PsbtUtils.serialize_kv(
      <<@psbt_in_final_scriptsig::big-size(8)>>,
      Script.serialize_script(script)
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

  defp serialize_partial_sig(%{public_key: public_key, signature: signature, sighash: sighash}) do
    key = <<@psbt_in_partial_sig::big-size(8)>> <> Point.sec(public_key)
    value = Signature.der_serialize_signature(signature) <> <<sighash>>
    PsbtUtils.serialize_kv(key, value)
  end

  defp serialize_bip32_derivation(%{public_key: public_key, origin: origin}) do
    key = <<@psbt_in_bip32_derivation::big-size(8)>> <> Point.sec(public_key)
    PsbtUtils.serialize_kv(key, PsbtUtils.serialize_key_origin(origin))
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
  alias Bitcoinex.Script
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.PSBT.KeyOrigin
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Secp256k1.Point

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

  @doc """
  Returns an empty output map.
  """
  @spec new() :: t()
  def new(), do: %Out{}

  @doc """
  Adds a field to an output map. Accepted fields:

    * `:redeem_script` / `:witness_script` — a `Script.t()` or its hex/binary
    * `:bip32_derivation` — `%{public_key: Point.t(), origin: KeyOrigin.t()}` (repeatable)
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable)
  """
  @spec add_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_field(%Out{} = output, :redeem_script, script) do
    with_script(script, fn script -> %Out{output | redeem_script: script} end)
  end

  def add_field(%Out{} = output, :witness_script, script) do
    with_script(script, fn script -> %Out{output | witness_script: script} end)
  end

  def add_field(
        %Out{} = output,
        :bip32_derivation,
        %{public_key: %Point{}, origin: %KeyOrigin{}} = record
      ) do
    {:ok, %Out{output | bip32_derivation: PsbtUtils.append(output.bip32_derivation, record)}}
  end

  def add_field(%Out{} = output, :proprietary, %{key: _, value: _} = record) do
    {:ok, %Out{output | proprietary: PsbtUtils.append(output.proprietary, record)}}
  end

  def add_field(%Out{} = output, :unknown, %{key: _, value: _} = record) do
    {:ok, %Out{output | unknown: PsbtUtils.append(output.unknown, record)}}
  end

  def add_field(%Out{}, _field, _value), do: {:error, :invalid_field}

  @doc """
  Combines two output maps (BIP-174 Combiner).
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(%Out{} = output_a, %Out{} = output_b) do
    with {:ok, redeem_script} <-
           PsbtUtils.combine_singleton(output_a.redeem_script, output_b.redeem_script),
         {:ok, witness_script} <-
           PsbtUtils.combine_singleton(output_a.witness_script, output_b.witness_script),
         {:ok, bip32_derivation} <-
           PsbtUtils.combine_repeatable(
             output_a.bip32_derivation,
             output_b.bip32_derivation,
             &public_key_key/1
           ),
         {:ok, proprietary} <-
           PsbtUtils.combine_repeatable(output_a.proprietary, output_b.proprietary, &record_key/1),
         {:ok, unknown} <-
           PsbtUtils.combine_repeatable(output_a.unknown, output_b.unknown, &record_key/1) do
      {:ok,
       %Out{
         redeem_script: redeem_script,
         witness_script: witness_script,
         bip32_derivation: bip32_derivation,
         proprietary: proprietary,
         unknown: unknown
       }}
    end
  end

  defp public_key_key(%{public_key: public_key}), do: Point.sec(public_key)
  defp record_key(%{key: key}), do: key

  defp with_script(%Script{} = script, put_fun), do: {:ok, put_fun.(script)}

  defp with_script(script, put_fun) when is_binary(script) do
    case Script.parse_script(script) do
      {:ok, script} -> {:ok, put_fun.(script)}
      {:error, _reason} -> {:error, :invalid_script}
    end
  end

  defp with_script(_script, _put_fun), do: {:error, :invalid_field}

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
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%Out{output | redeem_script: script}, psbt}
    end
  end

  defp parse(<<@psbt_out_witness_script::big-size(8)>>, psbt, output) do
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%Out{output | witness_script: script}, psbt}
    end
  end

  defp parse(
         <<@psbt_out_bip32_derivation::big-size(8), public_key_bytes::binary-size(33)>>,
         psbt,
         output
       ) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case Point.parse_public_key(public_key_bytes) do
      {:ok, public_key} ->
        record = %{public_key: public_key, origin: PsbtUtils.parse_key_origin(value)}
        {%Out{output | bip32_derivation: PsbtUtils.append(output.bip32_derivation, record)}, psbt}

      {:error, _reason} ->
        {:error, :invalid_bip32_derivation}
    end
  end

  # A key whose leading byte is a known output type but which did not match the
  # exact format above is malformed (BIP-174: wrong key length for its type).
  defp parse(<<type, _rest::binary>>, _psbt, _output)
       when type in @psbt_out_redeem_script..@psbt_out_bip32_derivation do
    {:error, :invalid_key_format}
  end

  defp parse(key, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {field, record} = PsbtUtils.classify_unknown_record(key, value)
    {Map.update(output, field, [record], &PsbtUtils.append(&1, record)), psbt}
  end

  # Parses a length-prefixed script value into a Script struct.
  defp parse_script(psbt) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    case Script.parse_script(Base.encode16(value, case: :lower)) do
      {:ok, script} -> {:ok, {script, psbt}}
      {:error, _reason} -> {:error, :invalid_script}
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

  defp serialize_kv(:redeem_script, script) do
    PsbtUtils.serialize_kv(
      <<@psbt_out_redeem_script::big-size(8)>>,
      Script.serialize_script(script)
    )
  end

  defp serialize_kv(:witness_script, script) do
    PsbtUtils.serialize_kv(
      <<@psbt_out_witness_script::big-size(8)>>,
      Script.serialize_script(script)
    )
  end

  defp serialize_bip32_derivation(%{public_key: public_key, origin: origin}) do
    key = <<@psbt_out_bip32_derivation::big-size(8)>> <> Point.sec(public_key)
    PsbtUtils.serialize_kv(key, PsbtUtils.serialize_key_origin(origin))
  end

  defp serialize_record(%{key: key, value: value}) do
    PsbtUtils.serialize_kv(key, value)
  end
end
