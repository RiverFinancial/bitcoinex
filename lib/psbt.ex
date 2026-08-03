defmodule Bitcoinex.PSBT do
  @moduledoc """
  Support for Partially Signed Bitcoin Transactions (PSBT).

  The format consists of key-value maps.
  Each map consists of a sequence of key-value records, terminated by a 0x00 byte.

  Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

  Only PSBT version 0 (BIP-174) is supported; version 2 (BIP-370) and the
  BIP-371 taproot fields are not.

  Known limitations (deliberate):

  * Public keys in `partial_sig` and `bip32_derivation` records must be
    33-byte compressed SEC keys: decoded keys are stored as `Secp256k1.Point`
    structs, which re-serialize compressed, so legacy uncompressed (65-byte)
    keys — permitted by BIP-174 — are rejected with
    `{:error, :uncompressed_public_key}` rather than silently re-encoded to a
    different key.
  * Serialization always emits records in ascending key-type order with
    unknown records last (as Bitcoin Core does). `decode |> encode_b64` is
    byte-identical for canonically-ordered PSBTs; a PSBT whose records arrive
    in a different order decodes to the same struct but re-encodes canonically.
  * `redeem_script`, `witness_script`, and `final_scriptsig` values must parse
    as Script: they are stored as `Bitcoinex.Script` structs, so a value whose
    bytes are not valid script (e.g. a truncated push) is rejected with
    `{:error, :invalid_script}`. BIP-174 treats these fields as opaque byte
    strings, so this is stricter than Bitcoin Core — which accepts (almost
    certainly unspendable) unparseable scripts.
  """
  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Utils, as: TxUtils
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
    with :ok <- validate_unsigned_tx(tx) do
      {:ok,
       %PSBT{
         global: Global.from_unsigned_tx(tx),
         inputs: Enum.map(tx.inputs, fn _input -> In.new() end),
         outputs: Enum.map(tx.outputs, fn _output -> Out.new() end)
       }}
    end
  end

  # A PSBT's global unsigned transaction must carry no scriptSigs and no
  # witness data (BIP-174). A tx decoded from segwit serialization carries one
  # *empty* witness stack per input — that is still unsigned (Core's Creator
  # accepts these and strips them), so only a non-empty stack disqualifies.
  defp validate_unsigned_tx(%Transaction{} = tx) do
    cond do
      Enum.any?(tx.inputs, fn input -> input.script_sig not in [nil, ""] end) ->
        {:error, :tx_not_unsigned}

      not unsigned_witnesses?(tx.witnesses) ->
        {:error, :tx_not_unsigned}

      true ->
        :ok
    end
  end

  defp unsigned_witnesses?(witnesses) when witnesses in [nil, []], do: true

  defp unsigned_witnesses?(witnesses) when is_list(witnesses) do
    Enum.all?(witnesses, fn witness -> witness.txinwitness in [nil, []] end)
  end

  defp unsigned_witnesses?(_witnesses), do: false

  @doc """
  Returns the txid of the PSBT's global unsigned transaction.
  """
  @spec txid(t()) :: {:ok, String.t()} | {:error, :no_unsigned_tx}
  def txid(%PSBT{global: %{unsigned_tx: %Transaction{} = tx}}),
    do: {:ok, Transaction.transaction_id(tx)}

  # Covers both global: nil and unsigned_tx: nil on hand-built structs.
  def txid(%PSBT{}), do: {:error, :no_unsigned_tx}

  @doc """
  Adds a field to the PSBT's global map (the BIP-174 Updater role).
  See `Bitcoinex.PSBT.Global.add_field/3` for the accepted fields.
  """
  @spec add_global_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_global_field(%PSBT{global: %{unsigned_tx: existing}}, :unsigned_tx, %Transaction{})
      when not is_nil(existing) do
    # The unsigned tx fixes the number of input/output maps; replacing it would
    # desync them (and is the Creator's job, not the Updater's).
    {:error, :unsigned_tx_already_set}
  end

  def add_global_field(%PSBT{} = psbt, :unsigned_tx, %Transaction{} = tx) do
    with :ok <- validate_unsigned_tx(tx),
         :ok <- validate_io_counts(psbt, tx),
         {:ok, global} <- Global.add_field(psbt.global || struct(Global), :unsigned_tx, tx) do
      {:ok, %PSBT{psbt | global: global}}
    end
  end

  def add_global_field(%PSBT{} = psbt, field, value) do
    # A hand-built PSBT may carry global: nil; treat it as an empty map rather
    # than raising. (struct/1 because Global is defined later in this file.)
    case Global.add_field(psbt.global || struct(Global), field, value) do
      {:ok, global} -> {:ok, %PSBT{psbt | global: global}}
      {:error, reason} -> {:error, reason}
    end
  end

  # The unsigned tx's input/output counts must match the PSBT's map counts.
  # A hand-built PSBT may carry inputs/outputs: nil — that is a mismatch, not
  # a raise (the Updater never raises).
  defp validate_io_counts(%PSBT{inputs: inputs, outputs: outputs}, %Transaction{} = tx) do
    if is_list(inputs) and is_list(outputs) and
         length(tx.inputs) == length(inputs) and length(tx.outputs) == length(outputs) do
      :ok
    else
      {:error, :tx_io_count_mismatch}
    end
  end

  @doc """
  Adds a field to the input map at `index`.
  See `Bitcoinex.PSBT.In.add_field/3` for the accepted fields.
  """
  @spec add_input_field(t(), non_neg_integer(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_input_field(%PSBT{} = psbt, index, :non_witness_utxo, %Transaction{} = utxo) do
    # Mirror the decoder: a non_witness_utxo must be the transaction the input
    # spends (same txid, prevout index in range), else the Updater would build
    # a PSBT its own decoder rejects — and hand a Finalizer the wrong prevout.
    with :ok <- validate_non_witness_utxo(psbt, index, utxo),
         {:ok, inputs} <-
           put_item_field(psbt.inputs, index, &In.add_field(&1, :non_witness_utxo, utxo)) do
      {:ok, %PSBT{psbt | inputs: inputs}}
    end
  end

  def add_input_field(%PSBT{} = psbt, index, field, value) do
    case put_item_field(psbt.inputs, index, &In.add_field(&1, field, value)) do
      {:ok, inputs} -> {:ok, %PSBT{psbt | inputs: inputs}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_non_witness_utxo(%PSBT{global: global}, index, %Transaction{} = utxo) do
    case global && global.unsigned_tx do
      nil ->
        {:error, :missing_unsigned_tx}

      %Transaction{inputs: tx_inputs} ->
        case Enum.at(tx_inputs, index) do
          nil ->
            {:error, :index_out_of_range}

          tx_input ->
            case safe_transaction_id(utxo) do
              {:ok, utxo_txid} ->
                if utxo_txid == tx_input.prev_txid and
                     tx_input.prev_vout < length(utxo.outputs) do
                  :ok
                else
                  {:error, :non_witness_utxo_mismatch}
                end

              {:error, reason} ->
                {:error, reason}
            end
        end
    end
  end

  # Computing the txid serializes the whole transaction, which raises on a
  # hand-built struct with invalid (e.g. uppercase) hex in any script field.
  # Reject those cleanly: the Updater must never crash, nor store a utxo its
  # own encoder cannot serialize.
  defp safe_transaction_id(%Transaction{} = tx) do
    {:ok, Transaction.transaction_id(tx)}
  rescue
    _error in [MatchError, ArgumentError, FunctionClauseError] ->
      {:error, :invalid_non_witness_utxo}
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

  Both PSBTs must describe the same global unsigned transaction — compared by
  full serialization, byte for byte — otherwise `{:error, :mismatched_tx}` is
  returned; a PSBT lacking an unsigned transaction altogether yields
  `{:error, :missing_unsigned_tx}`, and PSBTs whose input or output map counts
  do not match yield `{:error, :map_count_mismatch}` rather than silently
  dropping maps. Each map is merged field by field: singleton fields must agree
  where both are set, and repeatable fields are unioned by key. A record
  present in both maps under the same key but with a different value yields
  `{:error, :conflicting_field}`.

  The union keeps the first PSBT's records in their existing order and appends
  records new from the second (Bitcoin Core's merge semantics), so `combine/2`
  is idempotent (`combine(a, a) == {:ok, a}`) and commutative up to record
  order for non-conflicting inputs.
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(
        %PSBT{global: %{unsigned_tx: %Transaction{}}} = psbt_a,
        %PSBT{
          global: %{unsigned_tx: %Transaction{}} = _global_b
        } = psbt_b
      ) do
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

  # A hand-built PSBT may lack the mandatory unsigned tx (or the whole global
  # map); there is nothing to compare, so refuse rather than raise.
  def combine(%PSBT{}, %PSBT{}), do: {:error, :missing_unsigned_tx}

  # BIP-174 Combiner precondition: the two PSBTs must describe the same unsigned
  # transaction. Compare the full serialization byte-for-byte (not just the txid)
  # so a hand-built PSBT carrying stray witnesses or scriptSigs that happen to
  # collide on txid is still rejected. `TxUtils.serialize/1` emits legacy form
  # when there are no witnesses, so the genuine "witnesses nil vs []" difference
  # between a decoded and a from_tx/1-built unsigned tx does not cause a mismatch.
  defp same_unsigned_tx?(tx_a, tx_b) do
    TxUtils.serialize(tx_a) == TxUtils.serialize(tx_b)
  end

  @doc """
  Finalizes every input that can be finalized (the BIP-174 Input Finalizer
  role), leaving the rest untouched (best-effort, matching Bitcoin Core). For
  each finalizable input it builds the `final_scriptsig` and/or
  `final_scriptwitness` from the collected signatures and scripts and removes
  the now-redundant fields.

  Supported spend types: p2pkh, p2wpkh, p2sh-p2wpkh, bare/p2sh/p2wsh multisig,
  and p2sh-p2wsh. Anything else — bare p2pk, p2sh-wrapped p2pkh, arbitrary
  scripts, taproot — is left unfinalized (not an error), so an untouched input
  can mean "unsupported spend type" as well as "missing signatures".
  A non-witness spend type additionally requires a `non_witness_utxo` whose
  txid matches the input's outpoint; a `witness_utxo` alone cannot be verified
  and is never trusted to finalize a non-witness input (BIP-174 Signer checks).

  Deliberate divergence from BIP-174: when an input specifies a
  `sighash_type`, the BIP says the finalizer "must fail to sign" if *any*
  `partial_sig` carries a different flag; this implementation instead treats
  such signatures as ineligible and finalizes if enough matching ones remain,
  so a stray signature contributed for an unrelated key (e.g. picked up in a
  `combine/2`) does not block an otherwise-complete input. Every signature
  actually placed in a `final_scriptsig`/`final_scriptwitness` always carries
  the required flag.
  """
  @spec finalize(t()) :: t()
  def finalize(%PSBT{global: %{unsigned_tx: %Transaction{} = tx}, inputs: inputs} = psbt)
      when is_list(inputs) do
    # A well-formed PSBT has exactly one input map per unsigned-tx input. If a
    # (hand-built) PSBT desyncs them — or its tx carries nil instead of an
    # input list — `Enum.zip` would finalize only the common prefix and
    # silently drop the rest, so leave the PSBT untouched instead (best-effort
    # means returning it untouched, not raising).
    if is_list(tx.inputs) and length(inputs) == length(tx.inputs) do
      inputs =
        inputs
        |> Enum.zip(tx.inputs)
        |> Enum.map(fn {input, tx_input} -> In.finalize(input, tx_input) end)

      %PSBT{psbt | inputs: inputs}
    else
      psbt
    end
  end

  # Nothing to finalize on a hand-built PSBT with no unsigned tx, no global
  # map, or no input list; best-effort means returning it untouched, not
  # raising.
  def finalize(%PSBT{} = psbt), do: psbt

  @doc """
  Returns true if every input has been finalized. A PSBT with no inputs at all
  (or a hand-built one with `inputs: nil`) is not considered finalized — there
  is nothing extractable in it.
  """
  @spec finalized?(t()) :: boolean()
  def finalized?(%PSBT{inputs: inputs}) when is_list(inputs) and inputs != [],
    do: Enum.all?(inputs, &In.finalized?/1)

  def finalized?(%PSBT{}), do: false

  @doc """
  Extracts the fully-signed network transaction from a finalized PSBT (the
  BIP-174 Transaction Extractor role). Returns `{:error, :not_finalized}` unless
  every input is finalized.
  """
  @spec extract_tx(t()) :: {:ok, Transaction.t()} | {:error, :not_finalized}
  def extract_tx(%PSBT{global: %{unsigned_tx: %Transaction{} = tx}} = psbt) do
    if finalized?(psbt) and is_list(tx.inputs) and length(psbt.inputs) == length(tx.inputs) do
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

  def extract_tx(%PSBT{}), do: {:error, :not_finalized}

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

  # Combines two lists of maps positionally, short-circuiting on the first
  # conflict. The lists must be the same length: `Enum.zip` would otherwise
  # silently truncate to the shorter one and drop maps. For validly-decoded
  # PSBTs equal txids imply equal counts, but a hand-built PSBT could desync
  # them — or carry nil instead of a list — so guard explicitly rather than
  # lose data or raise.
  defp combine_pairs(maps_a, maps_b, _combiner)
       when not is_list(maps_a) or not is_list(maps_b) do
    {:error, :map_count_mismatch}
  end

  defp combine_pairs(maps_a, maps_b, _combiner) when length(maps_a) != length(maps_b) do
    {:error, :map_count_mismatch}
  end

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
  # A hand-built PSBT may carry inputs/outputs: nil — no index is in range
  # there, and the Updater never raises.
  defp put_item_field(items, index, add_field_fun) do
    if not is_list(items) or index < 0 or index >= length(items) do
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

    Returns `{:error, :missing_unsigned_tx}` for a PSBT without a global
    unsigned transaction (see `to_file/2`).
  """
  @spec encode_b64(t()) :: String.t() | {:error, :missing_unsigned_tx}
  def encode_b64(packet) do
    case ensure_unsigned_tx(packet) do
      :ok -> packet |> serialize() |> Base.encode64()
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
         :ok <- validate_non_witness_utxos(inputs, global.unsigned_tx.inputs),
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

  # BIP-174: an input's non_witness_utxo is the full transaction identified by
  # that input's prevout. Its txid must equal the input's prev_txid and the
  # prevout index must reference one of its outputs; otherwise the PSBT is
  # internally inconsistent (it provides the wrong previous transaction).
  defp validate_non_witness_utxos(inputs, tx_inputs) do
    inputs
    |> Enum.zip(tx_inputs)
    |> Enum.reduce_while(:ok, fn {input, tx_input}, :ok ->
      case input.non_witness_utxo do
        nil ->
          {:cont, :ok}

        %Transaction{} = utxo ->
          if Transaction.transaction_id(utxo) == tx_input.prev_txid and
               tx_input.prev_vout < length(utxo.outputs) do
            {:cont, :ok}
          else
            {:halt, {:error, :non_witness_utxo_mismatch}}
          end
      end
    end)
  end

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

  BIP-174 requires compact size uints to be minimally encoded, so a
  non-minimal length is rejected: it cannot survive a re-serialize
  byte-for-byte, and a non-minimally encoded zero key length would produce
  an empty key that re-serializes as a map separator, silently corrupting
  the PSBT on re-encode.
  """
  @spec parse_compact_size_value(binary()) ::
          {binary(), binary()} | {:error, :non_canonical_compact_size}
  def parse_compact_size_value(key_value) do
    {value_length, remaining} = TxUtils.get_counter(key_value)
    prefix_size = byte_size(key_value) - byte_size(remaining)

    if byte_size(TxUtils.serialize_compact_size_unsigned_int(value_length)) == prefix_size do
      <<value::binary-size(value_length), remaining::binary>> = remaining
      {value, remaining}
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
      {<<>>, _remaining} ->
        {:error, :invalid_key_format}

      {key, remaining} ->
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

  @doc """
  Validates the raw key of an Updater-supplied `:proprietary` or `:unknown`
  record. A `:proprietary` key must carry the 0xFC type byte. An `:unknown` key
  must be non-empty (an empty key re-serializes as the 0x00 map separator,
  corrupting the PSBT) and must not use a type byte the section parses into a
  dedicated field, nor 0xFC — such a record would re-decode as a different
  struct (or a `:duplicate_key` error), breaking `decode(encode_b64(psbt))`.
  """
  @spec validate_updater_key(:proprietary | :unknown, binary(), Enumerable.t()) ::
          :ok | {:error, :invalid_key_format}
  def validate_updater_key(:proprietary, <<0xFC, _rest::binary>>, _known_types), do: :ok

  def validate_updater_key(:unknown, <<type, _rest::binary>>, known_types) do
    if type == 0xFC or type in known_types do
      {:error, :invalid_key_format}
    else
      :ok
    end
  end

  def validate_updater_key(_field, _key, _known_types), do: {:error, :invalid_key_format}

  @doc """
  Parses the 78-byte raw extended key from a PSBT `xpub` key into an ExtendedKey.
  The PSBT encoding omits the Base58 checksum that `ExtendedKey` expects, so it
  is appended before parsing.

  BIP-174 defines the key-data as an extended *public* key; an extended private
  key is rejected with `{:error, :private_key_not_allowed}` — PSBTs are meant
  to be shared, and no private key may pass through this module.
  """
  @spec parse_xpub_keydata(binary()) :: {:ok, ExtendedKey.t()} | {:error, term()}
  def parse_xpub_keydata(<<raw_extended_key::binary-size(78)>>) do
    with {:ok, xkey} <- ExtendedKey.parse_extended_key(Base58.append_checksum(raw_extended_key)),
         :ok <- ensure_public_xkey(xkey) do
      {:ok, xkey}
    end
  end

  @doc """
  Returns `:ok` for an extended public key, `{:error, :private_key_not_allowed}`
  for an extended private key.
  """
  @spec ensure_public_xkey(ExtendedKey.t()) :: :ok | {:error, :private_key_not_allowed}
  def ensure_public_xkey(%ExtendedKey{} = xkey) do
    if ExtendedKey.public_key?(xkey), do: :ok, else: {:error, :private_key_not_allowed}
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
  @spec parse_key_origin(binary()) :: {:ok, KeyOrigin.t()} | {:error, :invalid_derivation}
  def parse_key_origin(<<fingerprint::binary-size(4), path::binary>>)
      when rem(byte_size(path), 4) == 0 do
    child_nums = for <<index::little-unsigned-32 <- path>>, do: index

    {:ok,
     %KeyOrigin{fingerprint: fingerprint, derivation: %DerivationPath{child_nums: child_nums}}}
  end

  # BIP-174: the value is a 4-byte fingerprint followed by whole 32-bit
  # indexes — a shorter value or a trailing partial index is malformed, not
  # ignorable (dropping bytes would silently alter the PSBT on re-serialize).
  def parse_key_origin(_), do: {:error, :invalid_derivation}

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
  @spec combine_singleton(term(), term()) :: {:ok, term()} | {:error, :conflicting_field}
  def combine_singleton(nil, value), do: {:ok, value}
  def combine_singleton(value, nil), do: {:ok, value}
  def combine_singleton(value, value), do: {:ok, value}
  def combine_singleton(_value_a, _value_b), do: {:error, :conflicting_field}

  @doc """
  Combines two repeatable (list-valued) fields into their union, identifying
  records by `key_fun`. Two records that share a key but differ in value are a
  `{:error, :conflicting_field}`.

  The union keeps the first list's records in their existing order and appends
  only records new from the second list (Bitcoin Core's `Merge` semantics), so
  `combine(a, a) == a` unconditionally and combining reproduces the official
  BIP-174 Combiner vector byte-for-byte. Commutativity holds up to record
  order — the same record *set* results either way — which is all BIP-174
  asks of key-value maps. An empty union normalizes back to `nil`.
  """
  @spec combine_repeatable(list() | nil, list() | nil, (term() -> term())) ::
          {:ok, list() | nil} | {:error, :conflicting_field}
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
      other -> other
    end
  end

  defp to_list(nil), do: []
  defp to_list(list) when is_list(list), do: list

  @doc """
  Validates a caller-supplied `KeyOrigin`: the fingerprint must be exactly 4
  bytes and every derivation index a concrete uint32 (`DerivationPath`
  wildcards like `:any` cannot be serialized into a PSBT). Guards the Updater
  against values that would corrupt or raise at encode time.
  """
  @spec validate_key_origin(KeyOrigin.t()) :: :ok | {:error, :invalid_key_origin}
  def validate_key_origin(%KeyOrigin{
        fingerprint: <<_::binary-size(4)>>,
        derivation: %DerivationPath{child_nums: child_nums}
      })
      when is_list(child_nums) do
    if Enum.all?(child_nums, fn i -> is_integer(i) and i >= 0 and i <= 0xFFFFFFFF end) do
      :ok
    else
      {:error, :invalid_key_origin}
    end
  end

  def validate_key_origin(_origin), do: {:error, :invalid_key_origin}

  @doc """
  Appends a record to a repeatable (list-valued, `nil`-as-empty) field unless a
  record with the same key (per `key_fun`) is already present — a PSBT map may
  not contain duplicate keys, so an Updater must not create one.
  """
  @spec append_unique(list() | nil, term(), (term() -> term())) ::
          {:ok, list()} | {:error, :duplicate_key}
  def append_unique(items, item, key_fun) do
    items = items || []
    key = key_fun.(item)

    if Enum.any?(items, fn existing -> key_fun.(existing) == key end) do
      {:error, :duplicate_key}
    else
      {:ok, items ++ [item]}
    end
  end
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

  @type t() :: %__MODULE__{
          unsigned_tx: Transaction.t() | nil,
          xpub: list(%{xkey: ExtendedKey.t(), origin: KeyOrigin.t()}) | nil,
          version: non_neg_integer() | nil,
          proprietary: list(%{key: binary(), value: binary()}) | nil,
          unknown: list(%{key: binary(), value: binary()}) | nil
        }

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
  @known_global_types [@psbt_global_unsigned_tx, @psbt_global_xpub, @psbt_global_version]

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
    * `:xpub` — `%{xkey: ExtendedKey.t(), origin: KeyOrigin.t()}` (repeatable); the
      key must be an extended *public* key (`{:error, :private_key_not_allowed}`)
    * `:version` — `0` (only PSBT v0 is supported; any other integer is
      `{:error, :unsupported_version}`)
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable);
      a `:proprietary` key must carry the 0xFC type byte, and an `:unknown` key
      must be non-empty and must not use a type byte this map already parses
      into a dedicated field, nor 0xFC (`{:error, :invalid_key_format}`) — such
      a record could not survive a decode round-trip

  Repeatable fields reject a record whose key is already present
  (`{:error, :duplicate_key}`): a PSBT map may not contain duplicate keys, so
  the Updater must not create one its own decoder would reject.
  """
  @spec add_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  # Witnesses are normalized away like `from_unsigned_tx/1` does: an unsigned
  # tx must never serialize in segwit form (the decoder rejects it), and a tx
  # decoded from segwit serialization carries only empty stacks anyway.
  def add_field(%Global{} = global, :unsigned_tx, %Transaction{} = tx) do
    {:ok, %Global{global | unsigned_tx: %{tx | witnesses: nil}}}
  end

  def add_field(
        %Global{} = global,
        :xpub,
        %{xkey: %ExtendedKey{} = xkey, origin: %KeyOrigin{} = origin} = xpub
      ) do
    with :ok <- PsbtUtils.ensure_public_xkey(xkey),
         :ok <- PsbtUtils.validate_key_origin(origin),
         :ok <- validate_xpub_depth(xkey, origin),
         {:ok, xpubs} <-
           PsbtUtils.append_unique(global.xpub, xpub, & &1.xkey) do
      {:ok, %Global{global | xpub: xpubs}}
    end
  end

  # Only PSBT v0 is supported, so 0 is the only version we will emit.
  def add_field(%Global{} = global, :version, 0) do
    {:ok, %Global{global | version: 0}}
  end

  def add_field(%Global{}, :version, version) when is_integer(version) do
    {:error, :unsupported_version}
  end

  def add_field(%Global{} = global, :proprietary, %{key: key, value: _} = record) do
    with :ok <- PsbtUtils.validate_updater_key(:proprietary, key, @known_global_types),
         {:ok, records} <- PsbtUtils.append_unique(global.proprietary, record, & &1.key) do
      {:ok, %Global{global | proprietary: records}}
    end
  end

  def add_field(%Global{} = global, :unknown, %{key: key, value: _} = record) do
    with :ok <- PsbtUtils.validate_updater_key(:unknown, key, @known_global_types),
         {:ok, records} <- PsbtUtils.append_unique(global.unknown, record, & &1.key) do
      {:ok, %Global{global | unknown: records}}
    end
  end

  def add_field(%Global{}, _field, _value), do: {:error, :invalid_field}

  # BIP-174: "The number of 32 bit unsigned integer indexes must match the
  # depth provided in the extended public key."
  defp validate_xpub_depth(%ExtendedKey{depth: <<depth>>}, %KeyOrigin{derivation: derivation}) do
    if length(derivation.child_nums) == depth do
      :ok
    else
      {:error, :xpub_depth_mismatch}
    end
  end

  # A hand-built ExtendedKey whose depth is not a 1-byte binary must not raise
  # out of the Updater.
  defp validate_xpub_depth(%ExtendedKey{}, %KeyOrigin{}), do: {:error, :xpub_depth_mismatch}

  @doc """
  Combines two Global maps (BIP-174 Combiner). Callers guarantee the two
  `unsigned_tx` values are equal.
  """
  @spec combine(t(), t()) :: {:ok, t()} | {:error, atom()}
  def combine(%Global{} = global_a, %Global{} = global_b) do
    with {:ok, xpub} <- PsbtUtils.combine_repeatable(global_a.xpub, global_b.xpub, &xpub_key/1),
         {:ok, proprietary} <-
           PsbtUtils.combine_repeatable(global_a.proprietary, global_b.proprietary, &record_key/1),
         {:ok, unknown} <-
           PsbtUtils.combine_repeatable(global_a.unknown, global_b.unknown, &record_key/1) do
      {:ok,
       %Global{
         global_a
         | version: combine_version(global_a.version, global_b.version),
           xpub: xpub,
           proprietary: proprietary,
           unknown: unknown
       }}
    end
  end

  # BIP-174: when two PSBTs for the same tx carry different PSBT versions, the
  # combiner keeps the higher version rather than treating it as a conflict.
  defp combine_version(nil, version), do: version
  defp combine_version(version, nil), do: version
  defp combine_version(version_a, version_b), do: max(version_a, version_b)

  defp xpub_key(%{xkey: xkey}), do: PsbtUtils.serialize_xpub_keydata(xkey)
  defp record_key(%{key: key}), do: key

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

      {txn_bytes, psbt} ->
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

  defp parse(<<@psbt_global_xpub::big-size(8), raw_extended_key::binary-size(78)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    with {:ok, xkey} <- PsbtUtils.parse_xpub_keydata(raw_extended_key),
         {:ok, origin} <- PsbtUtils.parse_key_origin(value),
         :ok <- validate_xpub_depth(xkey, origin) do
      xpub = %{xkey: xkey, origin: origin}
      {%Global{global | xpub: PsbtUtils.append(global.xpub, xpub)}, psbt}
    else
      {:error, :private_key_not_allowed} ->
        {:error, :private_key_not_allowed}

      {:error, :invalid_derivation} ->
        {:error, :invalid_derivation}

      {:error, :xpub_depth_mismatch} ->
        {:error, :xpub_depth_mismatch}

      {:error, _reason} ->
        {:error, :invalid_xpub}
    end
  end

  # BIP-174: the version is a 32-bit little-endian unsigned int. Only v0 is
  # supported: a PSBT that advertises any other version follows a spec
  # (BIP-370 v2, etc.) whose fields we do not implement, so we must not parse
  # it as if it were v0.
  defp parse(<<@psbt_global_version::big-size(8)>>, psbt, global) do
    case PsbtUtils.parse_compact_size_value(psbt) do
      {<<0::little-unsigned-32>>, psbt} ->
        {%Global{global | version: 0}, psbt}

      {<<_version::little-unsigned-32>>, _psbt} ->
        {:error, :unsupported_version}

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

  @type key_value_record() :: %{key: binary(), value: binary()}
  @type hash_preimage_record() :: %{hash: binary(), preimage: binary()}

  @type t() :: %__MODULE__{
          non_witness_utxo: Transaction.t() | nil,
          witness_utxo: Out.t() | nil,
          partial_sig:
            list(%{public_key: Point.t(), signature: binary(), sighash_flag: non_neg_integer()})
            | nil,
          sighash_type: non_neg_integer() | nil,
          redeem_script: Script.t() | nil,
          witness_script: Script.t() | nil,
          bip32_derivation: list(%{public_key: Point.t(), origin: KeyOrigin.t()}) | nil,
          final_scriptsig: Script.t() | nil,
          final_scriptwitness: Witness.t() | nil,
          por_commitment: binary() | nil,
          ripemd160: list(hash_preimage_record()) | nil,
          sha256: list(hash_preimage_record()) | nil,
          hash160: list(hash_preimage_record()) | nil,
          hash256: list(hash_preimage_record()) | nil,
          proprietary: list(key_value_record()) | nil,
          unknown: list(key_value_record()) | nil
        }

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
    * `:partial_sig` — `%{public_key: Point.t(), signature: binary(), sighash_flag: flag}` (repeatable), where `signature` is the raw DER-encoded ECDSA signature (stored verbatim, so it round-trips byte-for-byte) and `flag` (like `:sighash_type`) must be one of the valid sighash flags `0x01`/`0x02`/`0x03` optionally `| 0x80`
    * `:sighash_type` — one of the valid sighash flag integers
    * `:redeem_script` / `:witness_script` / `:final_scriptsig` — a `Script.t()` or its hex/binary
    * `:bip32_derivation` — `%{public_key: Point.t(), origin: KeyOrigin.t()}` (repeatable)
    * `:final_scriptwitness` — a `Transaction.Witness.t()`
    * `:por_commitment` — a binary
    * `:ripemd160` / `:sha256` / `:hash160` / `:hash256` — `%{hash: binary(), preimage: binary()}` (repeatable); the hash must be the digest of the preimage under the named algorithm, else `{:error, :invalid_hash_preimage}`
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable);
      a `:proprietary` key must carry the 0xFC type byte, and an `:unknown` key
      must be non-empty and must not use a type byte this map already parses
      into a dedicated field, nor 0xFC (`{:error, :invalid_key_format}`) — such
      a record could not survive a decode round-trip
  """
  @spec add_field(t(), atom(), any()) :: {:ok, t()} | {:error, atom()}
  def add_field(%In{} = input, :non_witness_utxo, %Transaction{} = tx) do
    {:ok, %In{input | non_witness_utxo: tx}}
  end

  # The amount serializes as a uint64, so anything above 0xFFFFFFFFFFFFFFFF
  # would silently truncate on encode.
  def add_field(
        %In{} = input,
        :witness_utxo,
        %Out{script_pub_key: script_pub_key, value: value} = utxo
      )
      when is_integer(value) and value >= 0 and value <= 0xFFFFFFFFFFFFFFFF do
    case normalize_hex(script_pub_key) do
      {:ok, hex} -> {:ok, %In{input | witness_utxo: %Out{utxo | script_pub_key: hex}}}
      :error -> {:error, :invalid_field}
    end
  end

  def add_field(
        %In{} = input,
        :partial_sig,
        %{
          public_key: %Point{},
          signature: signature,
          sighash_flag: sighash_flag
        } = record
      )
      when is_binary(signature) and sighash_flag in @valid_sighash_flags do
    # Signatures are kept as their raw DER bytes so they round-trip verbatim, but
    # still validate that those bytes are well-formed DER so a garbage partial_sig
    # is rejected rather than stored.
    with {:ok, _signature} <- Signature.der_parse_signature(signature),
         {:ok, partial_sigs} <-
           PsbtUtils.append_unique(input.partial_sig, record, &Point.sec(&1.public_key)) do
      {:ok, %In{input | partial_sig: partial_sigs}}
    else
      {:error, :duplicate_key} -> {:error, :duplicate_key}
      {:error, _reason} -> {:error, :invalid_partial_sig}
    end
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
        %{public_key: %Point{}, origin: %KeyOrigin{} = origin} = record
      ) do
    with :ok <- PsbtUtils.validate_key_origin(origin),
         {:ok, records} <-
           PsbtUtils.append_unique(input.bip32_derivation, record, &Point.sec(&1.public_key)) do
      {:ok, %In{input | bip32_derivation: records}}
    end
  end

  def add_field(%In{} = input, :final_scriptwitness, %Witness{txinwitness: items} = witness)
      when is_list(items) do
    case normalize_hex_list(items) do
      {:ok, items} ->
        {:ok, %In{input | final_scriptwitness: %Witness{witness | txinwitness: items}}}

      :error ->
        {:error, :invalid_field}
    end
  end

  def add_field(%In{} = input, :por_commitment, por_commitment)
      when is_binary(por_commitment) do
    {:ok, %In{input | por_commitment: por_commitment}}
  end

  def add_field(%In{} = input, :ripemd160, %{hash: _, preimage: _} = record) do
    put_hash_preimage(input, :ripemd160, record, &:crypto.hash(:ripemd160, &1))
  end

  def add_field(%In{} = input, :sha256, %{hash: _, preimage: _} = record) do
    put_hash_preimage(input, :sha256, record, &Bitcoinex.Utils.sha256/1)
  end

  def add_field(%In{} = input, :hash160, %{hash: _, preimage: _} = record) do
    put_hash_preimage(input, :hash160, record, &Bitcoinex.Utils.hash160/1)
  end

  def add_field(%In{} = input, :hash256, %{hash: _, preimage: _} = record) do
    put_hash_preimage(input, :hash256, record, &Bitcoinex.Utils.double_sha256/1)
  end

  def add_field(%In{} = input, :proprietary, %{key: key, value: _} = record) do
    with :ok <-
           PsbtUtils.validate_updater_key(
             :proprietary,
             key,
             @psbt_in_non_witness_utxo..@psbt_in_hash256
           ),
         {:ok, records} <- PsbtUtils.append_unique(input.proprietary, record, & &1.key) do
      {:ok, %In{input | proprietary: records}}
    end
  end

  def add_field(%In{} = input, :unknown, %{key: key, value: _} = record) do
    with :ok <-
           PsbtUtils.validate_updater_key(
             :unknown,
             key,
             @psbt_in_non_witness_utxo..@psbt_in_hash256
           ),
         {:ok, records} <- PsbtUtils.append_unique(input.unknown, record, & &1.key) do
      {:ok, %In{input | unknown: records}}
    end
  end

  def add_field(%In{}, _field, _value), do: {:error, :invalid_field}

  # BIP-174 hash-preimage fields (ripemd160/sha256/hash160/hash256) require the
  # hash to be the digest of the preimage. Validate that before appending, so
  # the Updater never records a preimage a finalizer could not use.
  defp put_hash_preimage(input, field, %{hash: hash, preimage: preimage}, hash_fun)
       when is_binary(hash) and is_binary(preimage) do
    if hash_fun.(preimage) == hash do
      record = %{hash: hash, preimage: preimage}

      with {:ok, records} <- PsbtUtils.append_unique(Map.get(input, field), record, & &1.hash) do
        {:ok, Map.put(input, field, records)}
      end
    else
      {:error, :invalid_hash_preimage}
    end
  end

  defp put_hash_preimage(_input, _field, _record, _hash_fun), do: {:error, :invalid_field}

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
      # Update syntax (not a fresh struct literal) so a field added to %In{}
      # later at least survives combining from the first argument instead of
      # being silently dropped from both sides.
      {:ok,
       %In{
         input_a
         | non_witness_utxo: non_witness_utxo,
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
         {:ok, final_scriptsig, final_scriptwitness} <-
           build_finalization(eligible_signatures(input), script_pub_key) do
      finalized_input(input, final_scriptsig, final_scriptwitness)
    else
      _ -> input
    end
  end

  # BIP-174: a finalizer must not finalize an input with a signature that does
  # not match the sighash type the input requires. Signatures with a different
  # flag are simply not eligible for selection — they may belong to keys not in
  # this input's script at all (e.g. after combining PSBTs from several
  # signers), so their presence alone must not block finalization.
  defp eligible_signatures(%In{sighash_type: nil} = input), do: input

  defp eligible_signatures(%In{sighash_type: sighash_type, partial_sig: partial_sigs} = input) do
    eligible =
      Enum.filter(partial_sigs || [], fn partial_sig ->
        partial_sig.sighash_flag == sighash_type
      end)

    %In{input | partial_sig: eligible}
  end

  # Resolves the scriptPubKey being spent. The non-witness UTXO is preferred:
  # it is the full previous transaction, verifiable against the input's
  # outpoint (txid + index), whereas a witness_utxo is a bare output that
  # cannot be cross-checked at all.
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

  defp script_pub_key(%In{witness_utxo: %Out{} = utxo}, _tx_input) do
    Script.parse_script(utxo.script_pub_key)
  end

  defp script_pub_key(_input, _tx_input), do: :error

  # Builds {final_scriptsig, final_scriptwitness} for the input's script type, or
  # :cannot_finalize if the collected data is insufficient or the type is
  # unsupported.
  defp build_finalization(input, script_pub_key) do
    case Script.get_script_type(script_pub_key) do
      :p2pkh -> with_non_witness_utxo(input, &finalize_p2pkh(&1, script_pub_key))
      :p2wpkh -> finalize_p2wpkh(input, script_pub_key)
      :p2sh -> finalize_p2sh(input, script_pub_key)
      :p2wsh -> finalize_p2wsh(input, input.witness_script, script_pub_key)
      :multi -> with_non_witness_utxo(input, &finalize_bare_multisig(&1, script_pub_key))
      _other -> :cannot_finalize
    end
  end

  # BIP-174 Signer check: "A Witness UTXO is provided for a non-witness input"
  # must fail. A non-witness spend path may only be finalized from a
  # non_witness_utxo (whose txid the caller verified against the outpoint) —
  # a lying witness_utxo must not steer a legacy finalization.
  defp with_non_witness_utxo(%In{non_witness_utxo: %Transaction{}} = input, finalize_fun),
    do: finalize_fun.(input)

  defp with_non_witness_utxo(%In{}, _finalize_fun), do: :cannot_finalize

  defp finalize_p2pkh(input, script_pub_key) do
    case single_signature_for(input, script_pub_key, &Script.create_p2pkh/1) do
      {:ok, signature, public_key} ->
        {:ok, script_with_pushes([signature, public_key]), nil}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  defp finalize_p2wpkh(input, script_pub_key) do
    case single_signature_for(input, script_pub_key, &Script.create_p2wpkh/1) do
      {:ok, signature, public_key} ->
        {:ok, nil, witness([signature, public_key])}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  defp finalize_p2sh(%In{redeem_script: nil}, _script_pub_key), do: :cannot_finalize

  defp finalize_p2sh(%In{redeem_script: redeem_script} = input, script_pub_key) do
    redeem_bytes = Script.serialize_script(redeem_script)

    cond do
      # BIP-174 Signer/Finalizer check: the redeemScript must hash (HASH160) to
      # the p2sh scriptPubKey. Without this, a mismatched redeemScript would be
      # assembled into a provably-invalid scriptSig.
      Script.to_p2sh(redeem_script) != {:ok, script_pub_key} ->
        :cannot_finalize

      Script.is_p2wpkh?(redeem_script) ->
        case single_signature_for(input, redeem_script, &Script.create_p2wpkh/1) do
          {:ok, signature, public_key} ->
            {:ok, script_with_pushes([redeem_bytes]), witness([signature, public_key])}

          :cannot_finalize ->
            :cannot_finalize
        end

      Script.is_p2wsh?(redeem_script) ->
        case finalize_p2wsh(input, input.witness_script, redeem_script) do
          {:ok, nil, final_scriptwitness} ->
            {:ok, script_with_pushes([redeem_bytes]), final_scriptwitness}

          :cannot_finalize ->
            :cannot_finalize
        end

      Script.is_multi?(redeem_script) ->
        # A legacy (non-witness) spend path: like p2pkh, it may only be
        # finalized from a verifiable non_witness_utxo (see
        # with_non_witness_utxo/2).
        with_non_witness_utxo(input, fn input ->
          case multisig_signatures(redeem_script, input.partial_sig) do
            {:ok, signatures} ->
              {:ok, script_with_op0_dummy(signatures ++ [redeem_bytes]), nil}

            :cannot_finalize ->
              :cannot_finalize
          end
        end)

      true ->
        :cannot_finalize
    end
  end

  defp finalize_p2wsh(_input, nil, _expected_p2wsh), do: :cannot_finalize

  defp finalize_p2wsh(input, witness_script, expected_p2wsh) do
    cond do
      # BIP-174 Signer/Finalizer check: the witnessScript must hash (SHA256) to
      # the p2wsh witness program — the scriptPubKey for native p2wsh, or the
      # redeemScript for p2sh-nested p2wsh.
      Script.to_p2wsh(witness_script) != {:ok, expected_p2wsh} ->
        :cannot_finalize

      true ->
        case multisig_signatures(witness_script, input.partial_sig) do
          {:ok, signatures} ->
            stack_items = signatures ++ [Script.serialize_script(witness_script)]
            {:ok, nil, witness([<<>> | stack_items])}

          :cannot_finalize ->
            :cannot_finalize
        end
    end
  end

  defp finalize_bare_multisig(input, script_pub_key) do
    case multisig_signatures(script_pub_key, input.partial_sig) do
      {:ok, signatures} ->
        {:ok, script_with_op0_dummy(signatures), nil}

      :cannot_finalize ->
        :cannot_finalize
    end
  end

  # Finds the one partial_sig whose pubkey matches `expected_script` for a
  # single-key script type, returning its raw signature bytes and SEC pubkey.
  # `builder` rebuilds the expected script from HASH160(pubkey) — the p2pkh/p2wpkh
  # scriptPubKey, or the redeemScript for nested p2wpkh. This enforces the BIP-174
  # Signer key-hash check (without it a signature from an unrelated key would
  # finalize into a provably-invalid input) and, since the input may legitimately
  # carry signatures for several keys, also selects the correct one rather than
  # requiring exactly a single partial_sig.
  defp single_signature_for(%In{partial_sig: partial_sigs}, expected_script, builder) do
    case Enum.find(partial_sigs || [], fn partial_sig ->
           public_key = Point.sec(partial_sig.public_key)
           builder.(Bitcoinex.Utils.hash160(public_key)) == {:ok, expected_script}
         end) do
      nil ->
        :cannot_finalize

      partial_sig ->
        {:ok, signature_bytes(partial_sig), Point.sec(partial_sig.public_key)}
    end
  end

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

  # partial_sig signatures are stored as their raw DER bytes; the finalized
  # scriptSig/witness pushes those bytes followed by the 1-byte sighash flag.
  defp signature_bytes(%{signature: signature, sighash_flag: sighash_flag}) do
    signature <> <<sighash_flag>>
  end

  # Builds a witness stack from raw byte items.
  defp witness(items) do
    %Witness{txinwitness: Enum.map(items, &Base.encode16(&1, case: :lower))}
  end

  # Builds a Script pushing the given data items in order (Script items are
  # built back to front, so items are pushed in reverse).
  defp script_with_pushes(items) do
    Enum.reduce(Enum.reverse(items), Script.new(), fn item, acc ->
      {:ok, acc} = Script.push_data(acc, item)
      acc
    end)
  end

  # Same, preceded by the OP_0 dummy that OP_CHECKMULTISIG's off-by-one pops.
  defp script_with_op0_dummy(items) do
    {:ok, script} = Script.push_op(script_with_pushes(items), 0x00)
    script
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
  # NOTE: hex is tried first, so a raw binary whose bytes are all ASCII hex
  # digits is read as hex. Pass a %Script{} (or hex) to avoid the ambiguity.
  defp with_script(%Script{} = script, put_fun), do: {:ok, put_fun.(script)}

  defp with_script(script, put_fun) when is_binary(script) do
    case Script.parse_script(script) do
      {:ok, script} -> {:ok, put_fun.(script)}
      {:error, _reason} -> {:error, :invalid_script}
    end
  end

  defp with_script(_script, _put_fun), do: {:error, :invalid_field}

  # Validates that a string is hex and normalizes it to lowercase, so the Updater
  # rejects values that would otherwise raise at encode time (the serializers use
  # `Base.decode16(.., case: :lower)`). Returns `:error` for non-hex input.
  defp normalize_hex(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, _bytes} -> {:ok, String.downcase(hex)}
      :error -> :error
    end
  end

  defp normalize_hex(_hex), do: :error

  defp normalize_hex_list(items) when is_list(items) do
    Enum.reduce_while(items, {:ok, []}, fn item, {:ok, acc} ->
      case normalize_hex(item) do
        {:ok, hex} -> {:cont, {:ok, [hex | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      :error -> :error
    end
  end

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

  # BIP-174: the value is the entire output in network serialization — bytes
  # beyond the scriptPubKey are malformed, not ignorable (dropping them would
  # also silently alter the PSBT on re-serialize). Like the tx-valued fields,
  # the parsed output must reproduce the value bytes exactly, so a non-minimal
  # scriptPubKey length is rejected too.
  defp parse(<<@psbt_in_witness_utxo::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

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

  # partial_sig is repeatable: one record per signing pubkey (BIP-174 keys them
  # by pubkey), so a multisig input legitimately carries several.
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

  # 65-byte (uncompressed) pubkeys are valid in BIP-174 but unsupported here:
  # `Secp256k1.Point` carries no compression flag, so an uncompressed key could
  # not be re-serialized faithfully. Reject with a distinct reason rather than
  # conflating it with a malformed key.
  defp parse(<<@psbt_in_partial_sig::big-size(8), _public_key::binary-size(65)>>, _psbt, _input) do
    {:error, :uncompressed_public_key}
  end

  # BIP-174: the sighash type is a 32-bit little-endian unsigned int, stored
  # here as an integer and validated against the known ECDSA sighash flags.
  defp parse(<<@psbt_in_sighash_type::big-size(8)>>, psbt, input) do
    case PsbtUtils.parse_compact_size_value(psbt) do
      {<<sighash_type::little-unsigned-32>>, psbt} when sighash_type in @valid_sighash_flags ->
        {%In{input | sighash_type: sighash_type}, psbt}

      _ ->
        {:error, :invalid_sighash_type}
    end
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

    with {:ok, public_key} <- Point.parse_public_key(public_key_bytes),
         {:ok, origin} <- PsbtUtils.parse_key_origin(value) do
      record = %{public_key: public_key, origin: origin}
      {%In{input | bip32_derivation: PsbtUtils.append(input.bip32_derivation, record)}, psbt}
    else
      {:error, :invalid_derivation} -> {:error, :invalid_derivation}
      {:error, _reason} -> {:error, :invalid_bip32_derivation}
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
    with {:ok, {script, psbt}} <- parse_script(psbt) do
      {%In{input | final_scriptsig: script}, psbt}
    end
  end

  # BIP-174: the value is the entire witness stack in network serialization —
  # bytes beyond the last stack item are malformed, not ignorable. Like the
  # tx-valued fields, the parsed stack must reproduce the value bytes exactly,
  # so a non-minimal stack count or item length is rejected too.
  defp parse(<<@psbt_in_final_scriptwitness::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

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

  defp parse(<<@psbt_in_por_commitment::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {%In{input | por_commitment: value}, psbt}
  end

  defp parse(<<@psbt_in_ripemd160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    parse_hash_preimage(input, :ripemd160, hash, psbt, &:crypto.hash(:ripemd160, &1))
  end

  defp parse(<<@psbt_in_sha256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    parse_hash_preimage(input, :sha256, hash, psbt, &Bitcoinex.Utils.sha256/1)
  end

  defp parse(<<@psbt_in_hash160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    parse_hash_preimage(input, :hash160, hash, psbt, &Bitcoinex.Utils.hash160/1)
  end

  defp parse(<<@psbt_in_hash256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    parse_hash_preimage(input, :hash256, hash, psbt, &Bitcoinex.Utils.double_sha256/1)
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

  # BIP-174: for the 0x0a-0x0d preimage fields the key hash must equal the value
  # run through the field's hash algorithm. Reject a record that does not, so the
  # decoder never accepts a preimage a finalizer could not use (mirrors the
  # Updater's `put_hash_preimage/4` validation).
  defp parse_hash_preimage(input, field, hash, psbt, hash_fun) do
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    if hash_fun.(preimage) == hash do
      record = %{hash: hash, preimage: preimage}
      {Map.update(input, field, [record], &PsbtUtils.append(&1, record)), psbt}
    else
      {:error, :invalid_hash_preimage}
    end
  end

  # Splits a PSBT partial_sig value into its DER signature and trailing 1-byte
  # sighash flag. The DER signature is stored as raw bytes rather than parsed into
  # a Signature struct: re-serializing a parsed ECDSA signature yields canonical
  # DER, which is not guaranteed to reproduce a non-canonically-encoded input, so
  # storing the raw bytes is what makes partial_sig round-trip losslessly. The
  # bytes are still validated as well-formed DER so a malformed value is rejected.
  defp parse_partial_sig(public_key, value) do
    signature_length = byte_size(value) - 1
    <<der_signature::binary-size(signature_length), sighash_flag::8>> = value

    cond do
      sighash_flag not in @valid_sighash_flags ->
        {:error, :invalid_sighash_type}

      true ->
        case Signature.der_parse_signature(der_signature) do
          {:ok, _signature} ->
            {:ok, %{public_key: public_key, signature: der_signature, sighash_flag: sighash_flag}}

          {:error, reason} ->
            {:error, reason}
        end
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

  @spec serialize_inputs(list(t()) | nil) :: binary()
  def serialize_inputs(nil), do: <<>>

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

  defp serialize_partial_sig(%{
         public_key: public_key,
         signature: signature,
         sighash_flag: sighash_flag
       }) do
    key = <<@psbt_in_partial_sig::big-size(8)>> <> Point.sec(public_key)
    value = signature <> <<sighash_flag>>
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

  @type t() :: %__MODULE__{
          redeem_script: Script.t() | nil,
          witness_script: Script.t() | nil,
          bip32_derivation: list(%{public_key: Point.t(), origin: KeyOrigin.t()}) | nil,
          proprietary: list(%{key: binary(), value: binary()}) | nil,
          unknown: list(%{key: binary(), value: binary()}) | nil
        }

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
    * `:proprietary` / `:unknown` — `%{key: binary(), value: binary()}` (repeatable);
      a `:proprietary` key must carry the 0xFC type byte, and an `:unknown` key
      must be non-empty and must not use a type byte this map already parses
      into a dedicated field, nor 0xFC (`{:error, :invalid_key_format}`) — such
      a record could not survive a decode round-trip
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
        %{public_key: %Point{}, origin: %KeyOrigin{} = origin} = record
      ) do
    with :ok <- PsbtUtils.validate_key_origin(origin),
         {:ok, records} <-
           PsbtUtils.append_unique(output.bip32_derivation, record, &Point.sec(&1.public_key)) do
      {:ok, %Out{output | bip32_derivation: records}}
    end
  end

  def add_field(%Out{} = output, :proprietary, %{key: key, value: _} = record) do
    with :ok <-
           PsbtUtils.validate_updater_key(
             :proprietary,
             key,
             @psbt_out_redeem_script..@psbt_out_bip32_derivation
           ),
         {:ok, records} <- PsbtUtils.append_unique(output.proprietary, record, & &1.key) do
      {:ok, %Out{output | proprietary: records}}
    end
  end

  def add_field(%Out{} = output, :unknown, %{key: key, value: _} = record) do
    with :ok <-
           PsbtUtils.validate_updater_key(
             :unknown,
             key,
             @psbt_out_redeem_script..@psbt_out_bip32_derivation
           ),
         {:ok, records} <- PsbtUtils.append_unique(output.unknown, record, & &1.key) do
      {:ok, %Out{output | unknown: records}}
    end
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
      # Update syntax (not a fresh struct literal) so a field added to %Out{}
      # later at least survives combining from the first argument instead of
      # being silently dropped from both sides.
      {:ok,
       %Out{
         output_a
         | redeem_script: redeem_script,
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

    with {:ok, public_key} <- Point.parse_public_key(public_key_bytes),
         {:ok, origin} <- PsbtUtils.parse_key_origin(value) do
      record = %{public_key: public_key, origin: origin}
      {%Out{output | bip32_derivation: PsbtUtils.append(output.bip32_derivation, record)}, psbt}
    else
      {:error, :invalid_derivation} -> {:error, :invalid_derivation}
      {:error, _reason} -> {:error, :invalid_bip32_derivation}
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

  @spec serialize_outputs(list(t()) | nil) :: binary()
  def serialize_outputs(nil), do: <<>>

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
