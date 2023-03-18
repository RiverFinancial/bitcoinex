defmodule Bitcoinex.PSBT do
  @moduledoc """
  Support for Partially Signed Bitcoin Transactions (PSBT).

  The format consists of key-value maps.
  Each map consists of a sequence of key-value records, terminated by a 0x00 byte.

  Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
  """
  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Utils

  @type t() :: %__MODULE__{}

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
  def decode(psbt_b64) when is_binary(psbt_b64) do
    case Base.decode64(psbt_b64) do
      {:ok, psbt_b64} ->
        parse(psbt_b64)

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
    |> parse()
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

  def parse(<<@magic::big-size(32), @separator::big-size(8), psbt::binary>>) do
    # key-value pairs for all global data
    {global, psbt} = Global.parse_global(psbt)

    {in_counter, out_counter} =
      cond do
        # either unsigned_tx must be present for v0 or in/out count must be present for v2 PSBT
        global.unsigned_tx != nil ->
          {length(global.unsigned_tx.inputs), length(global.unsigned_tx.outputs)}

        global.input_count != nil && global.output_count != nil ->
          {global.input_count, global.output_count}
      end

    {inputs, psbt} = In.parse_inputs(psbt, in_counter)
    {outputs, _} = Out.parse_outputs(psbt, out_counter)

    {:ok,
     %PSBT{
       global: global,
       inputs: inputs,
       outputs: outputs
     }}
  end

  @spec from_tx(Transaction.t()) :: {:ok, Bitcoinex.PSBT.t()}
  def from_tx(tx) do
    inputs = In.from_tx_inputs(tx.inputs, tx.witnesses)
    outputs = Out.from_tx_outputs(tx.outputs)

    {:ok,
     %PSBT{
       global: Global.from_tx(tx),
       inputs: inputs,
       outputs: outputs
     }}
  end

  def to_tx(psbt) do
    tx = psbt.global.unsigned_tx

    inputs = In.populate_script_sigs(tx.inputs, psbt.inputs)

    witnesses = In.populate_witnesses(psbt.inputs)

    %Bitcoinex.Transaction{tx | witnesses: witnesses, inputs: inputs}
  end
end

defmodule Bitcoinex.PSBT.Utils do
  @moduledoc """
  Contains utility functions used throughout PSBT serialization.
  """
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Utils
  alias Bitcoinex.ExtendedKey.DerivationPath

  def parse_compact_size_value(key_value) do
    {len, key_value} = TxUtils.get_counter(key_value)
    <<value::binary-size(len), remaining::binary>> = key_value
    {value, remaining}
  end

  # parses key value pairs with a provided parse function
  def parse_key_value(psbt, kv, parse_func) do
    case psbt do
      # separator
      <<0x00::big-size(8), psbt::binary>> ->
        {kv, psbt}

      _ ->
        case parse_compact_size_value(psbt) do
          {key, psbt} ->
            {kv, psbt} = parse_func.(key, psbt, kv)
            parse_key_value(psbt, kv, parse_func)
        end
    end
  end

  def serialize_kv(key, val) do
    key_len = Utils.serialize_compact_size_unsigned_int(byte_size(key))
    val_len = Utils.serialize_compact_size_unsigned_int(byte_size(val))
    key_len <> key <> val_len <> val
  end

  def serialize_repeatable_fields(_, nil, _), do: <<>>

  def serialize_repeatable_fields(field, values, serialize_func) do
    for(kv <- values, do: serialize_func.(field, kv))
    |> :erlang.list_to_binary()
  end

  def parse_fingerprint_path(data) do
    <<pfp::binary-size(4), path_bin::binary>> = data
    {:ok, path} = DerivationPath.parse(path_bin)
    {pfp, path}
  end

  # reuse this elsewhere
  @spec serialize_fingerprint_path(binary, DerivationPath.t()) :: binary
  def serialize_fingerprint_path(pfp, path) do
    {:ok, path_bin} = DerivationPath.serialize(path)
    pfp <> path_bin
  end

  def parse_leaf_hashes(value, leaf_hash_ct) do
    leaf_hashes_byte_size = 32 * leaf_hash_ct
    <<leaf_hashes::binary-size(leaf_hashes_byte_size), value::binary>> = value

    leaf_hashes =
      leaf_hashes
      |> :erlang.binary_to_list()
      |> Enum.chunk_every(32)
      |> Enum.map(&:erlang.list_to_binary/1)

    {leaf_hashes, value}
  end

  @spec serialize_leaf_hashes(list(binary)) :: binary
  def serialize_leaf_hashes(leaf_hashes) do
    leaf_hashes_bin = Enum.reduce(leaf_hashes, <<>>, fn leaf_hash, acc -> acc <> leaf_hash end)
    Utils.serialize_compact_size_unsigned_int(length(leaf_hashes)) <> leaf_hashes_bin
  end

  def append(nil, item), do: [item]
  def append(items, item), do: items ++ [item]
end

defmodule Bitcoinex.PSBT.Global do
  @moduledoc """
  Global properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.Transaction
  alias Bitcoinex.Utils
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.ExtendedKey
  alias Bitcoinex.ExtendedKey.DerivationPath, as: DerivationPath

  defstruct [
    :unsigned_tx,
    :xpub,
    :tx_version,
    :fallback_locktime,
    :input_count,
    :output_count,
    :tx_modifiable,
    :version,
    :proprietary,
    :unknown
  ]

  @psbt_global_unsigned_tx 0x00
  @psbt_global_xpub 0x01
  @psbt_global_tx_version 0x02
  @psbt_global_fallback_locktime 0x03
  @psbt_global_input_count 0x04
  @psbt_global_output_count 0x05
  @psbt_global_tx_modifiable 0x06
  @psbt_global_version 0xFB
  @psbt_global_proprietary 0xFC

  def parse_global(psbt) do
    PsbtUtils.parse_key_value(psbt, %Global{}, &parse/3)
  end

  def from_tx(tx), do: %Global{unsigned_tx: tx}

  # unsigned transaction
  defp parse(<<@psbt_global_unsigned_tx::big-size(8)>>, psbt, global) do
    {txn_len, psbt} = TxUtils.get_counter(psbt)

    <<txn_bytes::binary-size(txn_len), psbt::binary>> = psbt

    case Transaction.decode(txn_bytes) do
      {:ok, txn} ->
        {%Global{global | unsigned_tx: txn}, psbt}

      {:error, error_msg} ->
        {:error, error_msg}
    end
  end

  defp parse(<<@psbt_global_xpub::big-size(8), xpub::binary-size(78)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {master, path} = PsbtUtils.parse_fingerprint_path(value)
    {:ok, xpub} = ExtendedKey.parse(xpub)

    if :binary.decode_unsigned(xpub.depth) != DerivationPath.depth(path),
      do:
        raise(ArgumentError,
          message: "invalid xpub in PSBT: depth does not match number of indexes provided"
        )

    global_xpub = %{
      xpub: xpub,
      pfp: master,
      derivation: path
    }

    global_xpubs = PsbtUtils.append(global.xpub, global_xpub)

    global = %Global{global | xpub: global_xpubs}

    {global, psbt}
  end

  defp parse(<<@psbt_global_tx_version::big-size(8)>>, psbt, global) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    global = %Global{global | tx_version: value}
    {global, psbt}
  end

  defp parse(<<@psbt_global_fallback_locktime::big-size(8)>>, psbt, global) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    global = %Global{global | fallback_locktime: value}
    {global, psbt}
  end

  defp parse(<<@psbt_global_input_count::big-size(8)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {input_count, _} = TxUtils.get_counter(value)
    global = %Global{global | input_count: input_count}
    {global, psbt}
  end

  defp parse(<<@psbt_global_output_count::big-size(8)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {output_count, _} = TxUtils.get_counter(value)
    global = %Global{global | output_count: output_count}
    {global, psbt}
  end

  defp parse(<<@psbt_global_tx_modifiable::big-size(8)>>, psbt, global) do
    {<<value>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    global = %Global{global | tx_modifiable: value}
    {global, psbt}
  end

  defp parse(<<@psbt_global_version::big-size(8)>>, psbt, global) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    global = %Global{global | version: value}
    {global, psbt}
  end

  defp parse(<<@psbt_global_proprietary::big-size(8)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    global = %Global{global | proprietary: value}
    {global, psbt}
  end

  defp serialize_kv(:unsigned_tx, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_unsigned_tx::big-size(8)>>, TxUtils.serialize(value))
  end

  defp serialize_kv(:xpub, value) when value != nil do
    key = <<@psbt_global_xpub::big-size(8)>>
    key_data = ExtendedKey.serialize(value.xpub, with_checksum?: false)

    val = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(key <> key_data, val)
  end

  defp serialize_kv(:tx_version, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_tx_version::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:fallback_locktime, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_global_fallback_locktime::big-size(8)>>,
      <<value::little-size(32)>>
    )
  end

  defp serialize_kv(:input_count, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_global_input_count::big-size(8)>>,
      Utils.serialize_compact_size_unsigned_int(value)
    )
  end

  defp serialize_kv(:output_count, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_global_output_count::big-size(8)>>,
      Utils.serialize_compact_size_unsigned_int(value)
    )
  end

  defp serialize_kv(:tx_modifiable, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_tx_modifiable::big-size(8)>>, <<value>>)
  end

  defp serialize_kv(:version, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_global_version::big-size(8)>>,
      <<value::little-size(32)>>
    )
  end

  defp serialize_kv(:proprietary, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_proprietary::big-size(8)>>, value)
  end

  def serialize_global(global) do
    serialized_global =
      Enum.reduce(
        [
          :unsigned_tx,
          :xpub,
          :tx_version,
          :fallback_locktime,
          :input_count,
          :output_count,
          :tx_modifiable,
          :version,
          :proprietary,
          :unknown
        ],
        <<>>,
        fn k, acc ->
          case Map.get(global, k) do
            nil ->
              acc

            [] ->
              acc

            v = [_ | _] ->
              acc <> PsbtUtils.serialize_repeatable_fields(k, v, &serialize_kv/2)

            v ->
              acc <> serialize_kv(k, v)
          end
        end
      )

    serialized_global <> <<0x00::big-size(8)>>
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
  alias Bitcoinex.Utils
  alias Bitcoinex.Script

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
    :previous_txid,
    :output_index,
    :sequence,
    :required_time_locktime,
    :required_height_locktime,
    :tap_key_sig,
    :tap_script_sig,
    :tap_leaf_script,
    :tap_bip32_derivation,
    :tap_internal_key,
    :tap_merkle_root,
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
  @psbt_in_previous_txid 0x0E
  @psbt_in_output_index 0x0F
  @psbt_in_sequence 0x10
  @psbt_in_required_time_locktime 0x11
  @psbt_in_required_height_locktime 0x12
  @psbt_in_tap_key_sig 0x13
  @psbt_in_tap_script_sig 0x14
  @psbt_in_tap_leaf_script 0x15
  @psbt_in_tap_bip32_derivation 0x16
  @psbt_in_tap_internal_key 0x17
  @psbt_in_tap_merkle_root 0x18
  @psbt_in_proprietary 0xFC

  def parse_inputs(psbt, num_inputs) do
    psbt
    |> parse_input([], num_inputs)
  end

  @spec from_tx_inputs(list(Transaction.In.t()), list(Transaction.Witness.t())) :: list()
  def from_tx_inputs(tx_inputs, tx_witnesses) do
    inputs_witnesses = Enum.zip(tx_inputs, tx_witnesses)

    Enum.reduce(inputs_witnesses, [], fn {input, witness}, acc ->
      [
        %In{
          final_scriptsig: input.script_sig,
          final_scriptwitness: witness
        }
        | acc
      ]
    end)
    |> Enum.reverse()
  end

  def populate_script_sigs(tx_inputs, psbt_inputs) do
    inputs = Enum.zip(tx_inputs, psbt_inputs)

    Enum.reduce(inputs, [], fn {tx_in, psbt_in}, acc ->
      [%Transaction.In{tx_in | script_sig: psbt_in.final_scriptsig} | acc]
    end)
    |> Enum.reverse()
  end

  @spec populate_witnesses(list(In)) :: list(binary)
  def populate_witnesses(psbt_inputs) do
    Enum.reduce(psbt_inputs, [], fn psbt_in, acc ->
      [psbt_in.final_scriptwitness | acc]
    end)
    |> Enum.reverse()
  end

  defp serialize_kv(:non_witness_utxo, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_non_witness_utxo::big-size(8)>>, TxUtils.serialize(value))
  end

  defp serialize_kv(:witness_utxo, value) when value != nil do
    script = Base.decode16!(value.script_pub_key, case: :lower)

    val =
      <<value.value::little-size(64)>> <>
        Utils.serialize_compact_size_unsigned_int(byte_size(script)) <> script

    PsbtUtils.serialize_kv(<<@psbt_in_witness_utxo::big-size(8)>>, val)
  end

  defp serialize_kv(:partial_sig, value) when value != nil do
    key_data = Base.decode16!(value.public_key, case: :lower)
    val = Base.decode16!(value.signature, case: :lower)

    PsbtUtils.serialize_kv(<<@psbt_in_partial_sig::big-size(8)>> <> key_data, val)
  end

  defp serialize_kv(:sighash_type, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_sighash_type::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:final_scriptsig, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_final_scriptsig::big-size(8)>>,
      Base.decode16!(value, case: :lower)
    )
  end

  defp serialize_kv(:redeem_script, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_redeem_script::big-size(8)>>,
      Base.decode16!(value, case: :lower)
    )
  end

  defp serialize_kv(:witness_script, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_witness_script::big-size(8)>>,
      Base.decode16!(value, case: :lower)
    )
  end

  defp serialize_kv(:final_scriptwitness, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_final_scriptwitness::big-size(8)>>,
      Witness.serialize_witness([value])
    )
  end

  defp serialize_kv(:bip32_derivation, value) when value != nil do
    key_data = Base.decode16!(value.public_key, case: :lower)

    val = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(<<@psbt_in_bip32_derivation::big-size(8)>> <> key_data, val)
  end

  defp serialize_kv(:por_commitment, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_por_commitment::big-size(8)>>, value)
  end

  defp serialize_kv(:in_ripemd160, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_ripemd160::big-size(8), value.hash::binary-size(20)>>,
      value.preimage
    )
  end

  defp serialize_kv(:in_sha256, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_sha256::big-size(8), value.hash::binary-size(32)>>,
      value.preimage
    )
  end

  defp serialize_kv(:in_hash160, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_hash160::big-size(8), value.hash::binary-size(20)>>,
      value.preimage
    )
  end

  defp serialize_kv(:in_hash256, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_hash256::big-size(8), value.hash::binary-size(32)>>,
      value.preimage
    )
  end

  defp serialize_kv(:previous_txid, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_previous_txid::big-size(8)>>, value)
  end

  defp serialize_kv(:output_index, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_output_index::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:sequence, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_sequence::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:required_time_locktime, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_required_time_locktime::big-size(8)>>,
      <<value::little-size(32)>>
    )
  end

  defp serialize_kv(:required_height_locktime, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_required_height_locktime::big-size(8)>>,
      <<value::little-size(32)>>
    )
  end

  defp serialize_kv(:tap_key_sig, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_tap_key_sig::big-size(8)>>, value)
  end

  defp serialize_kv(:tap_script_sig, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_in_tap_script_sig::big-size(8), value.pubkey::binary, value.leaf_hash::binary>>,
      value.signature
    )
  end

  defp serialize_kv(:tap_leaf_script, value) when value != nil do
    # TODO:taproot make this use TapLeaf
    script_bytes = Script.serialize_script(value.script)

    PsbtUtils.serialize_kv(
      <<@psbt_in_tap_leaf_script::big-size(8), value.control_block::binary>>,
      script_bytes <> <<value.leaf_version::little-size(8)>>
    )
  end

  defp serialize_kv(:tap_bip32_derivation, value) when value != nil do
    leaf_hashes = PsbtUtils.serialize_leaf_hashes(value.leaf_hashes)
    fingerprint_path = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(
      <<@psbt_in_tap_bip32_derivation::big-size(8), value.pubkey::binary>>,
      leaf_hashes <> fingerprint_path
    )
  end

  defp serialize_kv(:tap_internal_key, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_tap_internal_key::big-size(8)>>, value)
  end

  defp serialize_kv(:tap_merkle_root, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_tap_merkle_root::big-size(8)>>, value)
  end

  defp serialize_kv(:proprietary, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_proprietary::big-size(8)>>, value)
  end

  defp serialize_kv(:unknown, %{key: k, value: v}) do
    PsbtUtils.serialize_kv(k, v)
  end

  defp serialize_kv(_key, _value) do
    <<>>
  end

  def serialize_inputs(inputs) when is_list(inputs) and length(inputs) > 0 do
    serialize_input(inputs, <<>>)
  end

  def serialize_inputs(_inputs) do
    <<>>
  end

  defp serialize_input([], serialized_inputs), do: serialized_inputs

  defp serialize_input(inputs, serialized_inputs) do
    [input | inputs] = inputs

    serialized_input =
      Enum.reduce(
        [
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
          :previous_txid,
          :output_index,
          :sequence,
          :required_time_locktime,
          :required_height_locktime,
          :tap_key_sig,
          :tap_script_sig,
          :tap_leaf_script,
          :tap_bip32_derivation,
          :tap_internal_key,
          :tap_merkle_root,
          :proprietary,
          :unknown
        ],
        <<>>,
        fn k, acc ->
          case Map.get(input, k) do
            nil ->
              acc

            [] ->
              acc

            v = [_ | _] ->
              acc <> PsbtUtils.serialize_repeatable_fields(k, v, &serialize_kv/2)

            v ->
              acc <> serialize_kv(k, v)
          end
        end
      )

    serialized_input = serialized_input <> <<0x00::big-size(8)>>

    serialize_input(inputs, serialized_inputs <> serialized_input)
  end

  defp parse_input(psbt, inputs, 0), do: {Enum.reverse(inputs), psbt}

  defp parse_input(psbt, inputs, num_inputs) do
    case PsbtUtils.parse_key_value(psbt, %In{}, &parse/3) do
      # why are we not adding an empty in here?
      {nil, psbt} ->
        parse_input(psbt, inputs, num_inputs - 1)

      {input, psbt} ->
        parse_input(psbt, [input | inputs], num_inputs - 1)
    end
  end

  defp parse(<<@psbt_in_non_witness_utxo::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {:ok, txn} = Transaction.decode(value)
    input = %In{input | non_witness_utxo: txn}
    {input, psbt}
  end

  defp parse(<<@psbt_in_witness_utxo::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    out = Out.output(value)
    input = %In{input | witness_utxo: out}
    {input, psbt}
  end

  defp parse(<<@psbt_in_partial_sig::big-size(8), public_key::binary-size(33)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    partial_sig = %{
      public_key: Base.encode16(public_key, case: :lower),
      signature: Base.encode16(value, case: :lower)
    }

    partial_sigs = PsbtUtils.append(input.partial_sig, partial_sig)
    input = %In{input | partial_sig: partial_sigs}

    {input, psbt}
  end

  defp parse(<<@psbt_in_sighash_type::big-size(8)>>, psbt, input) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | sighash_type: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_redeem_script::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | redeem_script: Base.encode16(value, case: :lower)}
    {input, psbt}
  end

  defp parse(<<@psbt_in_witness_script::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | witness_script: Base.encode16(value, case: :lower)}
    {input, psbt}
  end

  defp parse(<<@psbt_in_bip32_derivation::big-size(8), public_key::binary-size(33)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {pfp, path} = PsbtUtils.parse_fingerprint_path(value)

    derivation = %{
      public_key: Base.encode16(public_key, case: :lower),
      pfp: pfp,
      derivation: path
    }

    bip32_derivation = PsbtUtils.append(input.bip32_derivation, derivation)

    input = %In{input | bip32_derivation: bip32_derivation}
    {input, psbt}
  end

  defp parse(<<@psbt_in_final_scriptsig::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | final_scriptsig: Base.encode16(value, case: :lower)}
    {input, psbt}
  end

  defp parse(<<@psbt_in_por_commitment::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | por_commitment: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_ripemd160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    data = %{
      hash: hash,
      preimage: preimage
    }

    ripemd160s = PsbtUtils.append(input.ripemd160, data)

    input = %In{input | ripemd160: ripemd160s}
    {input, psbt}
  end

  defp parse(<<@psbt_in_sha256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    data = %{
      hash: hash,
      preimage: preimage
    }

    sha256s = PsbtUtils.append(input.sha256, data)
    input = %In{input | sha256: sha256s}
    {input, psbt}
  end

  defp parse(<<@psbt_in_hash160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    data = %{
      hash: hash,
      preimage: preimage
    }

    hash160s = PsbtUtils.append(input.hash160, data)
    input = %In{input | hash160: hash160s}
    {input, psbt}
  end

  defp parse(<<@psbt_in_hash256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    data = %{
      hash: hash,
      preimage: preimage
    }

    hash256s = PsbtUtils.append(input.hash256, data)
    input = %In{input | hash256: hash256s}
    {input, psbt}
  end

  defp parse(<<@psbt_in_previous_txid::big-size(8)>>, psbt, input) do
    {value = <<_::binary-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | previous_txid: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_output_index::big-size(8)>>, psbt, input) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | output_index: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_sequence::big-size(8)>>, psbt, input) do
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | sequence: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_required_time_locktime::big-size(8)>>, psbt, input) do
    # TODO:validation must be > 500_000_000
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | required_time_locktime: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_required_height_locktime::big-size(8)>>, psbt, input) do
    # TODO:validation must be < 500_000_000
    {<<value::little-size(32)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | required_height_locktime: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_key_sig::big-size(8)>>, psbt, input) do
    # TODO:validation validate script len (64|65)
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | tap_key_sig: value}
    {input, psbt}
  end

  defp parse(
         <<@psbt_in_tap_script_sig::big-size(8), pubkey::binary-size(32),
           leaf_hash::binary-size(32)>>,
         psbt,
         input
       ) do
    # TODO:validation validate sig len (64|65)
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    data = %{
      pubkey: pubkey,
      leaf_hash: leaf_hash,
      signature: value
    }

    tap_script_sigs = PsbtUtils.append(input.tap_script_sig, data)

    input = %In{input | tap_script_sig: tap_script_sigs}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_leaf_script::big-size(8), control_block::binary>>, psbt, input) do
    {tapleaf, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {leaf_version, script_bytes} =
      tapleaf
      |> :erlang.binary_to_list()
      |> List.pop_at(-1)

    script_bytes = :erlang.list_to_binary(script_bytes)

    {:ok, script} = Script.parse_script(script_bytes)

    data = %{
      # TODO:taproot make this a TapLeaf object
      leaf_version: leaf_version,
      script: script,
      control_block: control_block
    }

    tap_leaf_scripts = PsbtUtils.append(input.tap_leaf_script, data)
    input = %In{input | tap_leaf_script: tap_leaf_scripts}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_bip32_derivation::big-size(8), pubkey::binary-size(32)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {leaf_hash_ct, value} = TxUtils.get_counter(value)
    {leaf_hashes, value} = PsbtUtils.parse_leaf_hashes(value, leaf_hash_ct)
    {pfp, path} = PsbtUtils.parse_fingerprint_path(value)

    derivation = %{
      pubkey: pubkey,
      leaf_hashes: leaf_hashes,
      pfp: pfp,
      derivation: path
    }

    tap_bip32_derivation = PsbtUtils.append(input.tap_bip32_derivation, derivation)

    input = %In{input | tap_bip32_derivation: tap_bip32_derivation}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_internal_key::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | tap_internal_key: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_merkle_root::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | tap_merkle_root: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_proprietary::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    input = %In{input | proprietary: value}
    {input, psbt}
  end

  defp parse(<<@psbt_in_final_scriptwitness::big-size(8)>>, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    value = Witness.witness(value)
    input = %In{input | final_scriptwitness: value}
    {input, psbt}
  end

  defp parse(key, psbt, input) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    kv = %{key: key, value: value}

    unknown =
      case input.unknown do
        nil ->
          [kv]

        _ ->
          input.unknown ++ [kv]
      end

    input = %In{input | unknown: unknown}
    {input, psbt}
  end
end

defmodule Bitcoinex.PSBT.Out do
  @moduledoc """
  Output properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.Utils
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Script

  defstruct [
    :redeem_script,
    :witness_script,
    :bip32_derivation,
    :amount,
    :script,
    :tap_internal_key,
    :tap_tree,
    :tap_bip32_derivation,
    :proprietary
  ]

  @psbt_out_redeem_script 0x00
  @psbt_out_scriptwitness 0x01
  @psbt_out_bip32_derivation 0x02
  @psbt_out_amount 0x03
  @psbt_out_script 0x04
  @psbt_out_tap_internal_key 0x05
  @psbt_out_tap_tree 0x06
  @psbt_out_tap_bip32_derivation 0x07
  @psbt_out_proprietary 0xFC

  def serialize_outputs(outputs) when is_list(outputs) and length(outputs) > 0 do
    serialize_output(outputs, <<>>)
  end

  def serialize_outputs(_outputs) do
    <<>>
  end

  def from_tx_outputs(tx_outputs) do
    Enum.reduce(tx_outputs, [], fn _, acc -> [%Out{} | acc] end)
    |> Enum.reverse()
  end

  defp serialize_kv(:redeem_script, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_out_redeem_script::big-size(8)>>,
      Base.decode16!(value, case: :lower)
    )
  end

  defp serialize_kv(:witness_script, value) when value != nil do
    PsbtUtils.serialize_kv(
      <<@psbt_out_scriptwitness::big-size(8)>>,
      Base.decode16!(value, case: :lower)
    )
  end

  defp serialize_kv(:bip32_derivation, value) when value != nil do
    key_data = Base.decode16!(value.public_key, case: :lower)
    val = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(<<@psbt_out_bip32_derivation::big-size(8)>> <> key_data, val)
  end

  defp serialize_kv(:amount, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_out_amount::big-size(8)>>, <<value::little-size(64)>>)
  end

  defp serialize_kv(:script, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_out_script::big-size(8)>>, Script.serialize_script(value))
  end

  defp serialize_kv(:tap_internal_key, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_out_tap_internal_key::big-size(8)>>, value)
  end

  defp serialize_kv(:tap_tree, value) when value != nil do
    tree = serialize_tap_tree(value.leaves)
    PsbtUtils.serialize_kv(<<@psbt_out_tap_tree::big-size(8)>>, tree)
  end

  defp serialize_kv(:tap_bip32_derivation, value) when value != nil do
    key = <<@psbt_out_tap_bip32_derivation::big-size(8), value.pubkey::binary>>
    leaf_hashes = PsbtUtils.serialize_leaf_hashes(value.leaf_hashes)
    fingerprint_path = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(key, leaf_hashes <> fingerprint_path)
  end

  defp serialize_kv(:proprietary, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_out_proprietary::big-size(8)>>, value)
  end

  defp serialize_kv(_key, _value) do
    <<>>
  end

  defp serialize_output([], serialized_outputs), do: serialized_outputs

  defp serialize_output(outputs, serialized_outputs) do
    [output | outputs] = outputs

    serialized_output =
      Enum.reduce(
        [
          :redeem_script,
          :witness_script,
          :bip32_derivation,
          :amount,
          :script,
          :tap_internal_key,
          :tap_tree,
          :tap_bip32_derivation,
          :proprietary,
          :unknown
        ],
        <<>>,
        fn k, acc ->
          case Map.get(output, k) do
            nil ->
              acc

            [] ->
              acc

            v = [_ | _] ->
              acc <> PsbtUtils.serialize_repeatable_fields(k, v, &serialize_kv/2)

            v ->
              acc <> serialize_kv(k, v)
          end
        end
      )

    serialized_output = serialized_output <> <<0x00::big-size(8)>>

    serialize_output(outputs, serialized_outputs <> serialized_output)
  end

  def parse_outputs(psbt, num_outputs) do
    parse_output(psbt, [], num_outputs)
  end

  defp parse_output(psbt, outputs, 0), do: {Enum.reverse(outputs), psbt}

  defp parse_output(psbt, outputs, num_outputs) do
    {output, psbt} = PsbtUtils.parse_key_value(psbt, %Out{}, &parse/3)
    parse_output(psbt, [output | outputs], num_outputs - 1)
  end

  defp parse(<<@psbt_out_redeem_script::big-size(8)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    output = %Out{output | redeem_script: Base.encode16(value, case: :lower)}
    {output, psbt}
  end

  defp parse(<<@psbt_out_scriptwitness::big-size(8)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    output = %Out{output | witness_script: Base.encode16(value, case: :lower)}
    {output, psbt}
  end

  defp parse(
         <<@psbt_out_bip32_derivation::big-size(8), public_key::binary-size(33)>>,
         psbt,
         output
       ) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {pfp, path} = PsbtUtils.parse_fingerprint_path(value)

    derivation = %{
      public_key: Base.encode16(public_key, case: :lower),
      pfp: pfp,
      derivation: path
    }

    bip32_derivation = PsbtUtils.append(output.bip32_derivation, derivation)
    output = %Out{output | bip32_derivation: bip32_derivation}
    {output, psbt}
  end

  defp parse(<<@psbt_out_amount::big-size(8)>>, psbt, output) do
    {<<amount::little-size(64)>>, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    output = %Out{output | amount: amount}
    {output, psbt}
  end

  defp parse(<<@psbt_out_script::big-size(8)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {:ok, script} = Script.parse_script(value)
    output = %Out{output | script: script}
    {output, psbt}
  end

  defp parse(<<@psbt_out_tap_internal_key::big-size(8)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    output = %Out{output | tap_internal_key: value}
    {output, psbt}
  end

  defp parse(<<@psbt_out_tap_tree::big-size(8)>>, psbt, output) do
    {tree, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    leaves = parse_tap_tree(tree, [])
    # hack to ensure tap_tree is not treated like a repeatable field
    output = %Out{output | tap_tree: %{leaves: leaves}}
    {output, psbt}
  end

  defp parse(
         <<@psbt_out_tap_bip32_derivation::big-size(8), pubkey::binary-size(32)>>,
         psbt,
         output
       ) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {leaf_hash_ct, value} = TxUtils.get_counter(value)
    {leaf_hashes, value} = PsbtUtils.parse_leaf_hashes(value, leaf_hash_ct)
    {pfp, path} = PsbtUtils.parse_fingerprint_path(value)

    derivation = %{
      pubkey: pubkey,
      leaf_hashes: leaf_hashes,
      pfp: pfp,
      derivation: path
    }

    tap_bip32_derivation = PsbtUtils.append(output.tap_bip32_derivation, derivation)
    output = %Out{output | tap_bip32_derivation: tap_bip32_derivation}
    {output, psbt}
  end

  defp parse(<<@psbt_out_proprietary::big-size(8)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    output = %Out{output | proprietary: value}
    {output, psbt}
  end

  defp parse_tap_tree(<<>>, scripts), do: Enum.reverse(scripts)

  defp parse_tap_tree(tree, scripts) do
    <<depth::size(8), leaf_version::size(8), rest::binary>> = tree
    {script, tree} = PsbtUtils.parse_compact_size_value(rest)
    {:ok, script} = Script.parse_script(script)

    data = %{
      # TODO:taproot make this TapLeaf
      depth: depth,
      leaf_version: leaf_version,
      script: script
    }

    # TODO:taproot ideally we can build an actual binary tree not just a list.
    # But this is only useful once taproot is merged in
    parse_tap_tree(tree, [data | scripts])
  end

  defp serialize_tap_tree(leaves) do
    Enum.reduce(leaves, <<>>, fn leaf, acc ->
      # TODO:taproot use Script.serialize_with_compact_size
      script_bytes = Script.serialize_script(leaf.script)

      acc <>
        <<leaf.depth, leaf.leaf_version>> <>
        Utils.serialize_compact_size_unsigned_int(byte_size(script_bytes)) <>
        script_bytes
    end)
  end
end
