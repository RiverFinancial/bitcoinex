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
  alias Bitcoinex.Transaction.Utils, as: TxUtils

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

  defp parse(<<@magic::big-size(32), @separator::big-size(8), psbt::binary>>) do
    # key-value pairs for all global data
    {global, psbt} = Global.parse_global(psbt)
    in_counter = length(global.unsigned_tx.inputs)
    {inputs, psbt} = In.parse_inputs(psbt, in_counter)
    out_counter = length(global.unsigned_tx.outputs)
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

    %Bitcoinex.Transaction{ tx | witnesses: witnesses, inputs: inputs}
  end
end

defmodule Bitcoinex.PSBT.Utils do
  @moduledoc """
  Contains utility functions used throughout PSBT serialization.
  """
  alias Bitcoinex.Transaction.Utils, as: TxUtils
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
    key_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(key))
    val_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(val))
    key_len <> key <> val_len <> val
  end

  def parse_fingerprint_path(data) do
    <<pfp::binary-size(4), paths>> = data
    {:ok, indexes} = DerivationPath.parse(paths)
    {pfp, indexes}
  end

  # reuse this elsewhere
  def serialize_fingerprint_path(pfp, path) do
    {:ok, path} = DerivationPath.serialize(path)
    <<pfp, path>>
  end

  def parse_leaf_hashes(value, leaf_hash_ct) do
    <<leaf_hashes::binary-size(32*leaf_hash_ct), value>> = value
    leaf_hashes = Enum.chunk_every(leaf_hashes, 32)
    {leaf_hashes, value}
  end

  def serialize_leaf_hashes(leaf_hashes) do
    leaf_hashes = Enum.reduce(leaf_hashes, <<>>, fn leaf_hash, acc -> acc <> leaf_hash end)
    TxUtils.serialize_compact_size_unsigned_int(length(leaf_hashes)) <> leaf_hashes
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
    :proprietary
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

    {master, indexes} = PsbtUtils.parse_fingerprint_path(value)
    {:ok, xpub} = ExtendedKey.parse(xpub)

    if :binary.decode_unsigned(xpub.depth) != DerivationPath.depth(indexes),
      do:
        raise(ArgumentError,
          message: "invalid xpub in PSBT: depth does not match number of indexes provided"
        )

    global_xpub =
      case global.xpub do
        nil ->
          [
            %{
              xpub: xpub,
              pfp: master,
              derivation: indexes
            }
          ]

        _ ->
          global.xpub ++
            [
              %{
                xpub: xpub,
                pfp: master,
                derivation: indexes
              }
            ]
      end

    global = %Global{global | xpub: global_xpub}

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
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
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
    key_data = ExtendedKey.serialize(value.xpub, :no_checksum)

    val = PsbtUtils.serialize_fingerprint_path(value.pfp, value.derivation)

    PsbtUtils.serialize_kv(key <> key_data, val)
  end

  defp serialize_kv(:tx_version, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_tx_version::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:fallback_locktime, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_fallback_locktime::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:input_count, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_input_count::big-size(8)>>, TxUtils.serialize_compact_size_unsigned_int(value))
  end

  defp serialize_kv(:output_count, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_output_count::big-size(8)>>, TxUtils.serialize_compact_size_unsigned_int(value))
  end

  defp serialize_kv(:tx_modifiable, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_tx_modifiable::big-size(8)>>, <<value>>)
  end

  defp serialize_kv(:proprietary, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_global_proprietary::big-size(8)>>, value)
  end


  def serialize_global(global) do
    # TODO: serialize all other fields in global.
    serialized_global = serialize_kv(:unsigned_tx, global.unsigned_tx)

    bip32 =
      if global.xpub != nil do
        for(bip32 <- global.xpub, do: serialize_kv(:xpub, bip32))
        |> :erlang.list_to_binary()
      else
        <<>>
      end

    serialized_global <> bip32 <> <<0x00::big-size(8)>>
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
  alias Bitcoinex.ExtendedKey.DerivationPath, as: DerivationPath
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
    :proprietary
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
  @psbt_in_ripemd160 0x0a
  @psbt_in_sha256 0x0b
  @psbt_in_hash160 0x0c
  @psbt_in_hash256 0x0d
  @psbt_in_previous_txid 0x0e
  @psbt_in_output_index 0x0f
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

  @spec from_tx_inputs(list(Transaction.In.t()), list(Transaction.Witness.t())) :: list(%In{})
  def from_tx_inputs(tx_inputs, tx_witnesses) do
    inputs_witnesses = Enum.zip(tx_inputs, tx_witnesses)
    Enum.reduce(inputs_witnesses, [], fn {input, witness}, acc ->
      [%In{
          final_scriptsig: input.script_sig,
          final_scriptwitness: witness
        } | acc]
    end)
    |> Enum.reverse()
  end

  def populate_script_sigs(tx_inputs, psbt_inputs) do
    inputs = Enum.zip(tx_inputs, psbt_inputs)
    Enum.reduce(inputs, [],
      fn {tx_in, psbt_in}, acc ->
        [%Transaction.In{ tx_in | script_sig: psbt_in.final_scriptsig} | acc]
    end)
    |> Enum.reverse()
  end

  def populate_witnesses(psbt_inputs) do
    Enum.reduce(psbt_inputs, [],
        fn psbt_in, acc ->
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
        TxUtils.serialize_compact_size_unsigned_int(byte_size(script)) <> script

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
    PsbtUtils.serialize_kv(<<@psbt_in_ripemd160::big-size(8), value.hash::binary-size(20)>>, value.preimage)
  end

  defp serialize_kv(:in_sha256, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_sha256::big-size(8), value.hash::binary-size(32)>>, value.preimage)
  end

  defp serialize_kv(:in_hash160, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_hash160::big-size(8), value.hash::binary-size(20)>>, value.preimage)
  end

  defp serialize_kv(:in_hash256, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_hash256::big-size(8), value.hash::binary-size(32)>>, value.preimage)
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
    PsbtUtils.serialize_kv(<<@psbt_in_required_time_locktime::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:required_height_locktime, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_required_height_locktime::big-size(8)>>, <<value::little-size(32)>>)
  end

  defp serialize_kv(:tap_key_sig, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_tap_key_sig::big-size(8)>>, value)
  end

  defp serialize_kv(:tap_script_sig, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_in_tap_script_sig::big-size(8), value.pubkey, value.leaf_hash>>, value.signature)
  end

  defp serialize_kv(:tap_leaf_script, value) when value != nil do
    # TODO:taproot make this use TapLeaf
    script_bytes = Script.serialize_script(value.script)
    PsbtUtils.serialize_kv(<<@psbt_in_tap_leaf_script::big-size(8), value.control_block>>, script_bytes <> <<value.leaf_version::little-size(8)>> )
  end

  defp serialize_kv(:tap_bip32_derivation, value) when value != nil do
    leaf_hashes = PsbtUtils.serialize_leaf_hashes(value.leaf_hashes)
    fingerprint_path = PsbtUtils.serialize_fingerprint_path(value.pfp, value.path)

    PsbtUtils.serialize_kv(<<@psbt_in_tap_bip32_derivation::big-size(8), value.pubkey>>, leaf_hashes <> fingerprint_path)
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
          :sighash_type,
          :partial_sig,
          :redeem_script,
          :final_scriptsig,
          :witness_script
        ],
        <<>>,
        fn k, acc ->
          case Map.get(input, k) do
            nil ->
              acc

            v ->
              acc <> serialize_kv(k, v)
          end
        end
      )

    bip32 =
      if input.bip32_derivation != nil do
        for(bip32 <- input.bip32_derivation, do: serialize_kv(:bip32_derivation, bip32))
        |> :erlang.list_to_binary()
      else
        <<>>
      end

    serialized_input =
      serialized_input <>
        bip32 <>
        serialize_kv(:final_scriptwitness, input.final_scriptwitness) <> <<0x00::big-size(8)>>

    serialize_input(inputs, serialized_inputs <> serialized_input)
  end

  defp parse_input(psbt, inputs, 0), do: {Enum.reverse(inputs), psbt}

  defp parse_input(psbt, inputs, num_inputs) do
    case PsbtUtils.parse_key_value(psbt, %In{}, &parse/3) do
      {nil, psbt} ->
        parse_input(psbt, inputs, num_inputs - 1)

      {input, psbt} ->
        input =
          case input do
            %{bip32_derivation: bip32_derivation} when is_list(bip32_derivation) ->
              %{input | bip32_derivation: Enum.reverse(bip32_derivation)}

            _ ->
              input
          end

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

    input = %In{
      input
      | partial_sig: %{
          public_key: Base.encode16(public_key, case: :lower),
          signature: Base.encode16(value, case: :lower)
        }
    }

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

    <<pfp::little-unsigned-32, paths::binary>> = value
    {:ok, indexes} = DerivationPath.parse(paths)

    bip32_derivation =
      case input.bip32_derivation do
        nil ->
          [
            %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: pfp,
              derivation: indexes
            }
          ]

        _ ->
          [
            %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: pfp,
              derivation: indexes
            }
            | input.bip32_derivation
          ]
      end

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
    input = %In{input | ripemd160: data}
    {input, psbt}
  end

  defp parse(<<@psbt_in_sha256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    data = %{
      hash: hash,
      preimage: preimage
    }
    input = %In{input | sha256: data}
    {input, psbt}
  end

  defp parse(<<@psbt_in_hash160::big-size(8), hash::binary-size(20)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    data = %{
      hash: hash,
      preimage: preimage
    }
    input = %In{input | hash160: data}
    {input, psbt}
  end

  defp parse(<<@psbt_in_hash256::big-size(8), hash::binary-size(32)>>, psbt, input) do
    # TODO:validation check hash
    {preimage, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    data = %{
      hash: hash,
      preimage: preimage
    }
    input = %In{input | hash256: data}
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

  defp parse(<<@psbt_in_tap_script_sig::big-size(8), pubkey::binary-size(32), leaf_hash::binary-size(32)>>, psbt, input) do
    # TODO:validation validate script len (64|65)
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    data = %{
      pubkey: pubkey,
      leaf_hash: leaf_hash,
      signature: value
    }
    input = %In{input | tap_script_sig: data}
    {input, psbt}
  end

  defp parse(<<@psbt_in_tap_leaf_script::big-size(8), control_block>>, psbt, input) do
    {tapleaf, psbt} = PsbtUtils.parse_compact_size_value(psbt)
    {script_bytes, <<leaf_version::little-size(8)>>} = PsbtUtils.parse_compact_size_value(tapleaf)
    {:ok, script} = Script.parse_script(script_bytes)
    data = %{
      # TODO:taproot make this a TapLeaf object
      leaf_version: leaf_version,
      script: script,
      control_block: control_block,
    }
    input = %In{input | tap_leaf_script: data}
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

    tap_bip32_derivation =
      case input.tap_bip32_derivation do
        nil ->
          [derivation]

        _ ->
          [derivation | input.tap_bip32_derivation]
      end

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
end

defmodule Bitcoinex.PSBT.Out do
  @moduledoc """
  Output properties of a partially signed bitcoin transaction.
  """
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.PSBT.Utils, as: PsbtUtils
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.ExtendedKey.DerivationPath, as: DerivationPath
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
    :proprietary,
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
    tree = serialize_tap_tree(value)
    PsbtUtils.serialize_kv(<<@psbt_out_tap_tree::big-size(8)>>, tree)
  end

  defp serialize_kv(:tap_bip32_derivation, value) when value != nil do
    key = <<@psbt_out_tap_bip32_derivation::big-size(8), value.pubkey>>
    leaf_hashes = PsbtUtils.serialize_leaf_hashes(value.leaf_hashes)
    fingerprint_path = PsbtUtils.serialize_fingerprint_path(value.pfp, value.path)

    PsbtUtils.serialize_kv(key, leaf_hashes <> fingerprint_path)
  end

  defp serialize_kv(:proprietary, value) when value != nil do
    PsbtUtils.serialize_kv(<<@psbt_out_proprietary::big-size(8)>>, value)
  end

  defp serialize_kv(_key, _value) do
    <<>>
  end

  defp serialize_output([], serialize_outputs), do: serialize_outputs

  defp serialize_output(outputs, serialized_outputs) do
    [output | outputs] = outputs

    serialized_output =
      case output do
        %Out{bip32_derivation: nil, proprietary: nil, redeem_script: nil, witness_script: nil} ->
          <<0x00::big-size(8)>>

        _ ->
          serialized_output =
            serialize_kv(:redeem_script, output.redeem_script) <>
              serialize_kv(:witness_script, output.witness_script)

          bip32 =
            if output.bip32_derivation != nil do
              for(bip32 <- output.bip32_derivation, do: serialize_kv(:bip32_derivation, bip32))
              |> :erlang.list_to_binary()
            else
              <<>>
            end

          serialized_output <> bip32 <> <<0x00::big-size(8)>>
      end

    serialize_output(outputs, serialized_outputs <> serialized_output)
  end

  def parse_outputs(psbt, num_outputs) do
    parse_output(psbt, [], num_outputs)
  end

  defp parse_output(psbt, outputs, 0), do: {Enum.reverse(outputs), psbt}

  defp parse_output(psbt, outputs, num_outputs) do
    case PsbtUtils.parse_key_value(psbt, %Out{}, &parse/3) do
      {output = %Out{
         bip32_derivation: nil,
         proprietary: nil,
         redeem_script: nil,
         witness_script: nil
       }, psbt} ->
        parse_output(psbt, [output | outputs], num_outputs - 1)

      {output, psbt} ->
        output =
          case output do
            %{bip32_derivation: bip32_derivation} when is_list(bip32_derivation) ->
              %{output | bip32_derivation: Enum.reverse(bip32_derivation)}

            _ ->
              output
          end

        parse_output(psbt, [output | outputs], num_outputs - 1)
    end
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

    {pfp, indexes} = PsbtUtils.parse_fingerprint_path(value)

    bip32_derivation =
      case output.bip32_derivation do
        nil ->
          [
            %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: pfp,
              derivation: indexes
            }
          ]

        _ ->
          [
            %{
              public_key: Base.encode16(public_key, case: :lower),
              pfp: pfp,
              derivation: indexes
            }
            | output.bip32_derivation
          ]
      end

    output = %Out{
      output
      | bip32_derivation: bip32_derivation
    }

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
    output = %Out{output | tap_tree: leaves}
    {output, psbt}
  end

  defp parse(<<@psbt_out_tap_bip32_derivation::big-size(8), pubkey::binary-size(32)>>, psbt, output) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    {leaf_hash_ct, value} = TxUtils.get_counter(value)
    leaf_hashes = PsbtUtils.parse_leaf_hashes(value, leaf_hash_ct)
    {pfp, path} = PsbtUtils.parse_fingerprint_path(value)

    derivation = %{
      pubkey: pubkey,
      leaf_hashes: leaf_hashes,
      pfp: pfp,
      derivation: path
    }

    tap_bip32_derivation =
      case output.tap_bip32_derivation do
        nil ->
          [derivation]

        _ ->
          [derivation | output.tap_bip32_derivation]
      end

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
    <<depth::size(8), leaf_version::size(8), rest>> = tree
    {script, tree} = PsbtUtils.parse_compact_size_value(rest)
    {:ok, script} = Script.parse_script(script)
    data = %{
      # TODO:taproot make this TapLeaf
      depth: depth,
      leaf_version: leaf_version,
      script: script
    }
    parse_tap_tree(tree, [data | scripts])
  end

  defp serialize_tap_tree(leaves) do
    Enum.reduce(leaves, <<>>, fn leaf, acc ->
      # TODO:taproot use Script.serialize_with_compact_size
      script_bytes = Script.serialize_script(leaf.script)

      acc <> <<leaf.depth, leaf.leaf_version>>
      <> TxUtils.serialize_compact_size_unsigned_int(byte_size(script_bytes))
      <> script_bytes
    end)
  end

end
