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
  @spec decode(String.t()) :: {:ok, %Bitcoinex.PSBT{}} | {:error, term()}
  def decode(psbt_b64) when is_binary(psbt_b64) do
    case Base.decode64(psbt_b64, case: :lower) do
      {:ok, psbt_b64} ->
        case parse(psbt_b64) do
          {:ok, txn} ->
            {:ok, txn}
        end

      :error ->
        {:error, :decode_error}
    end
  end

  @spec serialize(%Bitcoinex.PSBT{}) :: binary
  defp serialize(packet) do
    global = Global.serialize_global(packet.global)
    inputs = In.serialize_inputs(packet.inputs)
    outputs = Out.serialize_outputs(packet.outputs)

    <<@magic::big-size(32)>> <>
      <<@separator::big-size(8)>> <>
      global <> inputs <> outputs
  end

  @spec encode_b64(%Bitcoinex.PSBT{}) :: String.t()
  def encode_b64(packet) do
    serialize(packet) |> Base.encode64()
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
end

defmodule Bitcoinex.PSBT.Utils do
  @moduledoc """
  Contains utility functions used throughout PSBT serialization.
  """
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  def parse_compact_size_value(key_value) do
    {len, key_value} = TxUtils.get_counter(key_value)
    <<value::binary-size(len), remaining::binary>> = key_value
    {value, remaining}
  end

  # parses key value pairs with a provided parse function
  def parse_key_value(psbt, kv, parse_func) do
    {kv, psbt} =
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

    {kv, psbt}
  end

  def serialize_kv(key, val) do
    key_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(key))
    val_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(val))
    key_len <> key <> val_len <> val
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
    :version,
    :proprietary
  ]

  @psbt_global_unsigned_tx 0x00
  @psbt_global_xpub 0x01
  @psbt_global_version 0xFB
  @psbt_global_proprietary 0xFC

  def parse_global(psbt) do
    PsbtUtils.parse_key_value(psbt, %Global{}, &parse/3)
  end

  # unsigned transaction
  defp parse(<<@psbt_global_unsigned_tx::big-size(8)>>, psbt, global) do
    {txn_len, psbt} = TxUtils.get_counter(psbt)

    <<txn_bytes::binary-size(txn_len), psbt::binary>> = psbt
    # TODO, different decode function for txn, directly in bytes
    case Transaction.decode(Base.encode16(txn_bytes, case: :lower)) do
      {:ok, txn} ->
        {%Global{global | unsigned_tx: txn}, psbt}

      {:error, error_msg} ->
        {:error, error_msg}
    end
  end

  defp parse(<<@psbt_global_xpub::big-size(8), xpub::binary-size(78)>>, psbt, global) do
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)

    <<master::little-unsigned-32, paths::binary>> = value

    {:ok, indexes} = DerivationPath.parse(paths)
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
              master_pfp: master,
              derivation: indexes
            }
          ]

        _ ->
          global.xpub ++
            [
              %{
                xpub: xpub,
                master_pfp: master,
                derivation: indexes
              }
            ]
      end

    global = %Global{global | xpub: global_xpub}

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

    {:ok, deriv_bin} = DerivationPath.serialize(value.derivation)

    val = <<value.master_pfp::little-size(32)>> <> deriv_bin

    PsbtUtils.serialize_kv(key <> key_data, val)
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
  @psbt_in_proprietary 0xFC

  def parse_inputs(psbt, num_inputs) do
    psbt
    |> parse_input([], num_inputs)
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
    PsbtUtils.serialize_kv(<<@psbt_in_sighash_type::big-size(8)>>, value)
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

    {:ok, deriv_bin} = DerivationPath.serialize(value.derivation)

    val = <<value.pfp::little-size(32)>> <> deriv_bin

    PsbtUtils.serialize_kv(<<@psbt_in_bip32_derivation::big-size(8)>> <> key_data, val)
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
    {:ok, txn} = Transaction.decode(Base.encode16(value, case: :lower))
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
    {value, psbt} = PsbtUtils.parse_compact_size_value(psbt)
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
  alias Bitcoinex.ExtendedKey.DerivationPath, as: DerivationPath

  defstruct [
    :redeem_script,
    :witness_script,
    :bip32_derivation,
    :proprietary
  ]

  @psbt_out_redeem_script 0x00
  @psbt_out_scriptwitness 0x01
  @psbt_out_bip32_derivation 0x02

  def serialize_outputs(outputs) when is_list(outputs) and length(outputs) > 0 do
    serialize_output(outputs, <<>>)
  end

  def serialize_outputs(_outputs) do
    <<>>
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

    {:ok, deriv_bin} = DerivationPath.serialize(value.derivation)

    val = <<value.pfp::little-size(32)>> <> deriv_bin

    PsbtUtils.serialize_kv(<<@psbt_out_bip32_derivation::big-size(8)>> <> key_data, val)
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

    <<pfp::little-unsigned-32, paths::binary>> = value
    {:ok, indexes} = DerivationPath.parse(paths)

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
end
