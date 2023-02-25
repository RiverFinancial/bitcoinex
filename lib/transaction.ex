defmodule Bitcoinex.Transaction do
  @moduledoc """
  Bitcoin on-chain transaction structure.
  Supports serialization of transactions.
  """
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.In
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Utils
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @type t() :: %__MODULE__{
          version: non_neg_integer(),
          inputs: list(In.t()),
          outputs: list(Out.t()),
          witnesses: list(Witness.t()),
          lock_time: non_neg_integer()
        }

  # TODO refactor witnesses into input fields
  defstruct [
    :version,
    :inputs,
    :outputs,
    :witnesses,
    :lock_time
  ]

  # https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
  @valid_sighash_flags [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

  def valid_sighash_flags(), do: @valid_sighash_flags

  @minimum_time_locktime 500_000_000

  def minimum_time_locktime(), do: @minimum_time_locktime

  @doc """
    Returns the TxID of the given tranasction.

    TxID is sha256(sha256(nVersion | txins | txouts | nLockTime))
  """
  def transaction_id(txn) do
    legacy_txn = TxUtils.serialize(%{txn | witnesses: []})

    Base.encode16(
      <<:binary.decode_unsigned(
          Utils.double_sha256(legacy_txn),
          :big
        )::little-size(256)>>,
      case: :lower
    )
  end

  @doc """
    Decodes a transaction in a hex encoded string into binary.
  """
  def decode(serialized_tx) when is_binary(serialized_tx) do
    tx_bytes =
      case Base.decode16(serialized_tx, case: :lower) do
        {:ok, tx_bytes} ->
          tx_bytes

        # if decoding fails, attempt to parse as if serialized_tx is already binary.
        :error ->
          serialized_tx
      end

    case parse(tx_bytes) do
      {:ok, txn} ->
        {:ok, txn}

      :error ->
        {:error, :parse_error}
    end
  end

  # returns transaction
  defp parse(<<version::little-size(32), remaining::binary>>) do
    {is_segwit, remaining} =
      case remaining do
        <<1::size(16), segwit_remaining::binary>> ->
          {:segwit, segwit_remaining}

        _ ->
          {:not_segwit, remaining}
      end

    # Inputs.
    {in_counter, remaining} = TxUtils.get_counter(remaining)
    {inputs, remaining} = In.parse_inputs(in_counter, remaining)

    # Outputs.
    {out_counter, remaining} = TxUtils.get_counter(remaining)
    {outputs, remaining} = Out.parse_outputs(out_counter, remaining)

    # If flag 0001 is present, this indicates an attached segregated witness structure.
    {witnesses, remaining} =
      if is_segwit == :segwit do
        Witness.parse_witness(in_counter, remaining)
      else
        {nil, remaining}
      end

    <<lock_time::little-size(32), remaining::binary>> = remaining

    if byte_size(remaining) != 0 do
      :error
    else
      {:ok,
       %Transaction{
         version: version,
         inputs: inputs,
         outputs: outputs,
         witnesses: witnesses,
         lock_time: lock_time
       }}
    end
  end
end

defmodule Bitcoinex.Transaction.Utils do
  @moduledoc """
  Utilities for when dealing with transaction objects.
  """
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.In
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.Transaction.Witness

  @doc """
    Returns the Variable Length Integer used in serialization.

    Reference: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
  """
  @spec get_counter(binary) :: {non_neg_integer(), binary()}
  def get_counter(<<counter::little-size(8), vec::binary>>) do
    case counter do
      # 0xFD followed by the length as uint16_t
      0xFD ->
        <<len::little-size(16), vec::binary>> = vec
        {len, vec}

      # 0xFE followed by the length as uint32_t
      0xFE ->
        <<len::little-size(32), vec::binary>> = vec
        {len, vec}

      # 0xFF followed by the length as uint64_t
      0xFF ->
        <<len::little-size(64), vec::binary>> = vec
        {len, vec}

      _ ->
        {counter, vec}
    end
  end

  @spec serialize(Transaction.t()) :: binary()
  def serialize(%Transaction{witnesses: witness} = txn)
      when is_list(witness) and length(witness) > 0 do
    version = <<txn.version::little-size(32)>>
    marker = <<0x00::big-size(8)>>
    flag = <<0x01::big-size(8)>>
    tx_in_count = serialize_compact_size_unsigned_int(length(txn.inputs))
    inputs = In.serialize_inputs(txn.inputs) |> :erlang.list_to_binary()
    tx_out_count = serialize_compact_size_unsigned_int(length(txn.outputs))
    outputs = Out.serialize_outputs(txn.outputs) |> :erlang.list_to_binary()
    witness = Witness.serialize_witness(txn.witnesses)
    lock_time = <<txn.lock_time::little-size(32)>>

    version <>
      marker <> flag <> tx_in_count <> inputs <> tx_out_count <> outputs <> witness <> lock_time
  end

  def serialize(txn) do
    version = <<txn.version::little-size(32)>>
    tx_in_count = serialize_compact_size_unsigned_int(length(txn.inputs))
    inputs = In.serialize_inputs(txn.inputs) |> :erlang.list_to_binary()
    tx_out_count = serialize_compact_size_unsigned_int(length(txn.outputs))
    outputs = Out.serialize_outputs(txn.outputs) |> :erlang.list_to_binary()
    lock_time = <<txn.lock_time::little-size(32)>>

    version <> tx_in_count <> inputs <> tx_out_count <> outputs <> lock_time
  end

  @doc """
    Returns the serialized variable length integer.
  """
  def serialize_compact_size_unsigned_int(compact_size) do
    cond do
      compact_size >= 0 and compact_size <= 0xFC ->
        <<compact_size::little-size(8)>>

      compact_size <= 0xFFFF ->
        <<0xFD>> <> <<compact_size::little-size(16)>>

      compact_size <= 0xFFFFFFFF ->
        <<0xFE>> <> <<compact_size::little-size(32)>>

      compact_size <= 0xFF ->
        <<0xFF>> <> <<compact_size::little-size(64)>>
    end
  end
end

defmodule Bitcoinex.Transaction.Witness do
  @moduledoc """
  Witness structure part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @type t :: %__MODULE__{
          txinwitness: list(binary())
        }
  defstruct [
    :txinwitness
  ]

  @doc """
    Wtiness accepts a binary and deserializes it.
  """
  @spec witness(binary) :: t()
  def witness(witness_bytes) do
    {stack_size, witness_bytes} = TxUtils.get_counter(witness_bytes)

    {witness, _} =
      if stack_size == 0 do
        {%Witness{txinwitness: []}, witness_bytes}
      else
        {stack_items, witness_bytes} = parse_stack(witness_bytes, [], stack_size)
        {%Witness{txinwitness: stack_items}, witness_bytes}
      end

    witness
  end

  @spec serialize_witness(list(Witness.t())) :: binary
  def serialize_witness(witnesses) do
    serialize_witness(witnesses, <<>>)
  end

  defp serialize_witness([], serialized_witnesses), do: serialized_witnesses

  defp serialize_witness(witnesses, serialized_witnesses) do
    [witness | witnesses] = witnesses

    serialized_witness =
      if witness == nil || Enum.empty?(witness.txinwitness) do
        <<0x0::big-size(8)>>
      else
        stack_len = TxUtils.serialize_compact_size_unsigned_int(length(witness.txinwitness))

        field =
          Enum.reduce(witness.txinwitness, <<>>, fn v, acc ->
            {:ok, item} = Base.decode16(v, case: :lower)
            item_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(item))
            acc <> item_len <> item
          end)

        stack_len <> field
      end

    serialize_witness(witnesses, serialized_witnesses <> serialized_witness)
  end

  def parse_witness(0, remaining), do: {nil, remaining}

  def parse_witness(counter, witnesses) do
    parse(witnesses, [], counter)
  end

  defp parse(remaining, witnesses, 0), do: {Enum.reverse(witnesses), remaining}

  defp parse(remaining, witnesses, count) do
    {stack_size, remaining} = TxUtils.get_counter(remaining)

    {witness, remaining} =
      if stack_size == 0 do
        {%Witness{txinwitness: 0}, remaining}
      else
        {stack_items, remaining} = parse_stack(remaining, [], stack_size)
        {%Witness{txinwitness: stack_items}, remaining}
      end

    parse(remaining, [witness | witnesses], count - 1)
  end

  defp parse_stack(remaining, stack_items, 0), do: {Enum.reverse(stack_items), remaining}

  defp parse_stack(remaining, stack_items, stack_size) do
    {item_size, remaining} = TxUtils.get_counter(remaining)

    <<stack_item::binary-size(item_size), remaining::binary>> = remaining

    parse_stack(
      remaining,
      [Base.encode16(stack_item, case: :lower) | stack_items],
      stack_size - 1
    )
  end
end

defmodule Bitcoinex.Transaction.In do
  @moduledoc """
  Transaction Input part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.In
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @type t :: %__MODULE__{
          prev_txid: binary(),
          prev_vout: non_neg_integer(),
          script_sig: binary(),
          sequence_no: non_neg_integer()
        }

  defstruct [
    :prev_txid,
    :prev_vout,
    :script_sig,
    :sequence_no
  ]

  @spec serialize_inputs(list(In.t())) :: iolist()
  def serialize_inputs(inputs) do
    serialize_input(inputs, [])
  end

  defp serialize_input([], serialized_inputs), do: serialized_inputs

  defp serialize_input(inputs, serialized_inputs) do
    [input | inputs] = inputs

    {:ok, prev_txid} = Base.decode16(input.prev_txid, case: :lower)

    prev_txid =
      prev_txid
      |> :binary.decode_unsigned(:big)
      |> :binary.encode_unsigned(:little)
      |> Bitcoinex.Utils.pad(32, :trailing)

    {:ok, script_sig} = Base.decode16(input.script_sig, case: :lower)

    script_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(script_sig))

    serialized_input = [
      prev_txid,
      <<input.prev_vout::little-size(32)>>,
      script_len,
      script_sig,
      <<input.sequence_no::little-size(32)>>
    ]

    serialize_input(inputs, [serialized_inputs, serialized_input])
  end

  def parse_inputs(counter, inputs) do
    parse(inputs, [], counter)
  end

  defp parse(remaining, inputs, 0), do: {Enum.reverse(inputs), remaining}

  defp parse(
         <<prev_txid::binary-size(32), prev_vout::little-size(32), remaining::binary>>,
         inputs,
         count
       ) do
    {script_len, remaining} = TxUtils.get_counter(remaining)

    <<script_sig::binary-size(script_len), sequence_no::little-size(32), remaining::binary>> =
      remaining

    input = %In{
      prev_txid:
        Base.encode16(<<:binary.decode_unsigned(prev_txid, :big)::little-size(256)>>, case: :lower),
      prev_vout: prev_vout,
      script_sig: Base.encode16(script_sig, case: :lower),
      sequence_no: sequence_no
    }

    parse(remaining, [input | inputs], count - 1)
  end
end

defmodule Bitcoinex.Transaction.Out do
  @moduledoc """
  Transaction Output part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  @type t :: %__MODULE__{
          value: non_neg_integer(),
          script_pub_key: binary()
        }

  defstruct [
    :value,
    :script_pub_key
  ]

  @spec serialize_outputs(list(Out.t())) :: iolist()
  def serialize_outputs(outputs) do
    serialize_output(outputs, [])
  end

  defp serialize_output([], serialized_outputs), do: serialized_outputs

  defp serialize_output(outputs, serialized_outputs) do
    [output | outputs] = outputs

    {:ok, script_pub_key} = Base.decode16(output.script_pub_key, case: :lower)

    script_len = TxUtils.serialize_compact_size_unsigned_int(byte_size(script_pub_key))

    serialized_output = [<<output.value::little-size(64)>>, script_len, script_pub_key]
    serialize_output(outputs, [serialized_outputs, serialized_output])
  end

  def output(out_bytes) do
    <<value::little-size(64), out_bytes::binary>> = out_bytes
    {script_len, out_bytes} = TxUtils.get_counter(out_bytes)
    <<script_pub_key::binary-size(script_len), _::binary>> = out_bytes
    %Out{value: value, script_pub_key: Base.encode16(script_pub_key, case: :lower)}
  end

  def parse_outputs(counter, outputs) do
    parse(outputs, [], counter)
  end

  defp parse(remaining, outputs, 0), do: {Enum.reverse(outputs), remaining}

  defp parse(<<value::little-size(64), remaining::binary>>, outputs, count) do
    {script_len, remaining} = TxUtils.get_counter(remaining)

    <<script_pub_key::binary-size(script_len), remaining::binary>> = remaining

    output = %Out{
      value: value,
      script_pub_key: Base.encode16(script_pub_key, case: :lower)
    }

    parse(remaining, [output | outputs], count - 1)
  end
end
