defmodule Bitcoinex.Transaction do
  @moduledoc """
  Bitcoin on-chain transaction structure.
  Serialization and Deserialization of bitcoin on-chain transaction structure.
  """
  alias Bitcoinex.Transaction
  alias Bitcoinex.Transaction.In
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  defstruct [
    :version,
    :inputs,
    :outputs,
    :witnesses,
    :lock_time
  ]

  # @spec decode(String.t()) :: {:ok, t} | {:error, error}
  def decode(tx_hex) when is_binary(tx_hex) do
    case Base.decode16(tx_hex, case: :lower) do
      {:ok, tx_bytes} ->
        case parse(tx_bytes) do
          {:ok, txn} ->
            {:ok, txn}

          :error ->
            {:error, :parse_error}
        end

      :error ->
        {:error, :decode_error}
    end
  end

  # returns transaction 
  defp parse(tx_bytes) do
    <<version::little-size(32), remaining::binary>> = tx_bytes

    {is_segwit, remaining} =
      try do
        <<segwit_flag::size(16), segwit_remaining::binary>> = remaining

        if segwit_flag == 1 do
          {:segwit, segwit_remaining}
        else
          {:not_segwit, remaining}
        end
      rescue
        _ -> {:not_segwit, remaining}
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
  # https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
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
end

defmodule Bitcoinex.Transaction.Witness do
  @moduledoc """
  Witness structure part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Utils, as: TxUtils

  defstruct [
    :txinwitness
  ]

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

  defstruct [
    :prev_txid,
    :prev_vout,
    :script_sig,
    :sequence_no
  ]

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

  defstruct [
    :value,
    :script_pub_key
  ]

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
