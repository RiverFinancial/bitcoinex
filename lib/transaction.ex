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
  alias Bitcoinex.Taproot

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

  @minimum_time_locktime 500_000_000

  def minimum_time_locktime(), do: @minimum_time_locktime

  @sighash_default 0x00
  @sighash_all 0x01
  @sighash_none 0x02
  @sighash_single 0x03
  @sighash_anyonecanpay 0x80
  @sighash_anyonecanpay_all 0x81
  @sighash_anyonecanpay_none 0x82
  @sighash_anyonecanpay_single 0x83

  @valid_sighash_flags [
    @sighash_default,
    @sighash_all,
    @sighash_none,
    @sighash_single,
    @sighash_anyonecanpay_all,
    @sighash_anyonecanpay_none,
    @sighash_anyonecanpay_single
  ]

  def valid_sighash_flags(), do: @valid_sighash_flags

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

  def serialize(tx = %__MODULE__{}), do: TxUtils.serialize(tx)

  def vbyte_size(tx = %__MODULE__{}) do
    legacy_bytes = byte_size(TxUtils.serialize(%{tx | witnesses: []}))
    witness_bytes = byte_size(Witness.serialize_witness(tx.witnesses))
    # add segwit marker + flag for segwit txs
    witness_bytes =
      if witness_bytes > 0 do
        witness_bytes + 2
      else
        witness_bytes
      end

    legacy_bytes + ceil(witness_bytes / 4)
  end

  @spec bip341_sighash(
          t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          list(non_neg_integer()),
          list(<<_::280>>),
          list({:tapleaf, Taproot.TapLeaf.t()})
        ) :: <<_::256>>
  def bip341_sighash(
        tx = %__MODULE__{},
        hash_type,
        ext_flag,
        input_idx,
        prev_amounts,
        prev_scriptpubkeys,
        opts \\ []
      ) do
    sigmsg =
      bip341_sigmsg(tx, hash_type, ext_flag, input_idx, prev_amounts, prev_scriptpubkeys, opts)

    Taproot.tagged_hash_tapsighash(sigmsg)
  end

  @spec bip341_sigmsg(
          t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          list(non_neg_integer()),
          list(<<_::280>>),
          # TODO do good caching
          list({:tapleaf, Taproot.TapLeaf.t()})
        ) :: binary
  def bip341_sigmsg(
        tx,
        hash_type,
        ext_flag,
        input_idx,
        prev_amounts,
        prev_scriptpubkeys,
        opts \\ []
      )

  def bip341_sigmsg(_, _, ext_flag, _, _, _, _) when ext_flag < 0 or ext_flag > 127,
    do: {:error, "ext_flag out of range 0-127"}

  def bip341_sigmsg(_, hash_type, _, _, _, _, _) when hash_type not in @valid_sighash_flags,
    do: {:error, "invalid sighash flag"}

  def bip341_sigmsg(
        tx = %__MODULE__{},
        hash_type,
        ext_flag,
        input_idx,
        prev_amounts,
        prev_scriptpubkeys,
        opts
      ) do
    tx_data = bip341_tx_data(tx, hash_type, prev_amounts, prev_scriptpubkeys)

    bip341_sigmsg_with_cache(
      tx,
      hash_type,
      ext_flag,
      input_idx,
      prev_amounts,
      prev_scriptpubkeys,
      tx_data,
      opts
    )
  end

  @spec bip341_sigmsg_with_cache(
          t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          list(non_neg_integer()),
          list(binary),
          binary,
          list({:tapleaf, Taproot.TapLeaf.t()})
        ) :: binary
  def bip341_sigmsg_with_cache(
        tx = %__MODULE__{},
        hash_type,
        ext_flag,
        input_idx,
        prev_amounts,
        prev_scriptpubkeys,
        cached_tx_data,
        opts \\ []
      ) do
    hash_byte = :binary.encode_unsigned(hash_type)

    input_data =
      bip341_input_data(
        tx,
        hash_type,
        ext_flag,
        input_idx,
        Enum.at(prev_amounts, input_idx),
        Enum.at(prev_scriptpubkeys, input_idx)
      )

    output_data = bip341_output_data(tx, input_idx, hash_type)

    tapleaf = Keyword.get(opts, :tapleaf, nil)

    ext =
      case tapleaf do
        tl = %Taproot.TapLeaf{} ->
          # TODO last_executed_codesep_pos not implemented
          sigmsg_extension(ext_flag, tl)

        nil ->
          sigmsg_extension(ext_flag)
      end

    <<0>> <>
      hash_byte <>
      cached_tx_data <> input_data <> output_data <> ext
  end

  # TODO good caching
  # The results of this function can be reused across input signings.
  @spec bip341_tx_data(t(), non_neg_integer(), list(non_neg_integer()), list(<<_::280>>)) ::
          binary
  def bip341_tx_data(tx, hash_type, prev_amounts, prev_scriptpubkeys) do
    version = <<tx.version::little-size(32)>>
    lock_time = <<tx.lock_time::little-size(32)>>
    acc = version <> lock_time

    acc =
      if !hash_type_is_anyonecanpay(hash_type) do
        sha_prevouts = bip341_sha_prevouts(tx.inputs)
        sha_amounts = bip341_sha_amounts(prev_amounts)
        sha_scriptpubkeys = bip341_sha_scriptpubkeys(prev_scriptpubkeys)
        sha_sequences = bip341_sha_sequences(tx.inputs)
        acc <> sha_prevouts <> sha_amounts <> sha_scriptpubkeys <> sha_sequences
      else
        acc
      end

    if !hash_type_is_none_or_single(hash_type) do
      sha_outputs = bip341_sha_outputs(tx.outputs)
      acc <> sha_outputs
    else
      acc
    end
  end

  defp bip341_input_data(
         tx,
         hash_type,
         ext_flag,
         input_idx,
         prev_amount,
         <<prev_scriptpubkey::binary-size(35)>>
       ) do
    annex = get_annex(tx, input_idx)
    spend_type = ext_flag * 2 + if annex == nil, do: 0, else: 1

    input_commit =
      if hash_type_is_anyonecanpay(hash_type) do
        input = Enum.at(tx.inputs, input_idx)
        prev_outpoint = Transaction.In.serialize_prevout(input)

        prev_outpoint <>
          <<prev_amount::little-size(64)>> <>
          prev_scriptpubkey <> <<input.sequence_no::little-size(32)>>
      else
        <<input_idx::little-size(32)>>
      end

    <<spend_type>> <> input_commit <> bip341_sha_annex(annex)
  end

  defp bip341_output_data(tx, input_idx, hash_type) do
    if hash_type_is_single(hash_type) do
      tx.outputs
      |> Enum.at(input_idx)
      |> Out.serialize_output()
      |> :erlang.list_to_binary()
      |> Utils.sha256()
    else
      <<>>
    end
  end

  @spec hash_type_is_anyonecanpay(non_neg_integer()) :: boolean
  def hash_type_is_anyonecanpay(hash_type),
    do: Bitwise.band(hash_type, @sighash_anyonecanpay) == @sighash_anyonecanpay

  defp hash_type_is_none_or_single(hash_type) do
    b = Bitwise.band(hash_type, 3)
    b == @sighash_none || b == @sighash_single
  end

  defp hash_type_is_single(hash_type) do
    Bitwise.band(hash_type, 3) == @sighash_single
  end

  @spec get_annex(t(), non_neg_integer()) :: nil | binary | {:error}
  def get_annex(%__MODULE__{witnesses: nil}, _), do: nil
  def get_annex(%__MODULE__{witnesses: []}, _), do: nil

  def get_annex(%__MODULE__{witnesses: witnesses, inputs: inputs}, input_idx)
      when input_idx >= 0 and input_idx < length(inputs) do
    witnesses
    |> Enum.at(input_idx)
    |> Witness.get_annex()
  end

  def get_annex(_, _), do: {:error, "input index is out of range"}

  @spec bip341_sha_prevouts(list(In.t())) :: <<_::256>>
  def bip341_sha_prevouts(inputs) do
    inputs
    |> Transaction.In.serialize_prevouts()
    |> Utils.sha256()
  end

  @spec bip341_sha_amounts(list(non_neg_integer())) :: <<_::256>>
  def bip341_sha_amounts(prev_amounts) do
    prev_amounts
    |> Enum.reduce(<<>>, fn amount, acc -> acc <> <<amount::little-size(64)>> end)
    |> Utils.sha256()
  end

  @spec bip341_sha_scriptpubkeys(list(<<_::280>>)) :: <<_::256>>
  def bip341_sha_scriptpubkeys(prev_scriptpubkeys) do
    prev_scriptpubkeys
    |> Enum.reduce(<<>>, fn script, acc -> acc <> script end)
    |> Utils.sha256()
  end

  @spec bip341_sha_sequences(list(Transaction.In.t())) :: <<_::256>>
  def bip341_sha_sequences(inputs) do
    inputs
    |> Transaction.In.serialize_sequences()
    |> Utils.sha256()
  end

  @spec bip341_sha_outputs(list(Transaction.Out.t())) :: <<_::256>>
  def bip341_sha_outputs(outputs) do
    outputs
    |> Transaction.Out.serialize_outputs()
    |> Utils.sha256()
  end

  @spec bip341_sha_annex(nil | binary) :: <<_::256>>
  def bip341_sha_annex(nil), do: <<>>

  def bip341_sha_annex(annex) do
    annex
    |> byte_size()
    |> Utils.serialize_compact_size_unsigned_int()
    |> Kernel.<>(annex)
    |> Utils.sha256()
  end

  def sigmsg_extension(0), do: <<>>

  def sigmsg_extension(1, tapleaf, last_executed_codesep_pos \\ 0xFFFFFFFF),
    do: bip342_sigmsg_ext(tapleaf, last_executed_codesep_pos)

  def bip342_sigmsg_ext(tapleaf = %Taproot.TapLeaf{}, last_executed_codesep_pos \\ 0xFFFFFFFF) do
    key_version = 0x00

    Taproot.TapLeaf.hash(tapleaf) <>
      <<key_version>> <> <<last_executed_codesep_pos::little-size(32)>>
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
  alias Bitcoinex.Utils

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
    tx_in_count = Utils.serialize_compact_size_unsigned_int(length(txn.inputs))
    inputs = In.serialize_inputs(txn.inputs) |> :erlang.list_to_binary()
    tx_out_count = Utils.serialize_compact_size_unsigned_int(length(txn.outputs))
    outputs = Out.serialize_outputs(txn.outputs) |> :erlang.list_to_binary()
    witness = Witness.serialize_witness(txn.witnesses)
    lock_time = <<txn.lock_time::little-size(32)>>

    version <>
      marker <> flag <> tx_in_count <> inputs <> tx_out_count <> outputs <> witness <> lock_time
  end

  def serialize(txn) do
    version = <<txn.version::little-size(32)>>
    tx_in_count = Utils.serialize_compact_size_unsigned_int(length(txn.inputs))
    inputs = In.serialize_inputs(txn.inputs) |> :erlang.list_to_binary()
    tx_out_count = Utils.serialize_compact_size_unsigned_int(length(txn.outputs))
    outputs = Out.serialize_outputs(txn.outputs) |> :erlang.list_to_binary()
    lock_time = <<txn.lock_time::little-size(32)>>

    version <> tx_in_count <> inputs <> tx_out_count <> outputs <> lock_time
  end
end

defmodule Bitcoinex.Transaction.Witness do
  @moduledoc """
  Witness structure part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.Witness
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Utils

  @type t :: %__MODULE__{
          txinwitness: list(binary())
        }
  defstruct [
    :txinwitness
  ]

  @doc """
    Witness accepts a binary and deserializes it.
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
  def serialize_witness(nil), do: serialize_witness([])

  def serialize_witness(witnesses) do
    serialize_witness(witnesses, <<>>)
  end

  defp serialize_witness([], serialized_witnesses), do: serialized_witnesses

  defp serialize_witness(witnesses, serialized_witnesses) do
    [witness | witnesses] = witnesses

    serialized_witness =
      if witness == nil || Enum.empty?(witness.txinwitness) do
        <<0x00::big-size(8)>>
      else
        stack_len = Utils.serialize_compact_size_unsigned_int(length(witness.txinwitness))

        field =
          Enum.reduce(witness.txinwitness, <<>>, fn v, acc ->
            {:ok, item} = Base.decode16(v, case: :lower)
            item_len = Utils.serialize_compact_size_unsigned_int(byte_size(item))
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
        {%Witness{txinwitness: []}, remaining}
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

  @spec get_annex(t()) :: nil | binary
  def get_annex(%__MODULE__{txinwitness: witnesses}) when length(witnesses) < 2, do: nil

  def get_annex(%__MODULE__{txinwitness: witnesses}) do
    last =
      witnesses
      |> Enum.reverse()
      |> Enum.at(0)

    case last do
      # TODO switch to binary or int once witnesses are no longer stored as strings
      "50" <> _ -> last
      _ -> nil
    end
  end
end

defmodule Bitcoinex.Transaction.In do
  @moduledoc """
  Transaction Input part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.In
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Utils

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

    prev_txid = prev_txid_little_endian(input.prev_txid)

    {:ok, script_sig} = Base.decode16(input.script_sig, case: :lower)

    script_len = Utils.serialize_compact_size_unsigned_int(byte_size(script_sig))

    serialized_input = [
      prev_txid,
      <<input.prev_vout::little-size(32)>>,
      script_len,
      script_sig,
      <<input.sequence_no::little-size(32)>>
    ]

    serialize_input(inputs, [serialized_inputs, serialized_input])
  end

  def serialize_prevouts(inputs) do
    Enum.reduce(inputs, <<>>, fn input, acc -> acc <> serialize_prevout(input) end)
  end

  def serialize_prevout(input) do
    prev_txid = prev_txid_little_endian(input.prev_txid)
    prev_txid <> <<input.prev_vout::little-size(32)>>
  end

  def serialize_sequences(inputs) do
    Enum.reduce(inputs, <<>>, fn input, acc -> acc <> <<input.sequence_no::little-size(32)>> end)
  end

  def prev_txid_little_endian(prev_txid_hex) do
    prev_txid_hex
    |> Base.decode16!(case: :lower)
    |> Utils.flip_endianness()
    |> Utils.pad(32, :trailing)
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
      # TODO fix this
      prev_txid:
        Base.encode16(<<:binary.decode_unsigned(prev_txid, :big)::little-size(256)>>,
          case: :lower
        ),
      prev_vout: prev_vout,
      script_sig: Base.encode16(script_sig, case: :lower),
      sequence_no: sequence_no
    }

    parse(remaining, [input | inputs], count - 1)
  end

  def lexicographical_sort_inputs(inputs) do
    Enum.sort(inputs, &lexicographical_cmp_inputs/2)
  end

  def lexicographical_cmp_inputs(input1, input2) do
    # compare txids then vouts
    input1little_txid = Base.decode16!(input1.prev_txid, case: :lower)

    input1bin =
      (input1little_txid <> <<input1.prev_vout::big-size(32)>>)
      |> :erlang.binary_to_list()

    input2little_txid = Base.decode16!(input2.prev_txid, case: :lower)

    input2bin =
      (input2little_txid <> <<input2.prev_vout::big-size(32)>>)
      |> :erlang.binary_to_list()

    Utils.lexicographical_cmp(input1bin, input2bin)
  end
end

defmodule Bitcoinex.Transaction.Out do
  @moduledoc """
  Transaction Output part of an on-chain transaction.
  """
  alias Bitcoinex.Transaction.Out
  alias Bitcoinex.Transaction.Utils, as: TxUtils
  alias Bitcoinex.Utils

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
    serialize_outputs(outputs, [])
  end

  def serialize_outputs([], serialized_outputs), do: serialized_outputs

  def serialize_outputs([output | outputs], serialized_outputs) do
    serialized_output = serialize_output(output)
    serialize_outputs(outputs, [serialized_outputs, serialized_output])
  end

  def serialize_output(output) do
    {:ok, script_pub_key} = Base.decode16(output.script_pub_key, case: :lower)

    script_len = Utils.serialize_compact_size_unsigned_int(byte_size(script_pub_key))

    [<<output.value::little-size(64)>>, script_len, script_pub_key]
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

  def lexicographical_sort_outputs(outputs) do
    Enum.sort(outputs, &lexicographical_cmp_output/2)
  end

  def lexicographical_cmp_output(o1, o2) do
    # first compare amounts, then scriptpubkeys
    cond do
      o1.value < o2.value ->
        true

      o1.value > o2.value ->
        false

      o1.value == o2.value ->
        o1spk = Base.decode16!(o1.script_pub_key, case: :lower) |> :erlang.binary_to_list()
        o2spk = Base.decode16!(o2.script_pub_key, case: :lower) |> :erlang.binary_to_list()
        Utils.lexicographical_cmp(o1spk, o2spk)
    end
  end
end
