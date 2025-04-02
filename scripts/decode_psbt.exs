
defmodule DecodePSBT do
  @moduledoc """
  Decode a PSBT file and print the relevant details to the console.
  This is useful for getting the address and value of the inputs and outputs of a PSBT.
  """
  alias Bitcoinex.{PSBT, Script, Transaction}

  @doc """
  Run the script with the first (and only) argument as the path to the PSBT file.
  """
  @spec run(list(String.t())) :: :ok
  def run(args) do
    psbt_path = List.first(args)
    hash = calculate_sha256(psbt_path)
    data = decode_psbt(psbt_path)

    print_results(hash, data)

    :ok
  end

  @doc """
  Print the results to the console.
  """
  @spec print_results(String.t(), map()) :: :ok
  def print_results(hash, %{inputs: inputs, outputs: outputs, fee: fee}) do
    IO.puts("SHA256: #{hash}")

    IO.puts("\nInputs:")
    Enum.each(inputs, fn input ->
      if input.note != nil do
        IO.puts(input.note)
      end
      IO.puts("  #{input.address}: #{sats_to_btc_str(input.value)} BTC")
    end)

    IO.puts("\nOutputs:")
    Enum.each(outputs, fn output ->
      IO.puts("  #{output.address}: #{sats_to_btc_str(output.value)} BTC")
    end)

    IO.puts("\nFee: #{sats_to_btc_str(fee)} BTC")

    :ok
  end

  # Convert sats to btc.
  @spec sats_to_btc_str(non_neg_integer()) :: String.t()
  defp sats_to_btc_str(sats) do
    :erlang.float_to_binary(sats / 100_000_000, decimals: 8)
  end

  @doc """
  Calculate the SHA256 hash of the PSBT file.
  """
  @spec calculate_sha256(String.t()) :: String.t()
  def calculate_sha256(filename) do
    {:ok, file_content} = File.read(filename)
    :crypto.hash(:sha256, file_content) |> Base.encode16(case: :lower)
  end

  @doc """
  Decode the PSBT file.
  """
  @spec decode_psbt(String.t()) :: %{inputs: list(map()), outputs: list(map()), fee: non_neg_integer()}
  def decode_psbt(psbt_path) do
    {:ok, psbt} = PSBT.from_file(psbt_path)
    %PSBT{global: %PSBT.Global{unsigned_tx: tx}, inputs: inputs} = psbt
    %Bitcoinex.Transaction{outputs: outputs} = tx

    inputs = parse_inputs(inputs)
    outputs = parse_outputs(outputs)

    fee = sum_values(inputs) - sum_values(outputs)

    %{
      inputs: inputs,
      outputs: outputs,
      fee: fee
    }
  end

  @spec sum_values(list(%{value: non_neg_integer()})) :: non_neg_integer()
  defp sum_values(entries) do
    Enum.reduce(entries, 0, fn %{value: value}, sum -> sum + value end)
  end

  @doc """
  Parse the inputs of the PSBT.
  """
  @spec parse_inputs(list(PSBT.In.t())) :: list(map())
  def parse_inputs(inputs) do
    Enum.map(inputs, fn input ->
      %PSBT.In{witness_utxo: %Transaction.Out{
        value: value,
        script_pub_key: script_pub_key
      }, sighash_type: sighash_type} = input

      {:ok, script} = Script.parse_script(script_pub_key)
      {:ok, address} = Script.to_address(script, :mainnet)

      note =
        if sighash_type != nil and sighash_type != 0x01 do
          "🚨🚨🚨 WARNING: NON-STANDARD SIGHASH TYPE: #{sighash_name(sighash_type)} 🚨🚨🚨"
        else
          nil
        end

      %{
        address: address,
        value: value,
        note: note
      }
    end)
  end

  # map between a sighash's int and a name
  @spec sighash_name(non_neg_integer)
  defp sighash_name(n) do
    case n do
      0x00 -> "SIGHASH_DEFAULT" # for Segwit v1 (taproot) inputs only
      0x01 -> "SIGHASH_ALL"
      0x02 -> "SIGHASH_NONE"
      0x03 -> "SIGHASH_SINGLE"
      0x81 -> "SIGHASH_ALL/ANYONECANPAY"
      0x82 -> "SIGHASH_NONE/ANYONECANPAY"
      0x82 -> "SIGHASH_SINGLE/ANYONECANPAY"
    end
  end

  @doc """
  Parse the outputs of the PSBT.
  """
  @spec parse_outputs(list(Transaction.Out.t())) :: list(map())
  def parse_outputs(outputs) do
    Enum.map(outputs, fn output ->
      %Transaction.Out{
        value: value,
        script_pub_key: script_pub_key
      } = output

      {:ok, script} = Script.parse_script(script_pub_key)
      {:ok, address} = Script.to_address(script, :mainnet)

      %{
        address: address,
        value: value
      }
    end)
  end
end

DecodePSBT.run(System.argv())
