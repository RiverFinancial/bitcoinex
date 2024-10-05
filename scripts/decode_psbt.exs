
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
    %{inputs: inputs, outputs: outputs} = decode_psbt(psbt_path)

    print_results(hash, inputs, outputs)

    :ok
  end

  @doc """
  Print the results to the console.
  """
  @spec print_results(String.t(), list(map()), list(map())) :: :ok
  def print_results(hash, inputs, outputs) do
    IO.puts("SHA256: #{hash}")

    IO.puts("Inputs:")
    Enum.each(inputs, fn input ->
      IO.puts("  #{input.address}: #{input.value}")
    end)

    IO.puts("Outputs:")
    Enum.each(outputs, fn output ->
      IO.puts("  #{output.address}: #{output.value}")
    end)

    :ok
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
  @spec decode_psbt(String.t()) :: %{inputs: list(map()), outputs: list(map())}
  def decode_psbt(psbt_path) do
    {:ok, psbt} = PSBT.from_file(psbt_path)
    %PSBT{global: %PSBT.Global{unsigned_tx: tx}, inputs: inputs} = psbt
    %Bitcoinex.Transaction{outputs: outputs} = tx

    %{
      inputs: parse_inputs(inputs),
      outputs: parse_outputs(outputs)
    }
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
      }} = input

      {:ok, script} = Script.parse_script(script_pub_key)
      {:ok, address} = Script.to_address(script, :mainnet)

      %{
        address: address,
        value: value
      }
    end)
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
