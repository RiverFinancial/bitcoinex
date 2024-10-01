alias Bitcoinex.{PSBT, Script, Transaction}

psbt_path = System.argv() |> List.first()
# psbt_path ="/Users/sachinmeier/Downloads/oct-2024-por.psbt"

{:ok, psbt} = PSBT.from_file(psbt_path)
%PSBT{global: %PSBT.Global{unsigned_tx: tx}, inputs: inputs} = psbt
%Bitcoinex.Transaction{outputs: outputs} = tx

inputs = Enum.map(inputs, fn input ->
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

outputs = Enum.map(outputs, fn output ->
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

IO.puts("Inputs:")
Enum.each(inputs, fn input ->
  IO.puts("  #{input.address}: #{input.value}")
end)

IO.puts("Outputs:")
Enum.each(outputs, fn output ->
  IO.puts("  #{output.address}: #{output.value}")
end)
