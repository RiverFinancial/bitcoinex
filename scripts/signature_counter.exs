alias Bitcoinex.{Transaction, Script}
alias Bitcoinex.Transaction.Witness

hex = "01000000000102fb3ff03edaa009000d506fbf5b72edcb152d690eb6656bd5fe2941b76138a5ff0100000000feffffff20f588818ff06044f9126383445eb154098e3bd72e26e0a47697edfefa928e2d0000000000feffffff02826b7018020000002200202424a778d073cadeae042ed65351f29f8126e80dce9bad0371c65fda90bc134250c3000000000000160014ba5a7dd009f9bd3b83da14ea8d6eafa09eded702050047304402201dbe68fce8e004f08dcc019dd33d07125ffb72d9d2396b66fd84ec3148ae2057022034a8ed2201ae070c04742939a459f1946ebc432a67a338a80efc241f45c4a71301473044022057ef566fd017b0b135671f0eb824e7d1af7875e1bc1d8a0c0c48ee101a1680f6022076968810ca52a35689f8914a68eb486e9f49abb9c0de8eaa9c1a75532e52dff90147304402201328752952151ae712c78ff47687c31b2021e58470b083278b5e9747d6aa892302205faae469141bde4ce335df7f753e20909a4dd9dbd3a0773d78bbe0c9358fe6d001ad532102105437efdff4fbb1ec18897fab99c4bf15e538bc6eec088691da1b6447281bb321026c3e8c288bffc3de7032399e909e6443c44c9facae704284f8eea7aa20d31b2e210306502903c15a105bbfb048b2dc522846659bfc05a32bd43347d670dd268fc60c21035e4aa1743dba3a1c9dbae212d3955275d7f2736e2277960fcba5966496776e552103ed70af84f987ff6494cb6def95d65b3f75560f7ec861d12351ff955143d198a255ae0500473044022022cfa4d87d8d92547f9e0199348958545c0f707cb687367608fcd1c2c039bfb10220721c118e8ca63e3b03b951888128da4767c99ad188f948095887ee31cb93961b01473044022028b3651a01b57ca0f1c3f46907adf115a597bac1db493202c877e8750715c18b02205a3ce6da2e6baa78b2e325b69e71dd2e3c298a2460a0faa5a98baa97698f945d01473044022038aee92addb0e2e2f38fdf3f8f0f4f36e2662865be786df8889a12ebde7a6c0402203f241690f879c366311c1f5162fe9b0952946a9f9df8b3f462f77a438aca271d01ad532102105437efdff4fbb1ec18897fab99c4bf15e538bc6eec088691da1b6447281bb321026c3e8c288bffc3de7032399e909e6443c44c9facae704284f8eea7aa20d31b2e210306502903c15a105bbfb048b2dc522846659bfc05a32bd43347d670dd268fc60c21035e4aa1743dba3a1c9dbae212d3955275d7f2736e2277960fcba5966496776e552103ed70af84f987ff6494cb6def95d65b3f75560f7ec861d12351ff955143d198a255aecf950d00"
prev_values = [6425, 9000000000]

{:ok, tx} = Transaction.decode(hex)

%Witness{txinwitness: first_witness} = Enum.at(tx.witnesses, 0)
# multi_script = "532102105437efdff4fbb1ec18897fab99c4bf15e538bc6eec088691da1b6447281bb321026c3e8c288bffc3de7032399e909e6443c44c9facae704284f8eea7aa20d31b2e210306502903c15a105bbfb048b2dc522846659bfc05a32bd43347d670dd268fc60c21035e4aa1743dba3a1c9dbae212d3955275d7f2736e2277960fcba5966496776e552103ed70af84f987ff6494cb6def95d65b3f75560f7ec861d12351ff955143d198a255ae"
multi_script = Enum.at(first_witness, -1)
{:ok, prev_witness_script} = Script.parse_script(multi_script)
{:ok, m, pks} = Script.extract_multisig_policy(prev_witness_script)

pk_usage = Map.new(pks, fn pk -> {pk, 0} end)

pk_usage =
  tx.witnesses
  |> Enum.with_index()
  |> Enum.reduce(pk_usage, fn {%Witness{txinwitness: witness}, idx}, pk_usage ->
    prev_value = Enum.at(prev_values, idx)

    # last element of the witness
    prev_witness_script_hex = Enum.at(witness, -1)
    {:ok, prev_witness_script} = Script.parse_script(prev_witness_script_hex)

    # assuming this is a p2wsh multisig, the first element is empty and the last element is the witness script
    sigs = Enum.slice(witness, 1..-2//1)

    signatures = Enum.map(sigs, fn sig ->
      {:ok, sig} =
        sig
        # pop the sighash flag off
        |> String.slice(0..-3//1)
        |> Base.decode16!(case: :lower)
        |> Bitcoinex.Secp256k1.Signature.der_parse_signature()
      sig
    end)

  sighash = Transaction.bip143_sighash(tx, idx, witness_script: prev_witness_script, prev_input_value: prev_value) |> :binary.decode_unsigned()

  Enum.reduce(signatures, pk_usage, fn sig, pk_usage ->
    Enum.reduce(pks, pk_usage, fn pk, pk_usage ->
      case Bitcoinex.Secp256k1.Ecdsa.verify_signature(pk, sighash, sig) do
        true -> Map.update(pk_usage, pk, 1, &(&1 + 1))
        false -> pk_usage
      end
    end)
  end)
end)

pk_usage = Enum.map(pk_usage, fn {pk, count} -> {Bitcoinex.Secp256k1.Point.serialize_public_key(pk), count} end)

IO.inspect("#{m}/#{length(pks)}", label: "multisig policy")
IO.inspect(pk_usage, label: "pk_usage")
