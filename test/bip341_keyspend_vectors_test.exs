defmodule Bitcoinex.Bip341KeyspendVectorsTest do
  @moduledoc """
  Drives the BIP341 key-path spend machinery (`Transaction.bip341_sighash/7`,
  `Taproot.tweak_privkey/2`, and `Schnorr.sign/3`) with the official BIP341
  wallet test vectors.

  https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json

  The checks are deliberately non-circular: sighashes/sigmsgs/tweaked keys are
  compared against the BIP's own ground-truth values, and the signatures we
  produce (as well as the vector's own expected witness signatures) are checked
  with an INDEPENDENT verifier (`Schnorr.verify_signature/3`) against the
  tweaked output key, never against our own signer.
  """
  use ExUnit.Case

  alias Bitcoinex.{Script, Taproot, Transaction, Utils}
  alias Bitcoinex.Secp256k1.{Point, PrivateKey, Schnorr, Signature}

  @vectors_path Path.join([__DIR__, "data", "bip341_wallet_test_vectors.json"])
  @vectors @vectors_path |> File.read!() |> Jason.decode!()
  @keypath Enum.at(@vectors["keyPathSpending"], 0)

  defp decode(hex), do: Base.decode16!(hex, case: :lower)

  defp privkey(hex),
    do: %PrivateKey{d: hex |> decode() |> :binary.decode_unsigned()}

  # All inputs' amounts and compact-size-prefixed scriptpubkeys, in input order.
  defp prev_amounts() do
    Enum.map(@keypath["given"]["utxosSpent"], & &1["amountSats"])
  end

  defp prev_scriptpubkeys() do
    Enum.map(@keypath["given"]["utxosSpent"], fn utxo ->
      {:ok, s} = Script.parse_script(utxo["scriptPubKey"])
      Script.serialize_with_compact_size(s)
    end)
  end

  defp unsigned_tx() do
    {:ok, tx} = Transaction.decode(@keypath["given"]["rawUnsignedTx"])
    tx
  end

  describe "BIP341 precomputed sighash components" do
    test "sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences / sha_outputs" do
      tx = unsigned_tx()
      inter = @keypath["intermediary"]

      assert Transaction.bip341_sha_prevouts(tx.inputs) == decode(inter["hashPrevouts"])
      assert Transaction.bip341_sha_amounts(prev_amounts()) == decode(inter["hashAmounts"])

      assert Transaction.bip341_sha_scriptpubkeys(prev_scriptpubkeys()) ==
               decode(inter["hashScriptPubkeys"])

      assert Transaction.bip341_sha_sequences(tx.inputs) == decode(inter["hashSequences"])
      assert Transaction.bip341_sha_outputs(tx.outputs) == decode(inter["hashOutputs"])
    end
  end

  describe "BIP341 key-path inputSpending vectors" do
    test "tweak_privkey, sigMsg, sigHash, and signature all match for every input" do
      tx = unsigned_tx()
      amounts = prev_amounts()
      spks = prev_scriptpubkeys()

      for spend <- @keypath["inputSpending"] do
        given = spend["given"]
        inter = spend["intermediary"]
        idx = given["txinIndex"]
        hash_type = given["hashType"]

        merkle_root =
          case given["merkleRoot"] do
            nil -> <<>>
            hex -> decode(hex)
          end

        # 1. tweaked private key matches the BIP ground truth
        q_sk = Taproot.tweak_privkey(privkey(given["internalPrivkey"]), merkle_root)
        assert Utils.int_to_big(q_sk.d, 32) == decode(inter["tweakedPrivkey"])

        # 2. the full sigMsg preimage matches (transitively validates every sha_* component)
        sigmsg = Transaction.bip341_sigmsg(tx, hash_type, 0, idx, amounts, spks)
        assert sigmsg == decode(inter["sigMsg"])

        # 3. the tagged TapSighash matches
        sighash = Transaction.bip341_sighash(tx, hash_type, 0, idx, amounts, spks)
        assert sighash == decode(inter["sigHash"])

        z = :binary.decode_unsigned(sighash)
        q_pk = PrivateKey.to_point(q_sk)
        # a validator always uses the even-Y lift of the x-only output key
        {:ok, even_q} = Point.lift_x(q_pk.x)

        # 4. the signature WE produce verifies under an independent verifier
        {:ok, our_sig} = Schnorr.sign(q_sk, z, 0)
        assert Schnorr.verify_signature(even_q, z, our_sig)

        # 5. the BIP's expected witness signature also verifies against our sighash.
        #    A 65-byte witness carries an explicit sighash flag byte (non-DEFAULT);
        #    DEFAULT (0x00) is a bare 64-byte signature.
        expected = decode(Enum.at(spend["expected"]["witness"], 0))

        sig_bytes =
          case byte_size(expected) do
            64 ->
              assert hash_type == 0x00
              expected

            65 ->
              <<sig::binary-size(64), flag>> = expected
              assert flag == hash_type
              sig
          end

        {:ok, vector_sig} = Signature.parse_signature(sig_bytes)
        assert Schnorr.verify_signature(even_q, z, vector_sig)
      end
    end

    test "covers all 7 inputs and every sighash flag type" do
      hash_types = Enum.map(@keypath["inputSpending"], & &1["given"]["hashType"])
      assert length(hash_types) == 7
      # DEFAULT, ALL, NONE, SINGLE, and the three ANYONECANPAY variants
      assert Enum.sort(hash_types) == [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]
    end
  end

  describe "BIP341 fullySignedTx (end-to-end)" do
    test "each key-path input's witness equals the expected witness signature" do
      {:ok, tx} = Transaction.decode(@keypath["auxiliary"]["fullySignedTx"])

      for spend <- @keypath["inputSpending"] do
        idx = spend["given"]["txinIndex"]
        expected_witness = spend["expected"]["witness"]
        witness = Enum.at(tx.witnesses, idx)
        assert witness.txinwitness == expected_witness, "witness mismatch at input #{idx}"
      end
    end
  end

  describe "bip341_sigmsg guards" do
    test "rejects invalid sighash flags and out-of-range ext_flag" do
      tx = unsigned_tx()
      amounts = prev_amounts()
      spks = prev_scriptpubkeys()

      # 0x04 is not a valid sighash flag
      assert {:error, _} = Transaction.bip341_sigmsg(tx, 0x04, 0, 0, amounts, spks)
      # ext_flag must be 0..127
      assert {:error, _} = Transaction.bip341_sigmsg(tx, 0x00, 128, 0, amounts, spks)
      # and bip341_sighash propagates the error
      assert {:error, _} = Transaction.bip341_sighash(tx, 0x04, 0, 0, amounts, spks)
    end
  end

  describe "silent-payment spend path (no taproot tweak)" do
    test "an output key used directly is spent by signing the key directly" do
      # A silent-payment output places the output key directly in the
      # scriptPubKey (no BIP341 taptweak). The spending key `d` comes from
      # SilentPayments.spending_privkey/3; here we stand in a concrete `d` and
      # assert the spend works WITHOUT Taproot.tweak_privkey.
      {:ok, d} =
        PrivateKey.new(0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF)

      d = Bitcoinex.Secp256k1.force_even_y(d)
      output_key = PrivateKey.to_point(d)

      # SP output: wrap the output key directly via create_p2tr/1 (NOT /2)
      {:ok, spk} = Script.create_p2tr(output_key)

      tx = %Transaction{
        version: 2,
        inputs: [
          %Transaction.In{
            prev_txid: "a7b1d058aa1b82af168831044720b16766b5a99667720b1c110464cd125c466b",
            prev_vout: 0,
            script_sig: "",
            sequence_no: 0xFFFFFFFF
          }
        ],
        outputs: [%Transaction.Out{value: 9000, script_pub_key: Script.to_hex(spk)}],
        lock_time: 0
      }

      sighash =
        Transaction.bip341_sighash(tx, 0x00, 0, 0, [10000], [
          Script.serialize_with_compact_size(spk)
        ])

      z = :binary.decode_unsigned(sighash)
      {:ok, sig} = Schnorr.sign(d, z, 0)

      # validator uses the even-Y lift of the x-only output key
      {:ok, even_q} = Point.lift_x(output_key.x)
      assert Schnorr.verify_signature(even_q, z, sig)
      assert byte_size(Signature.serialize_signature(sig)) == 64
    end
  end
end
