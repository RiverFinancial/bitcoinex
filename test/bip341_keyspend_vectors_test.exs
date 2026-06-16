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
end
