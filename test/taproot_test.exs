defmodule Bitcoinex.TaprootTest do
  use ExUnit.Case
  doctest Bitcoinex.Taproot

  alias Bitcoinex.{Script, Taproot}
  alias Bitcoinex.Secp256k1.Point

  # Official BIP341 wallet test vectors:
  # https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
  @vectors_path Path.join([__DIR__, "data", "bip341_wallet_test_vectors.json"])
  @vectors @vectors_path |> File.read!() |> Jason.decode!()
  @spk_vectors @vectors["scriptPubKey"]

  defp decode(hex), do: Base.decode16!(hex, case: :lower)

  # Build a Taproot.script_tree from the JSON `scriptTree` field:
  # null -> nil, leaf object -> TapLeaf, [a, b] -> {tree(a), tree(b)}.
  defp build_tree(nil), do: nil

  defp build_tree(%{"leafVersion" => v, "script" => s}),
    do: Taproot.TapLeaf.from_string(v, s)

  defp build_tree([a, b]), do: {build_tree(a), build_tree(b)}

  defp expected_root(nil), do: <<>>
  defp expected_root(hex), do: decode(hex)

  describe "BIP341 scriptPubKey test vectors" do
    test "merkelize_script_tree/1 computes the BIP341 merkle root" do
      for {e, i} <- Enum.with_index(@spk_vectors) do
        tree = build_tree(e["given"]["scriptTree"])
        {_, root} = Taproot.merkelize_script_tree(tree)

        assert root == expected_root(e["intermediary"]["merkleRoot"]),
               "merkle root mismatch for scriptPubKey vector #{i}"
      end
    end

    test "tweak_pubkey/2 produces the expected tweaked output key" do
      for {e, i} <- Enum.with_index(@spk_vectors) do
        {:ok, p} = Point.lift_x(decode(e["given"]["internalPubkey"]))
        root = expected_root(e["intermediary"]["merkleRoot"])
        q = Taproot.tweak_pubkey(p, root)

        assert Point.x_bytes(q) == decode(e["intermediary"]["tweakedPubkey"]),
               "tweaked pubkey mismatch for scriptPubKey vector #{i}"
      end
    end

    test "Script.create_p2tr/2 builds the expected scriptPubKey from internal key + tree" do
      for {e, i} <- Enum.with_index(@spk_vectors) do
        {:ok, p} = Point.lift_x(decode(e["given"]["internalPubkey"]))
        tree = build_tree(e["given"]["scriptTree"])
        {:ok, spk} = Script.create_p2tr(p, tree)

        assert Script.to_hex(spk) == e["expected"]["scriptPubKey"],
               "scriptPubKey mismatch for vector #{i}"
      end
    end

    test "build_control_block/3 produces blocks that validate_taproot_scriptpath_spend accepts" do
      # Exercises the BIP341 script-path control-block round trip for the
      # tree-bearing vectors (construction and validation are independent paths).
      for {e, i} <- Enum.with_index(@spk_vectors), e["given"]["scriptTree"] != nil do
        {:ok, p} = Point.lift_x(decode(e["given"]["internalPubkey"]))
        tree = build_tree(e["given"]["scriptTree"])
        {nodes, root} = Taproot.merkelize_script_tree(tree)
        q = Taproot.tweak_pubkey(p, root)

        for {{leaf, _path}, idx} <- Enum.with_index(nodes) do
          control_block = Taproot.build_control_block(p, tree, idx)
          script_bytes = Script.serialize_script(leaf.script)

          assert Taproot.validate_taproot_scriptpath_spend(q, script_bytes, control_block) ==
                   true,
                 "control block #{idx} failed validation for vector #{i}"
        end
      end
    end
  end

  describe "calculate_taptweak/2" do
    test "key-path-only tweak commits to an empty merkle root" do
      # vector 0 has scriptTree == null (key-path only)
      e = Enum.at(@spk_vectors, 0)
      {:ok, p} = Point.lift_x(decode(e["given"]["internalPubkey"]))

      tweak = Taproot.calculate_taptweak(p, <<>>)
      assert Bitcoinex.Utils.int_to_big(tweak, 32) == decode(e["intermediary"]["tweak"])
    end
  end
end
