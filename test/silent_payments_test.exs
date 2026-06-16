defmodule Bitcoinex.SilentPaymentsTest do
  use ExUnit.Case, async: true
  doctest Bitcoinex.SilentPayments

  alias Bitcoinex.SilentPayments
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Point, PrivateKey}

  # Values taken from the BIP-352 "Simple send: two inputs" test vector.
  @sk1 "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"
  @sk2 "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"
  @priv_sum "7ed265a6dac7aba8508a32d6d6b84c7f1dbd0a0941dd01088d69e8d556345f86"
  @pub1 "025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5"
  @pub2 "03bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792"
  @scan_pub "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4"
  @scan_priv "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"
  @txid1 "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
  @txid2 "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
  @shared_secret "028158aff7d61ea66b2fa7f555bc3c5937d1debbde16423d630f9aa7943e14d80d"
  @tweak_0 "f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6"
  # Recipient (== receiver) spend key + the resulting first output, same vector.
  @spend_pub "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36"
  @spend_priv "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3"
  @output_0 "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"

  defp privkey(hex),
    do: %PrivateKey{d: hex |> Base.decode16!(case: :lower) |> :binary.decode_unsigned()}

  defp point(hex) do
    {:ok, p} = Point.parse_public_key(Base.decode16!(hex, case: :lower))
    p
  end

  defp xonly(compressed_hex),
    do: Base.decode16!(String.slice(compressed_hex, 2, 64), case: :lower)

  # outpoint = txid (little-endian / reversed) || vout (4-byte little-endian)
  defp outpoint(txid_hex, vout) do
    txid_le =
      txid_hex
      |> Base.decode16!(case: :lower)
      |> :binary.bin_to_list()
      |> Enum.reverse()
      |> :binary.list_to_bin()

    txid_le <> <<vout::little-size(32)>>
  end

  describe "sum_input_privkeys/2" do
    test "sums non-taproot keys (matches the vector's input_private_key_sum)" do
      assert SilentPayments.sum_input_privkeys([], [privkey(@sk1), privkey(@sk2)]) ==
               {:ok, privkey(@priv_sum)}
    end

    test "negates a taproot key whose pubkey is odd-Y" do
      k = privkey(@sk2)
      refute Point.has_even_y(PrivateKey.to_point(k))

      assert SilentPayments.sum_input_privkeys([k], []) == {:ok, PrivateKey.negate(k)}

      {:ok, summed} = SilentPayments.sum_input_privkeys([k], [])
      assert Point.has_even_y(PrivateKey.to_point(summed))
    end

    test "leaves an already-even-Y taproot key unchanged" do
      k = privkey(@sk1)
      assert Point.has_even_y(PrivateKey.to_point(k))
      assert SilentPayments.sum_input_privkeys([k], []) == {:ok, k}
    end

    test "does not negate non-taproot keys" do
      k = privkey(@sk2)
      assert SilentPayments.sum_input_privkeys([], [k]) == {:ok, k}
    end

    test "errors when the final sum is zero" do
      k = privkey(@sk1)
      assert {:error, _} = SilentPayments.sum_input_privkeys([], [k, PrivateKey.negate(k)])
    end

    test "allows an intermediate zero sum when the final sum is non-zero" do
      k = privkey(@sk1)
      assert SilentPayments.sum_input_privkeys([], [k, PrivateKey.negate(k), k]) == {:ok, k}
    end

    test "errors with no inputs" do
      assert {:error, _} = SilentPayments.sum_input_privkeys([], [])
    end
  end

  describe "sum_input_pubkeys/2" do
    test "sums compressed pubkeys and equals the privkey-sum's point" do
      assert SilentPayments.sum_input_pubkeys([], [point(@pub1), point(@pub2)]) ==
               {:ok, PrivateKey.to_point(privkey(@priv_sum))}
    end

    test "lifts taproot x-only inputs to their even-Y point" do
      {:ok, lifted} = Point.lift_x(xonly(@pub1))
      assert SilentPayments.sum_input_pubkeys([xonly(@pub1)], []) == {:ok, lifted}
    end

    test "errors when the sum is the point at infinity" do
      p = point(@pub1)
      assert {:error, _} = SilentPayments.sum_input_pubkeys([], [p, Point.negate(p)])
    end

    test "allows an intermediate point at infinity when the final sum is finite" do
      p = point(@pub1)
      {:ok, sum} = SilentPayments.sum_input_pubkeys([], [p, Point.negate(p), p])
      assert sum.x == p.x and sum.y == p.y
    end

    test "errors with no inputs" do
      assert {:error, _} = SilentPayments.sum_input_pubkeys([], [])
    end
  end

  describe "input_hash/2" do
    test "rejects an outpoint that is not 36 bytes" do
      assert {:error, _} = SilentPayments.input_hash(<<0::size(280)>>, point(@pub1))
      assert {:error, _} = SilentPayments.input_hash(<<0::size(296)>>, point(@pub1))
    end

    test "is deterministic and returns 32 bytes" do
      op = outpoint(@txid1, 0)
      {:ok, h1} = SilentPayments.input_hash(op, point(@pub1))
      {:ok, h2} = SilentPayments.input_hash(op, point(@pub1))
      assert h1 == h2
      assert byte_size(h1) == 32
    end
  end

  describe "input_hash/2 -> shared_secret/3 -> shared_secret_tweak/2 (BIP-352 vector chain)" do
    test "derives the vector's shared_secret and t_0" do
      {:ok, a_sum} = SilentPayments.sum_input_privkeys([], [privkey(@sk1), privkey(@sk2)])
      a_pub = PrivateKey.to_point(a_sum)

      outpoint_l = Enum.min([outpoint(@txid1, 0), outpoint(@txid2, 0)])
      {:ok, input_hash} = SilentPayments.input_hash(outpoint_l, a_pub)

      {:ok, ecdh} = SilentPayments.shared_secret(a_sum, point(@scan_pub), input_hash)
      assert Point.sec(ecdh) == Base.decode16!(@shared_secret, case: :lower)

      {:ok, t0} = SilentPayments.shared_secret_tweak(ecdh, 0)
      assert PrivateKey.to_hex(t0) == @tweak_0
    end
  end

  describe "shared_secret/3" do
    test "is symmetric between sender and receiver (ECDH)" do
      a = %PrivateKey{d: 12_345}
      b = %PrivateKey{d: 67_890}
      input_hash = :binary.copy(<<0x42>>, 32)

      {:ok, s1} = SilentPayments.shared_secret(a, PrivateKey.to_point(b), input_hash)
      {:ok, s2} = SilentPayments.shared_secret(b, PrivateKey.to_point(a), input_hash)
      assert s1 == s2
    end
  end

  describe "shared_secret_tweak/2" do
    test "depends on the output index k" do
      ecdh = point(@shared_secret)
      {:ok, t0} = SilentPayments.shared_secret_tweak(ecdh, 0)
      {:ok, t1} = SilentPayments.shared_secret_tweak(ecdh, 1)
      refute t0 == t1
    end
  end

  describe "label_tweak/2 and label_point/2" do
    test "label_point is label_tweak * G" do
      b_scan = privkey(@scan_priv)
      {:ok, tweak} = SilentPayments.label_tweak(b_scan, 1)
      {:ok, lp} = SilentPayments.label_point(b_scan, 1)
      assert lp == PrivateKey.to_point(tweak)
    end

    test "different label integers give different tweaks (incl. m = 0 change label)" do
      b_scan = privkey(@scan_priv)
      {:ok, t0} = SilentPayments.label_tweak(b_scan, 0)
      {:ok, t1} = SilentPayments.label_tweak(b_scan, 1)
      {:ok, t2} = SilentPayments.label_tweak(b_scan, 2)
      assert t0 != t1 and t1 != t2 and t0 != t2
    end

    test "is deterministic" do
      b_scan = privkey(@scan_priv)
      assert SilentPayments.label_tweak(b_scan, 5) == SilentPayments.label_tweak(b_scan, 5)
    end
  end

  test "force_even_y agreement: a single taproot privkey sums to its even-Y form" do
    for hex <- [@sk1, @sk2] do
      k = privkey(hex)
      assert SilentPayments.sum_input_privkeys([k], []) == {:ok, Secp256k1.force_even_y(k)}
    end
  end

  defp vector_setup do
    {:ok, a_sum} = SilentPayments.sum_input_privkeys([], [privkey(@sk1), privkey(@sk2)])
    a_pub = PrivateKey.to_point(a_sum)
    outpoint_l = Enum.min([outpoint(@txid1, 0), outpoint(@txid2, 0)])
    {:ok, input_hash} = SilentPayments.input_hash(outpoint_l, a_pub)
    {a_sum, a_pub, input_hash}
  end

  describe "create_output_pubkey/5 (sender)" do
    test "derives the BIP-352 vector's taproot output key" do
      {a_sum, _a_pub, input_hash} = vector_setup()

      {:ok, p} =
        SilentPayments.create_output_pubkey(
          a_sum,
          point(@scan_pub),
          point(@spend_pub),
          input_hash,
          0
        )

      assert Point.x_hex(p) == @output_0
    end
  end

  describe "scan_output/5 (receiver)" do
    test "derives the per-output tweak and candidate point matching the vector" do
      {_a_sum, a_pub, input_hash} = vector_setup()

      {:ok, {t_k, p_k}} =
        SilentPayments.scan_output(privkey(@scan_priv), a_pub, point(@spend_pub), input_hash, 0)

      assert PrivateKey.to_hex(t_k) == @tweak_0
      assert Point.x_hex(p_k) == @output_0
    end
  end

  describe "input_hash size guards" do
    test "create_output_pubkey/5 and scan_output/5 reject a non-32-byte input_hash" do
      a = privkey(@sk1)
      p = point(@spend_pub)

      assert {:error, _} =
               SilentPayments.create_output_pubkey(a, point(@scan_pub), p, <<0::size(248)>>, 0)

      assert {:error, _} = SilentPayments.scan_output(a, point(@scan_pub), p, <<0::size(264)>>, 0)
    end
  end

  describe "spending_privkey/3" do
    test "unlabeled: d = (b_spend + t_k) mod n and d*G matches the output" do
      {_a_sum, a_pub, input_hash} = vector_setup()

      {:ok, {t_k, _p_k}} =
        SilentPayments.scan_output(privkey(@scan_priv), a_pub, point(@spend_pub), input_hash, 0)

      {:ok, d} = SilentPayments.spending_privkey(privkey(@spend_priv), t_k, nil)
      assert Point.x_hex(PrivateKey.to_point(d)) == @output_0
    end

    test "labeled: adds the label tweak" do
      b_spend = privkey(@spend_priv)
      t_k = %PrivateKey{d: 7}
      label = %PrivateKey{d: 11}
      {:ok, d} = SilentPayments.spending_privkey(b_spend, t_k, label)
      assert d.d == Secp256k1.Math.modulo(b_spend.d + 7 + 11, Secp256k1.Params.curve().n)
    end

    test "omitting the label equals passing nil" do
      b_spend = privkey(@spend_priv)
      t_k = %PrivateKey{d: 42}

      assert SilentPayments.spending_privkey(b_spend, t_k) ==
               SilentPayments.spending_privkey(b_spend, t_k, nil)
    end
  end

  describe "create_labeled_spend_pubkey/3" do
    test "B_m = B_spend + label_point(m)" do
      b_scan = privkey(@scan_priv)
      b_spend = point(@spend_pub)
      {:ok, label_point} = SilentPayments.label_point(b_scan, 1)
      {:ok, b_m} = SilentPayments.create_labeled_spend_pubkey(b_spend, b_scan, 1)
      assert b_m == Secp256k1.Math.add(b_spend, label_point)
    end
  end

  describe "output_label_candidates/2" do
    test "surfaces the label point for a labeled output regardless of output parity" do
      b_scan = privkey(@scan_priv)
      p_k = point(@spend_pub)
      {:ok, label_point} = SilentPayments.label_point(b_scan, 3)
      labeled_output = Secp256k1.Math.add(p_k, label_point)

      {:ok, candidates} =
        SilentPayments.output_label_candidates(p_k, Point.x_bytes(labeled_output))

      assert Enum.any?(candidates, &(&1.x == label_point.x and &1.y == label_point.y))
    end

    test "rejects a non-32-byte output" do
      assert {:error, _} =
               SilentPayments.output_label_candidates(point(@spend_pub), <<0::size(248)>>)
    end
  end
end
