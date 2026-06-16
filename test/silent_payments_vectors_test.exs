defmodule Bitcoinex.SilentPaymentsVectorHarness do
  @moduledoc """
  Test-only harness that drives `Bitcoinex.SilentPayments` with the official BIP-352
  `send_and_receive_test_vectors.json`.

  It plays the role the spec assigns to the caller (a wallet/scanner): it parses the
  transaction `vin`s to extract eligible input public/private keys (the BIP-352 "Inputs For
  Shared Secret Derivation" rules — P2PKH incl. malleated scriptSigs, P2SH-P2WPKH, P2WPKH,
  P2TR with the NUMS-H skip, and skipping uncompressed/invalid inputs), selects the smallest
  outpoint, and drives the `k` loop. The cryptography itself is exercised through the public
  `Bitcoinex.SilentPayments` API.
  """
  import ExUnit.Assertions

  alias Bitcoinex.{SilentPayments, Utils}
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey, Schnorr, Signature}

  @n Params.curve().n
  @k_max 2323
  @nums_h 0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0

  # ------------------------------------------------------------------ sending

  def run_sending(tcase) do
    for sending <- tcase["sending"] || [] do
      given = sending["given"]
      expected = sending["expected"]
      vins = given["vin"]

      eligible = for vin <- vins, (r = extract_pubkey(vin)) != :skip, do: {r, vin}

      assert Enum.map(eligible, fn {r, _} -> eligible_pubkey_hex(r) end) ==
               (expected["input_pub_keys"] || []),
             "input_pub_keys mismatch :: #{tcase["comment"]}"

      assert_recipient_addresses(given["recipients"], tcase["comment"])

      {taproot, other} =
        Enum.reduce(eligible, {[], []}, fn {r, vin}, {tp, ot} ->
          sk = privkey(vin["private_key"])

          case r do
            {:taproot, _} -> {[sk | tp], ot}
            {:other, _} -> {tp, [sk | ot]}
          end
        end)

      case SilentPayments.sum_input_privkeys(Enum.reverse(taproot), Enum.reverse(other)) do
        {:error, _} ->
          assert expected["outputs"] == [[]], "expected no outputs :: #{tcase["comment"]}"

        {:ok, a_sum} ->
          assert PrivateKey.to_hex(a_sum) == expected["input_private_key_sum"],
                 "input_private_key_sum mismatch :: #{tcase["comment"]}"

          {:ok, input_hash} =
            SilentPayments.input_hash(smallest_outpoint(vins), PrivateKey.to_point(a_sum))

          run_sending_outputs(a_sum, input_hash, given["recipients"], expected, tcase["comment"])
      end
    end
  end

  defp run_sending_outputs(a_sum, input_hash, recipients, expected, comment) do
    groups = recipients |> expand_recipients() |> Enum.group_by(& &1["scan_pub_key"])

    if Enum.any?(groups, fn {_, group} -> length(group) > @k_max end) do
      assert expected["outputs"] == [[]], "expected no outputs (K_max exceeded) :: #{comment}"
    else
      outputs =
        for {scan_hex, group} <- groups, {recipient, k} <- Enum.with_index(group) do
          {:ok, p} =
            SilentPayments.create_output_pubkey(
              a_sum,
              point(scan_hex),
              point(recipient["spend_pub_key"]),
              input_hash,
              k
            )

          Point.x_hex(p)
        end

      output_set = MapSet.new(outputs)

      assert Enum.any?(expected["outputs"], &(MapSet.new(&1) == output_set)),
             "sending outputs mismatch :: #{comment}"
    end
  end

  # ---------------------------------------------------------------- receiving

  def run_receiving(tcase) do
    for receiving <- tcase["receiving"] || [] do
      given = receiving["given"]
      expected = receiving["expected"]
      vins = given["vin"]

      b_scan = privkey(given["key_material"]["scan_priv_key"])
      b_spend_priv = privkey(given["key_material"]["spend_priv_key"])
      b_spend = PrivateKey.to_point(b_spend_priv)

      assert_receiving_addresses(
        b_scan,
        b_spend,
        given["labels"] || [],
        expected["addresses"],
        tcase["comment"]
      )

      {taproot_xonly, other_points} =
        Enum.reduce(vins, {[], []}, fn vin, {tp, ot} ->
          case extract_pubkey(vin) do
            {:taproot, xonly} -> {[xonly | tp], ot}
            {:other, p} -> {tp, [p | ot]}
            :skip -> {tp, ot}
          end
        end)

      case SilentPayments.sum_input_pubkeys(
             Enum.reverse(taproot_xonly),
             Enum.reverse(other_points)
           ) do
        {:error, _} ->
          # No eligible inputs, or A is the point at infinity -> tx is skipped.
          assert expected_count(expected) == 0,
                 "expected 0 outputs (skipped tx) :: #{tcase["comment"]}"

        {:ok, a_sum} ->
          assert Point.serialize_public_key(a_sum) == expected["input_pub_key_sum"],
                 "input_pub_key_sum mismatch :: #{tcase["comment"]}"

          {:ok, input_hash} = SilentPayments.input_hash(smallest_outpoint(vins), a_sum)
          assert_intermediates(b_scan, a_sum, input_hash, expected, tcase["comment"])
          assert_scan_output_consistent(b_scan, a_sum, b_spend, input_hash, tcase["comment"])

          labels = precompute_labels(b_scan, given["labels"] || [])
          outputs = Enum.map(given["outputs"], &decode_hex/1)
          found = scan(b_scan, a_sum, b_spend, input_hash, outputs, labels)

          assert length(found) == expected_count(expected),
                 "found #{length(found)}, expected #{expected_count(expected)} :: #{tcase["comment"]}"

          verify_found(found, expected["outputs"] || [], b_spend_priv, tcase["comment"])
      end
    end
  end

  # Sender side: decode each recipient address and check it carries the given keys.
  defp assert_recipient_addresses(recipients, comment) do
    for r <- recipients || [] do
      assert {:ok, {_net, _version, b_scan, b_m}} = SilentPayments.decode_address(r["address"])

      assert Point.serialize_public_key(b_scan) == r["scan_pub_key"],
             "recipient B_scan mismatch :: #{comment}"

      assert Point.serialize_public_key(b_m) == r["spend_pub_key"],
             "recipient B_m mismatch :: #{comment}"
    end
  end

  # Receiver side: re-encode the base + labeled addresses and compare to the vector.
  defp assert_receiving_addresses(_b_scan, _b_spend, _labels, nil, _comment), do: :ok

  defp assert_receiving_addresses(b_scan, b_spend, labels, expected_addresses, comment) do
    {:ok, base} = SilentPayments.encode_address(PrivateKey.to_point(b_scan), b_spend, :mainnet)

    labeled =
      for m <- labels do
        {:ok, b_m} = SilentPayments.create_labeled_spend_pubkey(b_spend, b_scan, m)
        {:ok, addr} = SilentPayments.encode_address(PrivateKey.to_point(b_scan), b_m, :mainnet)
        addr
      end

    assert [base | labeled] == expected_addresses, "receiving addresses mismatch :: #{comment}"
  end

  # Optional cross-checks against the expected intermediate values, when present.
  defp assert_intermediates(b_scan, a_sum, input_hash, expected, comment) do
    if tweak = expected["tweak"] do
      point = Math.multiply(a_sum, :binary.decode_unsigned(input_hash))
      assert Point.serialize_public_key(point) == tweak, "tweak point mismatch :: #{comment}"
    end

    if shared = expected["shared_secret"] do
      {:ok, ecdh} = SilentPayments.shared_secret(b_scan, a_sum, input_hash)
      assert Point.serialize_public_key(ecdh) == shared, "shared_secret mismatch :: #{comment}"
    end
  end

  # Cross-check scan_output/5 (the bundled convenience) against the unbundled
  # shared_secret/3 + shared_secret_tweak/2 path the scan loop uses below.
  defp assert_scan_output_consistent(b_scan, a_sum, b_spend, input_hash, comment) do
    {:ok, {t0, p0}} = SilentPayments.scan_output(b_scan, a_sum, b_spend, input_hash, 0)
    {:ok, ecdh} = SilentPayments.shared_secret(b_scan, a_sum, input_hash)
    {:ok, t0b} = SilentPayments.shared_secret_tweak(ecdh, 0)
    assert t0 == t0b, "scan_output t_k inconsistent :: #{comment}"

    assert Point.x_bytes(p0) == Point.x_bytes(Math.add(b_spend, PrivateKey.to_point(t0b))),
           "scan_output p_k inconsistent :: #{comment}"
  end

  # The BIP-352 scanning loop, capped at K_max. A real scanner computes the ECDH secret once
  # and loops the cheap per-output tweak; we do the same (shared_secret/3 once, then
  # shared_secret_tweak/2 per k). For labels we add each label point to P_k and test
  # membership (the BIP's O(K·M) alternative to the per-output subtraction), which keeps the
  # adversarial K_max case (2323 labeled outputs) tractable in pure-Elixir EC.
  defp scan(b_scan, a_sum, b_spend, input_hash, outputs, labels) do
    {:ok, ecdh} = SilentPayments.shared_secret(b_scan, a_sum, input_hash)
    do_scan(ecdh, b_spend, MapSet.new(outputs), labels, 0, [])
  end

  defp do_scan(_ecdh, _b_spend, _remaining, _labels, @k_max, found), do: Enum.reverse(found)

  defp do_scan(ecdh, b_spend, remaining, labels, k, found) do
    {:ok, t_k} = SilentPayments.shared_secret_tweak(ecdh, k)
    p_k = Math.add(b_spend, PrivateKey.to_point(t_k))

    case match_output(p_k, t_k, remaining, labels) do
      {:match, output, entry} ->
        do_scan(ecdh, b_spend, MapSet.delete(remaining, output), labels, k + 1, [entry | found])

      :no_match ->
        Enum.reverse(found)
    end
  end

  # Direct match first, then each label (output == P_k + label_point).
  defp match_output(p_k, t_k, remaining, labels) do
    direct = Point.x_bytes(p_k)

    if MapSet.member?(remaining, direct) do
      {:match, direct, %{pub_key: hex(direct), tweak: PrivateKey.to_hex(t_k)}}
    else
      match_labels(p_k, t_k, remaining, labels)
    end
  end

  defp match_labels(_p_k, _t_k, _remaining, []), do: :no_match

  defp match_labels(p_k, t_k, remaining, [{label_point, label_tweak} | rest]) do
    output = Point.x_bytes(Math.add(p_k, label_point))

    if MapSet.member?(remaining, output) do
      # Cross-check the subtraction-based library helper surfaces this label point.
      {:ok, candidates} = SilentPayments.output_label_candidates(p_k, output)

      assert Enum.any?(candidates, &(&1.x == label_point.x and &1.y == label_point.y)),
             "output_label_candidates did not surface the matched label point"

      full = Math.modulo(t_k.d + label_tweak.d, @n)
      {:match, output, %{pub_key: hex(output), tweak: PrivateKey.to_hex(%PrivateKey{d: full})}}
    else
      match_labels(p_k, t_k, remaining, rest)
    end
  end

  defp verify_found(found, expected_outputs, b_spend_priv, comment) do
    by_pub = Map.new(found, &{&1.pub_key, &1})

    for exp <- expected_outputs do
      entry = Map.fetch!(by_pub, exp["pub_key"])

      assert entry.tweak == exp["priv_key_tweak"],
             "priv_key_tweak mismatch for #{exp["pub_key"]} :: #{comment}"

      {:ok, d} =
        SilentPayments.spending_privkey(
          b_spend_priv,
          %PrivateKey{d: hex_to_int(exp["priv_key_tweak"])},
          nil
        )

      assert Point.x_hex(PrivateKey.to_point(d)) == exp["pub_key"],
             "spend pubkey mismatch :: #{comment}"

      if sig = exp["signature"] do
        {:ok, signature} = Schnorr.sign(d, hash_int("message"), hash_int("random auxiliary data"))

        assert Signature.to_hex(signature) == sig,
               "signature mismatch for #{exp["pub_key"]} :: #{comment}"
      end
    end
  end

  # ------------------------------------------- BIP-352 input pubkey extraction

  # Returns {:taproot, xonly} | {:other, Point.t()} | :skip
  def extract_pubkey(vin) do
    spk = decode_hex(get_in(vin, ["prevout", "scriptPubKey", "hex"]))
    do_extract(spk, decode_hex(vin["scriptSig"]), parse_witness(vin["txinwitness"]))
  end

  # P2PKH: parse the (possibly malleated) scriptSig for the pubkey whose hash160 matches the spk.
  defp do_extract(<<0x76, 0xA9, 0x14, hash::binary-size(20), 0x88, 0xAC>>, script_sig, _witness) do
    case scan_p2pkh(script_sig, hash) do
      %Point{} = p -> {:other, p}
      nil -> :skip
    end
  end

  # P2SH: eligible only if it wraps P2WPKH (scriptSig is a push of `0014<20>`); pubkey from witness.
  # Note: like the BIP-352 reference, this does not verify hash160(redeemScript) == the scriptPubKey
  # hash, nor that the redeem key-hash matches the witness key — sufficient for the vectors (invalid
  # P2SH inputs are filtered by the scriptSig shape and the compressed-key check), but a real scanner
  # validating untrusted inputs should also check those hashes.
  defp do_extract(<<0xA9, 0x14, _h::binary-size(20), 0x87>>, script_sig, witness) do
    case script_sig do
      <<_len, 0x00, 0x14, _kh::binary-size(20)>> -> pubkey_from_witness(witness)
      _ -> :skip
    end
  end

  # P2WPKH: pubkey is the last witness item (must be compressed).
  defp do_extract(<<0x00, 0x14, _h::binary-size(20)>>, _script_sig, witness) do
    pubkey_from_witness(witness)
  end

  # P2TR: use the x-only output key, unless it is a script-path spend with internal key = NUMS_H.
  defp do_extract(<<0x51, 0x20, xonly::binary-size(32)>>, _script_sig, witness) do
    stack = strip_annex(witness)

    case stack do
      [_, _ | _] ->
        if nums_h_internal_key?(List.last(stack)), do: :skip, else: {:taproot, xonly}

      _ ->
        {:taproot, xonly}
    end
  end

  defp do_extract(_spk, _script_sig, _witness), do: :skip

  defp nums_h_internal_key?(<<_control, internal_key::binary-size(32), _rest::binary>>),
    do: :binary.decode_unsigned(internal_key) == @nums_h

  defp nums_h_internal_key?(_), do: false

  defp strip_annex([_ | _] = stack) when length(stack) > 1 do
    case List.last(stack) do
      <<0x50, _::binary>> -> Enum.drop(stack, -1)
      _ -> stack
    end
  end

  defp strip_annex(stack), do: stack

  # Scan a scriptSig backwards with a 33-byte window for the compressed pubkey matching spk_hash.
  defp scan_p2pkh(script_sig, spk_hash) when byte_size(script_sig) >= 33 do
    size = byte_size(script_sig)

    Enum.find_value(size..33//-1, fn i ->
      window = :binary.part(script_sig, i - 33, 33)

      case window do
        <<p, _::binary-size(32)>> when p in [0x02, 0x03] ->
          if Utils.hash160(window) == spk_hash do
            case Point.parse_public_key(window) do
              {:ok, point} -> point
              _ -> nil
            end
          end

        _ ->
          nil
      end
    end)
  end

  defp scan_p2pkh(_script_sig, _spk_hash), do: nil

  defp pubkey_from_witness([]), do: :skip

  defp pubkey_from_witness(witness) do
    case List.last(witness) do
      <<p, _::binary-size(32)>> = compressed when p in [0x02, 0x03] ->
        case Point.parse_public_key(compressed) do
          {:ok, point} -> {:other, point}
          _ -> :skip
        end

      _ ->
        :skip
    end
  end

  # ------------------------------------------------------------------ helpers

  defp eligible_pubkey_hex({:taproot, xonly}) do
    {:ok, p} = Point.lift_x(xonly)
    Point.serialize_public_key(p)
  end

  defp eligible_pubkey_hex({:other, point}), do: Point.serialize_public_key(point)

  defp expand_recipients(recipients) do
    Enum.flat_map(recipients, fn r -> List.duplicate(r, r["count"] || 1) end)
  end

  defp precompute_labels(b_scan, labels) do
    Enum.map(labels, fn m ->
      {:ok, label_point} = SilentPayments.label_point(b_scan, m)
      {:ok, label_tweak} = SilentPayments.label_tweak(b_scan, m)
      {label_point, label_tweak}
    end)
  end

  defp expected_count(expected), do: expected["n_outputs"] || length(expected["outputs"] || [])

  defp smallest_outpoint(vins), do: vins |> Enum.map(&outpoint/1) |> Enum.min()

  defp outpoint(vin) do
    txid_le =
      vin["txid"]
      |> decode_hex()
      |> :binary.bin_to_list()
      |> Enum.reverse()
      |> :binary.list_to_bin()

    txid_le <> <<vin["vout"]::little-size(32)>>
  end

  defp parse_witness(nil), do: []
  defp parse_witness(""), do: []

  defp parse_witness(hex) do
    case Base.decode16(hex, case: :lower) do
      {:ok, <<>>} -> []
      {:ok, bin} -> bin |> compact_size() |> then(fn {n, rest} -> parse_items(rest, n, []) end)
      :error -> []
    end
  end

  defp parse_items(_bin, 0, acc), do: Enum.reverse(acc)

  defp parse_items(bin, n, acc) do
    {len, rest} = compact_size(bin)
    <<item::binary-size(len), rest2::binary>> = rest
    parse_items(rest2, n - 1, [item | acc])
  end

  defp compact_size(<<0xFD, v::little-size(16), rest::binary>>), do: {v, rest}
  defp compact_size(<<0xFE, v::little-size(32), rest::binary>>), do: {v, rest}
  defp compact_size(<<0xFF, v::little-size(64), rest::binary>>), do: {v, rest}
  defp compact_size(<<v, rest::binary>>), do: {v, rest}

  defp privkey(hex), do: %PrivateKey{d: hex_to_int(hex)}
  defp hex_to_int(hex), do: hex |> Base.decode16!(case: :lower) |> :binary.decode_unsigned()

  defp point(hex) do
    {:ok, p} = Point.parse_public_key(Base.decode16!(hex, case: :lower))
    p
  end

  defp decode_hex(nil), do: <<>>
  defp decode_hex(hex), do: Base.decode16!(hex, case: :lower)

  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp hash_int(s), do: :crypto.hash(:sha256, s) |> :binary.decode_unsigned()
end

defmodule Bitcoinex.SilentPaymentsVectorsTest do
  use ExUnit.Case, async: true

  alias Bitcoinex.SilentPaymentsVectorHarness, as: H

  @vectors_path Path.join(__DIR__, "data/bip0352_send_and_receive_test_vectors.json")
  @external_resource @vectors_path
  @cases @vectors_path |> File.read!() |> Jason.decode!()

  test "loaded the full BIP-352 vector set" do
    assert length(@cases) == 28
  end

  for {tcase, idx} <- Enum.with_index(@cases) do
    @tcase tcase

    test "##{idx} #{tcase["comment"]} :: sending" do
      H.run_sending(@tcase)
    end

    test "##{idx} #{tcase["comment"]} :: receiving" do
      H.run_receiving(@tcase)
    end
  end
end
