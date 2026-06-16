defmodule Bitcoinex.SilentPaymentsAddressTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Bitcoinex.{Bech32, SilentPayments}
  alias Bitcoinex.Secp256k1.{Point, PrivateKey}

  # BIP-352 "Simple send" recipient address and its contained keys.
  @addr "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
  @scan_pub "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4"
  @spend_pub "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36"

  defp point(hex) do
    {:ok, p} = Point.parse_public_key(Base.decode16!(hex, case: :lower))
    p
  end

  defp payload_66, do: Base.decode16!(@scan_pub <> @spend_pub, case: :lower)

  # Encode an SP-style address with an arbitrary version byte and payload (for version rules).
  defp encode_versioned(version, payload) do
    {:ok, data} = Bech32.convert_bits(:binary.bin_to_list(payload), 8, 5)
    {:ok, addr} = Bech32.encode("sp", [version | data], :bech32m, :infinity)
    addr
  end

  describe "decode_address/1" do
    test "decodes a BIP-352 mainnet address into {network, version, B_scan, B_m}" do
      assert {:ok, {:mainnet, 0, b_scan, b_m}} = SilentPayments.decode_address(@addr)
      assert Point.serialize_public_key(b_scan) == @scan_pub
      assert Point.serialize_public_key(b_m) == @spend_pub
    end

    test "rejects a non-bech32m (bech32) encoding" do
      assert {:error, _} =
               SilentPayments.decode_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    end

    test "rejects an unrecognized HRP" do
      bogus = encode_versioned(0, payload_66()) |> String.replace_prefix("sp1", "zz1")
      # checksum no longer valid after HRP swap, but either way it must error
      assert {:error, _} = SilentPayments.decode_address(bogus)
    end

    test "rejects malformed input" do
      assert {:error, _} = SilentPayments.decode_address("definitely not an address")
    end

    test "returns error (does not raise) for a valid-checksum address with a bad SEC prefix" do
      # 66-byte payload whose B_scan starts with 0x00 (not a valid 0x02/0x03 compressed key).
      bad_payload = <<0x00>> <> :binary.copy(<<0x07>>, 65)
      assert {:error, _} = SilentPayments.decode_address(encode_versioned(0, bad_payload))
    end
  end

  describe "encode_address/3" do
    test "round-trips the vector address (mainnet)" do
      {:ok, {_, _, b_scan, b_m}} = SilentPayments.decode_address(@addr)
      assert SilentPayments.encode_address(b_scan, b_m, :mainnet) == {:ok, @addr}
    end

    test "uses the sp HRP for mainnet and tsp for testnet/regtest" do
      b_scan = point(@scan_pub)
      b_m = point(@spend_pub)

      assert {:ok, "sp1q" <> _} = SilentPayments.encode_address(b_scan, b_m, :mainnet)
      assert {:ok, "tsp1q" <> _} = SilentPayments.encode_address(b_scan, b_m, :testnet)
      assert {:ok, "tsp1q" <> _} = SilentPayments.encode_address(b_scan, b_m, :regtest)
    end

    test "rejects an unsupported network" do
      assert {:error, _} =
               SilentPayments.encode_address(point(@scan_pub), point(@spend_pub), :bogus)
    end
  end

  describe "version rules" do
    test "v0 with a non-66-byte payload is rejected" do
      assert {:error, _} =
               SilentPayments.decode_address(
                 encode_versioned(0, binary_part(payload_66(), 0, 65))
               )
    end

    test "v1 with a 66-byte payload decodes and reports version 1" do
      assert {:ok, {:mainnet, 1, b_scan, b_m}} =
               SilentPayments.decode_address(encode_versioned(1, payload_66()))

      assert Point.serialize_public_key(b_scan) == @scan_pub
      assert Point.serialize_public_key(b_m) == @spend_pub
    end

    test "v1-v30 with extra payload bytes reads only the first 66" do
      padded = payload_66() <> <<0xAB, 0xCD, 0xEF>>

      assert {:ok, {:mainnet, 5, b_scan, b_m}} =
               SilentPayments.decode_address(encode_versioned(5, padded))

      assert Point.serialize_public_key(b_scan) == @scan_pub
      assert Point.serialize_public_key(b_m) == @spend_pub
    end

    test "v31 is rejected" do
      assert {:error, _} = SilentPayments.decode_address(encode_versioned(31, payload_66()))
    end
  end

  property "encode/decode round-trips for any points and network" do
    check all(
            scan_d <- StreamData.integer(1..100_000),
            spend_d <- StreamData.integer(1..100_000),
            network <- StreamData.member_of([:mainnet, :testnet, :regtest]),
            max_runs: 40
          ) do
      b_scan = PrivateKey.to_point(%PrivateKey{d: scan_d})
      b_m = PrivateKey.to_point(%PrivateKey{d: spend_d})

      {:ok, addr} = SilentPayments.encode_address(b_scan, b_m, network)
      {:ok, {net, version, decoded_scan, decoded_m}} = SilentPayments.decode_address(addr)

      assert version == 0
      assert net == if(network == :mainnet, do: :mainnet, else: :testnet)
      assert {decoded_scan.x, decoded_scan.y} == {b_scan.x, b_scan.y}
      assert {decoded_m.x, decoded_m.y} == {b_m.x, b_m.y}
    end
  end
end
