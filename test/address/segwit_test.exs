defmodule Bitcoinex.Address.SegwitTest do
  use ExUnit.Case
  doctest Bitcoinex.Address.Segwit

  alias Bitcoinex.Address.Segwit
  import Bitcoinex.Utils, only: [replicate: 2]

  @valid_segwit_address_hexscript_pairs_mainnet [
    {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
     "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
    {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
    {"BC1SW50QA3JX3S", "6002751e"},
    {"bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"}
  ]

  @valid_segwit_address_hexscript_pairs_testnet [
    {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
    {"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"}
  ]

  @valid_segwit_address_hexscript_pairs_regtest [
    {"bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
    {"bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7",
     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"}
  ]

  @invalid_segwit_addresses [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu"
  ]

  describe "decode/1" do
    test "successfully decode with valid segwit addresses in mainnet" do
      for {address, hexscript} <- @valid_segwit_address_hexscript_pairs_mainnet do
        assert_valid_segwit_address(address, hexscript, :mainnet)
      end
    end

    test "successfully decode with valid segwit addresses in testnet" do
      for {address, hexscript} <- @valid_segwit_address_hexscript_pairs_testnet do
        assert_valid_segwit_address(address, hexscript, :testnet)
      end
    end

    test "successfully decode with valid segwit addresses in regtest" do
      for {address, hexscript} <- @valid_segwit_address_hexscript_pairs_regtest do
        assert_valid_segwit_address(address, hexscript, :regtest)
      end
    end

    test "fail to decode with invalid address" do
      for address <- @invalid_segwit_addresses do
        assert {:error, _error} = Segwit.decode_address(address)
      end
    end
  end

  describe "encode_address/1" do
    test "successfully encode with valid netwrok, version and program " do
      version = 1
      program = replicate(1, 10)
      assert {:ok, mainnet_address} = Segwit.encode_address(:mainnet, version, program)
      assert {:ok, testnet_address} = Segwit.encode_address(:testnet, version, program)
      assert {:ok, regtest_address} = Segwit.encode_address(:regtest, version, program)
      all_addresses = [mainnet_address, testnet_address, regtest_address]
      # make sure they are different
      assert Enum.uniq(all_addresses) == all_addresses
    end

    test "fail to encode with program length > 40 " do
      assert {:error, _error} = Segwit.encode_address(:mainnet, 1, replicate(1, 41))
    end

    test "fail to encode with version 0 but program length not equalt to 20 or 32 " do
      assert {:ok, _address} = Segwit.encode_address(:mainnet, 0, replicate(1, 20))
      assert {:ok, _address} = Segwit.encode_address(:mainnet, 0, replicate(1, 32))
      assert {:error, _error} = Segwit.encode_address(:mainnet, 0, replicate(1, 21))
      assert {:error, _error} = Segwit.encode_address(:mainnet, 0, replicate(1, 33))
    end
  end

  # local private test helper
  defp assert_valid_segwit_address(address, hexscript, network) do
    assert {:ok, {hrp, version, program}} = Segwit.decode_address(address)
    assert hrp == network
    assert version in 0..16
    assert Segwit.get_segwit_script_pubkey(version, program) == hexscript

    # encode after decode should be the same(after downcase) as before
    {:ok, new_address} = Segwit.encode_address(hrp, version, program)
    assert new_address == String.downcase(address)
  end
end
