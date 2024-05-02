defmodule Bitcoinex.AddressTest do
  use ExUnit.Case
  doctest Bitcoinex.Address

  alias Bitcoinex.Address

  describe "is_valid?/1" do
    setup do
      valid_mainnet_p2pkh_addresses = [
        "12KYrjTdVGjFMtaxERSk3gphreJ5US8aUP",
        "12QeMLzSrB8XH8FvEzPMVoRxVAzTr5XM2y",
        "17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem",
        "1oNLrsHnBcR6dpaBpwz3LSwutbUNkNSjs"
      ]

      valid_testnet_p2pkh_addresses = [
        "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
      ]

      valid_mainnet_p2sh_addresses = [
        "3NJZLcZEEYBpxYEUGewU4knsQRn1WM5Fkt"
      ]

      valid_testnet_p2sh_addresses = [
        "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc"
      ]

      valid_mainnet_segwit_addresses = [
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
      ]

      valid_testnet_segwit_addresses = [
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"
      ]

      valid_regtest_segwit_addresses = [
        "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
        "bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7"
      ]

      valid_mainnet_p2wpkh_addresses = [
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
      ]

      valid_testnet_p2wpkh_addresses = [
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
      ]

      valid_mainnet_p2wsh_addresses = [
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
      ]

      valid_testnet_p2wsh_addresses = [
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
      ]

      valid_mainnet_p2tr_addresses = [
        "bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9e",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
      ]

      valid_testnet_p2tr_addresses = [
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
      ]

      valid_mainnet_addresses =
        valid_mainnet_p2pkh_addresses ++
          valid_mainnet_p2sh_addresses ++
          valid_mainnet_segwit_addresses ++
          valid_mainnet_p2wpkh_addresses ++
          valid_mainnet_p2wsh_addresses ++
          valid_mainnet_p2tr_addresses

      valid_testnet_addresses =
        valid_testnet_p2pkh_addresses ++
          valid_testnet_p2sh_addresses ++
          valid_testnet_segwit_addresses ++
          valid_testnet_p2wpkh_addresses ++
          valid_testnet_p2wsh_addresses ++
          valid_testnet_p2tr_addresses

      valid_regtest_addresses =
        valid_testnet_p2pkh_addresses ++
          valid_testnet_p2sh_addresses ++ valid_regtest_segwit_addresses

      invalid_addresses = [
        # witness v1 address using bech32 (not bech32m) encoding
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        "BC1SW50QA3JX3S",
        "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        "",
        "rrRmhfXzGBKbV4YHtbpxfA1ftEcry8AJaX",
        "LSxNsEQekEpXMS4B7tUYstMEdMyH321ZQ1",
        "rrRmhfXzGBKbV4YHtbpxfA1ftEcry8AJaX",
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
        "bc1rw5uspcuh",
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "bc1gmk9yu",
        # p2tr addresses
        "bc1pqyqszqgpqyqszqgpqyqszqppgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9e",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfpphlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc1pqyqszqgpqyqszqgpqyqszgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9e",
        "bc1p0xlxvlhemja6c4dqv22uapctquphlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9f",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1"
      ]

      {:ok,
       valid_mainnet_addresses: valid_mainnet_addresses,
       valid_testnet_addresses: valid_testnet_addresses,
       valid_regtest_addresses: valid_regtest_addresses,
       valid_mainnet_p2pkh_addresses: valid_mainnet_p2pkh_addresses,
       valid_testnet_p2pkh_addresses: valid_testnet_p2pkh_addresses,
       valid_mainnet_p2sh_addresses: valid_mainnet_p2sh_addresses,
       valid_testnet_p2sh_addresses: valid_testnet_p2sh_addresses,
       valid_mainnet_segwit_addresses: valid_mainnet_segwit_addresses,
       valid_testnet_segwit_addresses: valid_testnet_segwit_addresses,
       valid_regtest_segwit_addresses: valid_regtest_segwit_addresses,
       valid_mainnet_p2wpkh_addresses: valid_mainnet_p2wpkh_addresses,
       valid_testnet_p2wpkh_addresses: valid_testnet_p2wpkh_addresses,
       valid_mainnet_p2wsh_addresses: valid_mainnet_p2wsh_addresses,
       valid_testnet_p2wsh_addresses: valid_testnet_p2wsh_addresses,
       valid_mainnet_p2tr_addresses: valid_mainnet_p2tr_addresses,
       valid_testnet_p2tr_addresses: valid_testnet_p2tr_addresses,
       invalid_addresses: invalid_addresses}
    end

    test "return true when the address is valid address either p2sh, p2pkh, pwsh, p2wpkh, p2tr",
         %{
           valid_mainnet_p2pkh_addresses: valid_mainnet_p2pkh_addresses,
           valid_mainnet_p2sh_addresses: valid_mainnet_p2sh_addresses,
           valid_mainnet_segwit_addresses: valid_mainnet_segwit_addresses,
           valid_mainnet_p2tr_addresses: valid_mainnet_p2tr_addresses
         } do
      all_valid_addresses =
        valid_mainnet_p2sh_addresses ++
          valid_mainnet_p2pkh_addresses ++
          valid_mainnet_segwit_addresses ++ valid_mainnet_p2tr_addresses

      for valid_address <- all_valid_addresses do
        assert Address.is_valid?(valid_address, :mainnet)
      end
    end

    test "return false when the address is valid address either p2sh, p2pkh, pwsh, p2wpkh but not in correct network",
         %{
           valid_testnet_segwit_addresses: valid_testnet_segwit_addresses,
           valid_testnet_p2pkh_addresses: valid_testnet_p2pkh_addresses,
           valid_testnet_p2sh_addresses: valid_testnet_p2sh_addresses,
           valid_regtest_segwit_addresses: valid_regtest_segwit_addresses,
           valid_testnet_p2tr_addresses: valid_testnet_p2tr_addresses
         } do
      all_valid_testnet_addresses =
        valid_testnet_segwit_addresses ++
          valid_testnet_p2pkh_addresses ++
          valid_testnet_p2sh_addresses ++
          valid_regtest_segwit_addresses ++
          valid_testnet_p2tr_addresses

      for valid_testnet_address <- all_valid_testnet_addresses do
        refute Address.is_valid?(valid_testnet_address, :mainnet)
      end
    end

    test "return false when the address is not valid address either p2sh, p2pkh, pwsh, p2wpkh, p2tr",
         %{
           invalid_addresses: invalid_addresses
         } do
      all_invalid_addresses = invalid_addresses

      for invalid_address <- all_invalid_addresses do
        for %{name: network_name} <- Bitcoinex.Network.supported_networks() do
          for address_type <- Bitcoinex.Address.supported_address_types() do
            refute Address.is_valid?(invalid_address, network_name, address_type)
          end
        end
      end
    end

    test "check that the address decodes to the correct address type", %{
      valid_mainnet_p2pkh_addresses: valid_mainnet_p2pkh_addresses,
      valid_testnet_p2pkh_addresses: valid_testnet_p2pkh_addresses,
      valid_mainnet_p2sh_addresses: valid_mainnet_p2sh_addresses,
      valid_testnet_p2sh_addresses: valid_testnet_p2sh_addresses,
      valid_mainnet_p2wpkh_addresses: valid_mainnet_p2wpkh_addresses,
      valid_testnet_p2wpkh_addresses: valid_testnet_p2wpkh_addresses,
      valid_mainnet_p2wsh_addresses: valid_mainnet_p2wsh_addresses,
      valid_testnet_p2wsh_addresses: valid_testnet_p2wsh_addresses,
      valid_mainnet_p2tr_addresses: valid_mainnet_p2tr_addresses,
      valid_testnet_p2tr_addresses: valid_testnet_p2tr_addresses
    } do
      for mainnet_p2pkh <- valid_mainnet_p2pkh_addresses do
        assert Address.decode_type(mainnet_p2pkh, :mainnet) == {:ok, :p2pkh}
      end

      for testnet_p2pkh <- valid_testnet_p2pkh_addresses do
        assert Address.decode_type(testnet_p2pkh, :testnet) == {:ok, :p2pkh}
      end

      for mainnet_p2sh <- valid_mainnet_p2sh_addresses do
        assert Address.decode_type(mainnet_p2sh, :mainnet) == {:ok, :p2sh}
      end

      for testnet_p2sh <- valid_testnet_p2sh_addresses do
        assert Address.decode_type(testnet_p2sh, :testnet) == {:ok, :p2sh}
      end

      for mainnet_p2wpkh <- valid_mainnet_p2wpkh_addresses do
        assert Address.decode_type(mainnet_p2wpkh, :mainnet) == {:ok, :p2wpkh}
      end

      for testnet_p2wpkh <- valid_testnet_p2wpkh_addresses do
        assert Address.decode_type(testnet_p2wpkh, :testnet) == {:ok, :p2wpkh}
      end

      for mainnet_p2wsh <- valid_mainnet_p2wsh_addresses do
        assert Address.decode_type(mainnet_p2wsh, :mainnet) == {:ok, :p2wsh}
      end

      for testnet_p2wsh <- valid_testnet_p2wsh_addresses do
        assert Address.decode_type(testnet_p2wsh, :testnet) == {:ok, :p2wsh}
      end

      for mainnet_p2tr <- valid_mainnet_p2tr_addresses do
        assert Address.decode_type(mainnet_p2tr, :mainnet) == {:ok, :p2tr}
      end

      for testnet_p2tr <- valid_testnet_p2tr_addresses do
        assert Address.decode_type(testnet_p2tr, :testnet) == {:ok, :p2tr}
      end
    end
  end

  describe "encode/3" do
    test "return true for encoding p2pkh" do
      pubkey_hash = Base.decode16!("6dcd022b3c5e6439238eb333ec1d6ddd1973b5ba", case: :lower)
      assert "1B1aF9aUzxqgEviiCSe9u339hpUWLVWfxu" == Address.encode(pubkey_hash, :mainnet, :p2pkh)
    end

    test "return true for encoding p2sh" do
      script_hash = Base.decode16!("6d77fa9de297e9c536c6b23cfda1a8450bb5f765", case: :lower)
      assert "3BfqJjn7H2jsbKd2NVHGP4sQWQ2bQWBRLv" == Address.encode(script_hash, :mainnet, :p2sh)
    end

    test "return true for encoding p2wpkh" do
      script_hash = "751e76e8199196d454941c45d1b3a323f1433bd6"

      script_hash = Base.decode16!(script_hash, case: :lower)

      assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" ==
               Address.encode(script_hash, :mainnet, :p2wpkh)
    end
  end
end
