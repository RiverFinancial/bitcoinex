defmodule Bitcoinex.ScriptTest do
  use ExUnit.Case
  doctest Bitcoinex.Script

  alias Bitcoinex.{Script, Utils}
  alias Bitcoinex.Secp256k1.Point

  @raw_multisig_scripts [
    "522103a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af957521036ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640d210311ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef53ae",
    # from testnet tx: c7d1582d4cf85fbd10732002c5bb06068d4b86cfd5cca151ef88104c6702435a
    "52210265e6f7fb614a369c9230912a3bb09c33c5c5be2e1bcfc2293ecaed46708e0b5c2103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b6432102908375f301c7ea583f7e113939eab1164abda4ac27898b1cf78abf1c82f02da953ae",
    # from tx: 336b9de8941d945a41f9d982eaadb344b3457d22edf43a1aaec29252a58e6566
    "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    # from tx: 578e8ab81e6eff430fd37eaa460377387d75f0221881fe13cf9e5b400d98b0e3
    "52210353d36c27d345e0cda30800d769dbf239b16d19e0a28821c092ad277f1ae569f121034e2c48afb6d9cd6446442eeb6867a7787f16d28758b88ec99fa178d941930c6b2103142776b8982a94855686f175a31edbdc48336741e08b07c4cad5bc6852f6197353ae",
    "522103af40079dabd57915a41fc676c9a1e8e9278b9aa7e3b2cf7db63435e357bd589521024a84c829eb98eb69b37be6adcdc206b462b4c9549a0db2dbc91279a2f031a50a2102a5264fbc1be9b9a7d03d9637a5534ce8d59a06c4c1f30802fe52e7bf6c1dd97153ae"
  ]

  @raw_multisigs_with_data [
    # from testnet tx: c7d1582d4cf85fbd10732002c5bb06068d4b86cfd5cca151ef88104c6702435a
    %{
      script_hex:
        "52210265e6f7fb614a369c9230912a3bb09c33c5c5be2e1bcfc2293ecaed46708e0b5c2103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b6432102908375f301c7ea583f7e113939eab1164abda4ac27898b1cf78abf1c82f02da953ae",
      network: :testnet,
      wsh_addr: "",
      sh_addr: "2NFhEhTAiXJ8z8yEYnXe6SJX5E8bRgB5ZgY"
    },
    # from tx: 336b9de8941d945a41f9d982eaadb344b3457d22edf43a1aaec29252a58e6566
    %{
      script_hex:
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
      network: :mainnet,
      wsh_addr: "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
      sh_addr: ""
    },
    # from tx: 578e8ab81e6eff430fd37eaa460377387d75f0221881fe13cf9e5b400d98b0e3
    %{
      script_hex:
        "52210353d36c27d345e0cda30800d769dbf239b16d19e0a28821c092ad277f1ae569f121034e2c48afb6d9cd6446442eeb6867a7787f16d28758b88ec99fa178d941930c6b2103142776b8982a94855686f175a31edbdc48336741e08b07c4cad5bc6852f6197353ae",
      network: :mainnet,
      wsh_addr: "bc1q95wu94w9a08yzed4vc4v9z8v3zndltmgurkh893uy2qdk0lacneqawrq36",
      sh_addr: ""
    },
    # from tx: 578e8ab81e6eff430fd37eaa460377387d75f0221881fe13cf9e5b400d98b0e3
    %{
      script_hex:
        "522103af40079dabd57915a41fc676c9a1e8e9278b9aa7e3b2cf7db63435e357bd589521024a84c829eb98eb69b37be6adcdc206b462b4c9549a0db2dbc91279a2f031a50a2102a5264fbc1be9b9a7d03d9637a5534ce8d59a06c4c1f30802fe52e7bf6c1dd97153ae",
      network: :mainnet,
      wsh_addr: "bc1qamfphjerjc4jdmmnwku26x8e49m2455x65kldefw79j6j24fya9sy5r9jg",
      sh_addr: ""
    }
  ]

  @p2pk_scripts [
    # from tx df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    # from tx 2d05f0c9c3e1c226e63b5fac240137687544cf631cd616fd34fd188fc9020866
    "4104e70a02f5af48a1989bf630d92523c9d14c45c75f7d1b998e962bff6ff9995fc5bdb44f1793b37495d80324acba7c8f537caaf8432b8d47987313060cc82d8a93ac",
    # from tx da69323ec33972675d9594b6569983bfc2257bced36d8df541a2aadfe31db016
    "21035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344ac"
  ]

  @p2sh_scripts [
    # from tx db11e3569da3583f3001514163b5f1c4e0556dd550bfa4518f15095258d43bf3
    "a9148a7810adbe753308a8ccae63f81841c92554174487",
    # from tx 6dd1763922d5bf62a90d61b4dc1bce41df3f2dd599cbd94b5a75264b3dd2c7b2
    "a9148b56848ee759ae7370ca2af7d4d244db2dd3de6b87",
    "a9140549064a44f4864730c5f80495b062478cd6e68587"
  ]

  @p2pkh_scripts [
    # from tx 0a6140bbf75e73f11b90c4dabf71f83394d493d635c2bbf19d207fb821de74f5
    "76a91408be653b5582bb9c1b85ab1da70906946c90acc588ac",
    # from tx be626ca78e84876dec63622f9de36264925d8390fbaae65948bf459c623ede7f
    "76a9140609f52a6954adfdc13ecbcf07713c5a12aee8f988ac",
    "76a91491c9753821600b37ced3d0b04de88cd2cea06c2588ac",
    # from tx 6dd1763922d5bf62a90d61b4dc1bce41df3f2dd599cbd94b5a75264b3dd2c7b2
    "76a9146c25434c537c6e69fa3ebf4ea47f00b5e3e1d6b988ac"
  ]

  @p2wpkh_scripts [
    # from tx 16940cf0fd17da81f47fbae29a6e1eaad844fd45e772292022d0f066db43f007
    "00146756d75cc116c710bdfa4cbc12dd3f9629d5d61f",
    # from tx 0176631c41a73cf1391822a9dc50a3719e96c33f4f2e51e7f9ea65afd87781b6
    "00140d3953d2b732f7a293e3c4dc2b6b309f71b9c692",
    # from tx 6dd1763922d5bf62a90d61b4dc1bce41df3f2dd599cbd94b5a75264b3dd2c7b2
    "0014c944072f05f3dadf417c90f3f19c3b784562b116"
  ]

  @p2wsh_scripts [
    # from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
    "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
    # from tx c561120cdbe161186a3264aeda32ee964e4615a0831bbd204dd36ff9460d6af7
    "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
  ]

  # from
  # https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors-for-v0-v16-native-segregated-witness-addresses
  @bip350_test_vectors [
    %{
      b32: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
      hex: "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      net: :mainnet
    },
    %{
      b32: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
      hex: "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      net: :testnet
    },
    %{
      b32: "bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9e",
      hex: "51200101010101010101010101010101010101010101010101010101010101010101",
      net: :mainnet
    },
    %{
      b32: "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
      hex: "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      net: :testnet
    },
    %{
      b32: "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
      hex: "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      net: :testnet
    },
    %{
      b32: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
      hex: "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      net: :mainnet
    }
  ]

  @bip_350_invalid_test_vectors [
    # Invalid human-readable part
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    # Invalid checksum (Bech32 instead of Bech32m)
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    # Invalid checksum (Bech32 instead of Bech32m)
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    # Invalid checksum (Bech32 instead of Bech32m)
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    # Invalid checksum (Bech32m instead of Bech32)
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    # Invalid checksum (Bech32m instead of Bech32)
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    # Invalid character in checksum
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    # Invalid witness version
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    # Invalid program length (1 byte)
    "bc1pw5dgrnzv",
    # Invalid program length (41 bytes)
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    # Invalid program length for witness version 0 (per BIP141)
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    # Mixed case
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    # zero padding of more than 4 bits
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    # Non-zero padding in 8-to-5 conversion
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    # Empty data section
    "bc1gmk9yu"
  ]

  describe "test basics functions" do
    test "test new/0 and empty?/1" do
      s = Script.new()
      assert Script.empty?(s)

      {:ok, s} = Script.push_op(s, :op_true)
      assert !Script.empty?(s)
    end

    test "test script_length/1 and byte_length/1" do
      s = Script.new()
      assert Script.script_length(s) == 0
      assert Script.byte_length(s) == 0

      {:ok, s} = Script.push_op(s, :op_true)
      assert Script.script_length(s) == 1
      assert Script.byte_length(s) == 1

      {:ok, s} = Script.push_data(s, <<1, 1, 1, 1>>)
      assert Script.script_length(s) == 3
      assert Script.byte_length(s) == 6

      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)
      assert Script.script_length(s) == 3
      assert Script.byte_length(s) == 34

      s_hex = "0014a38e224fc2ead8f32b13e3cef6bbf3520f16378c"
      {:ok, s} = Script.parse_script(s_hex)
      assert Script.script_length(s) == 3
      assert Script.byte_length(s) == 22

      s_hex =
        "4de901c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      {:ok, s} = Script.parse_script(s_hex)
      assert Script.script_length(s) == 2
      assert Script.byte_length(s) == 492

      s_hex =
        "a94c50c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1ac"

      {:ok, s} = Script.parse_script(s_hex)
      assert Script.script_length(s) == 4
      assert Script.byte_length(s) == 84
    end

    test "test get_op_num/1 and get_op_atom/1" do
      assert {:ok, 0x00} == Script.get_op_num(:op_0)
      assert {:ok, 0x60} == Script.get_op_num(:op_16)
      assert {:ok, 0xFE} == Script.get_op_num(:op_pubkey)
      assert :error == Script.get_op_num(:op_eval)

      assert {:ok, :op_0} == Script.get_op_atom(0x00)
      assert {:ok, :op_pushdata1} == Script.get_op_atom(0x4C)
      assert {:ok, :op_invalidopcode} == Script.get_op_atom(0xFF)
      assert {:ok, :op_nop1} == Script.get_op_atom(0xB0)

      assert 5 == Script.get_op_atom(5)
      assert 75 == Script.get_op_atom(75)
      assert :error == Script.get_op_atom(-1)
    end

    test "test pop/1" do
      s = Script.new()
      assert Script.pop(s) == nil

      {:ok, s} = Script.push_op(s, :op_true)
      {:ok, 81, s1} = Script.pop(s)
      assert Script.empty?(s1)

      {:ok, s} = Script.push_data(s1, <<1, 1, 1, 1, 1, 1, 1>>)
      {:ok, 7, s1} = Script.pop(s)
      {:ok, <<1, 1, 1, 1, 1, 1, 1>>, s2} = Script.pop(s1)
      assert Script.pop(s2) == nil
    end
  end

  describe "test push_op/2" do
    test "test pushing and popping ops by atom" do
      s = Script.new()

      {:ok, s} = Script.push_op(s, :op_true)
      {:ok, s} = Script.push_op(s, :op_false)
      {:ok, s} = Script.push_op(s, :op_checksig)

      assert Script.script_length(s) == 3
      assert Script.byte_length(s) == 3

      {:ok, o1, s1} = Script.pop(s)
      {:ok, o2, s2} = Script.pop(s1)
      {:ok, o3, s3} = Script.pop(s2)

      # checksig
      assert o1 == 0xAC
      # false
      assert o2 == 0x00
      # true
      assert o3 == 0x51
      # empty
      assert Script.empty?(s3)
    end

    test "test pushing and popping ops by integer" do
      s = Script.new()
      # true
      {:ok, s} = Script.push_op(s, 0x51)
      # false
      {:ok, s} = Script.push_op(s, 0x00)
      # checksig
      {:ok, s} = Script.push_op(s, 0xAC)

      assert Script.script_length(s) == 3
      assert Script.byte_length(s) == 3

      {:ok, o1, s1} = Script.pop(s)
      {:ok, o2, s2} = Script.pop(s1)
      {:ok, o3, _s3} = Script.pop(s2)

      assert o1 == 0xAC
      assert o2 == 0x00
      assert o3 == 0x51
    end
  end

  describe "push_data/2" do
    test "push public key" do
      s = Script.new()
      hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      bin = Base.decode16!(hex, case: :lower)
      {:ok, s} = Script.push_data(s, bin)
      {:ok, len, s2} = Script.pop(s)
      {:ok, pk, _s3} = Script.pop(s2)

      assert len == 33
      assert pk == bin
    end

    test "push pubkey hash" do
      s = Script.new()
      hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
      bin = Base.decode16!(hex, case: :lower)
      Script.push_data(s, bin)
    end

    test "push data 1" do
      s = Script.new()

      hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      bin = Utils.hex_to_bin(hex)
      {:ok, s} = Script.push_data(s, bin)

      {:ok, op2, s1} = Script.pop(s)
      {:ok, bin2, _s2} = Script.pop(s1)

      assert op2 == 76
      assert bin2 == bin
    end

    test "push data 2" do
      s = Script.new()

      hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      bin = Utils.hex_to_bin(hex)
      {:ok, s} = Script.push_data(s, bin)

      {:ok, op2, s1} = Script.pop(s)
      {:ok, bin2, _s2} = Script.pop(s1)

      assert op2 == 77
      assert bin2 == bin
    end
  end

  describe "test specific script creation and identification" do
    test "test parse p2pk from uncompressed key" do
      s = Script.new()
      # from tx df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a
      hex =
        "04184f32b212815c6e522e66686324030ff7e5bf08efb21f8b00614fb7690e19131dd31304c54f37baa40db231c918106bb9fd43373e37ae31a0befc6ecaefb867"

      bin = Base.decode16!(hex, case: :lower)
      {:ok, s1} = Script.push_op(s, :op_checksig)
      {:ok, s1} = Script.push_data(s1, bin)

      assert Script.is_p2pk?(s1)

      {:ok, s2} = Script.create_p2pk(bin)
      assert s2 == s1

      # from tx da69323ec33972675d9594b6569983bfc2257bced36d8df541a2aadfe31db016
      hex = "035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344"
      bin = Base.decode16!(hex, case: :lower)
      {:ok, s3} = Script.push_op(s, :op_checksig)
      {:ok, s3} = Script.push_data(s3, bin)

      assert Script.is_p2pk?(s3)

      {:ok, s4} = Script.create_p2pk(bin)
      assert s4 == s3
    end

    test "test is_p2sh? and create_p2sh" do
      s = Script.new()
      hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
      bin = Base.decode16!(hex, case: :lower)
      {:ok, s} = Script.push_op(s, 0x87)
      {:ok, s} = Script.push_data(s, bin)
      {:ok, s} = Script.push_op(s, 0xA9)

      {:ok, s2} = Script.create_p2sh(bin)

      assert Script.is_p2sh?(s)
      assert s2 == s
    end

    test "test is_p2sh? with non p2sh" do
      # p2pkh from tx 0a6140bbf75e73f11b90c4dabf71f83394d493d635c2bbf19d207fb821de74f5
      s_hex = "76a91408be653b5582bb9c1b85ab1da70906946c90acc588ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2sh?(s)

      # p2wsh from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2sh?(s)

      # p2wpkh from tx 16940cf0fd17da81f47fbae29a6e1eaad844fd45e772292022d0f066db43f007
      s_hex = "00146756d75cc116c710bdfa4cbc12dd3f9629d5d61f"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2sh?(s)
    end

    test "test is_p2pkh? and create_p2pkh" do
      s = Script.new()
      hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      bin = Base.decode16!(hex, case: :lower)
      h160 = Utils.hash160(bin)
      {:ok, s} = Script.push_op(s, :op_checksig)
      {:ok, s} = Script.push_op(s, :op_equalverify)
      {:ok, s} = Script.push_data(s, h160)
      {:ok, s} = Script.push_op(s, :op_hash160)
      {:ok, s} = Script.push_op(s, :op_dup)

      {:ok, s2} = Script.create_p2pkh(h160)

      assert Script.is_p2pkh?(s)
      assert s2 == s
    end

    test "test is_p2pkh? with non p2pkh" do
      # p2wsh from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)

      # p2sh from tx db11e3569da3583f3001514163b5f1c4e0556dd550bfa4518f15095258d43bf3
      s_hex = "a9148a7810adbe753308a8ccae63f81841c92554174487"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)

      # p2wpkh from tx 16940cf0fd17da81f47fbae29a6e1eaad844fd45e772292022d0f066db43f007
      s_hex = "00146756d75cc116c710bdfa4cbc12dd3f9629d5d61f"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)
    end

    test "test is_p2wpkh? and create_p2wpkh" do
      s = Script.new()
      hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      bin = Base.decode16!(hex, case: :lower)
      h160 = Utils.hash160(bin)

      {:ok, s} = Script.push_data(s, h160)
      {:ok, s} = Script.push_op(s, 0x00)

      {:ok, s2} = Script.create_p2wpkh(h160)

      assert Script.is_p2wpkh?(s)
      assert s2 == s
    end

    test "test is_p2wpkh? with non p2wpkh" do
      # p2wsh from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)

      # p2sh from tx db11e3569da3583f3001514163b5f1c4e0556dd550bfa4518f15095258d43bf3
      s_hex = "a9148a7810adbe753308a8ccae63f81841c92554174487"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)

      # p2wpkh from tx 16940cf0fd17da81f47fbae29a6e1eaad844fd45e772292022d0f066db43f007
      s_hex = "00146756d75cc116c710bdfa4cbc12dd3f9629d5d61f"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2pkh?(s)
    end

    test "test create_p2sh_p2wpkh" do
      s = Script.new()
      hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      bin = Base.decode16!(hex, case: :lower)
      h160 = Utils.hash160(bin)

      {:ok, p2wpkh} = Script.push_data(s, h160)
      {:ok, p2wpkh} = Script.push_op(p2wpkh, 0x00)
      sbin = Script.serialize_script(p2wpkh)
      sh = Utils.hash160(sbin)

      {:ok, p2sh} = Script.push_op(s, 0x87)
      {:ok, p2sh} = Script.push_data(p2sh, sh)
      {:ok, p2sh} = Script.push_op(p2sh, 0xA9)

      {:ok, p2sh2, p2wpkh2} = Script.create_p2sh_p2wpkh(h160)

      assert Script.is_p2sh?(p2sh)
      assert p2sh == p2sh2
      assert Script.is_p2wpkh?(p2wpkh2)
      assert p2wpkh == p2wpkh2
    end

    test "test create_p2tr" do
      s = Script.new()
      script_hex = "51200101010101010101010101010101010101010101010101010101010101010101"
      pubkey_hex = "0101010101010101010101010101010101010101010101010101010101010101"
      bin = Base.decode16!(pubkey_hex, case: :lower)

      {:ok, p2tr} = Script.push_data(s, bin)
      {:ok, p2tr} = Script.push_op(p2tr, 0x51)
      assert Script.is_p2tr?(p2tr)

      s_hex = Script.to_hex(p2tr)
      assert s_hex == script_hex

      {:ok, p2tr_from_bin} = Script.create_p2tr(bin)
      assert Script.to_hex(p2tr_from_bin) == script_hex

      {:ok, pubkey} = Point.lift_x(bin)
      {:ok, p2tr_from_pk} = Script.create_p2tr(pubkey)
      assert Script.to_hex(p2tr_from_pk) == script_hex
    end

    test "test is_multi?" do
      for ms <- @raw_multisig_scripts do
        {:ok, multi} = Script.parse_script(ms)
        assert Script.is_multi?(multi)
      end
    end

    test "test create_multi" do
      # these keys will be added to multisig as compressed keys
      {:ok, pk1} =
        Point.parse_public_key(
          "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"
        )

      {:ok, multi} = Script.create_multi(2, [pk1, pk2, pk3])
      assert Script.is_multi?(multi)

      {:ok, pk1} =
        Point.parse_public_key(
          "03af40079dabd57915a41fc676c9a1e8e9278b9aa7e3b2cf7db63435e357bd5895"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "024a84c829eb98eb69b37be6adcdc206b462b4c9549a0db2dbc91279a2f031a50a"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "02a5264fbc1be9b9a7d03d9637a5534ce8d59a06c4c1f30802fe52e7bf6c1dd971"
        )

      {:ok, multi} = Script.create_multi(1, [pk1, pk2, pk3])
      assert Script.is_multi?(multi)

      {:ok, multi} = Script.create_multi(2, [pk1, pk2, pk3])
      assert Script.is_multi?(multi)

      {:ok, multi} = Script.create_multi(3, [pk1, pk2, pk3])
      assert Script.is_multi?(multi)

      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_multi(4, [pk1, pk2, pk3])
      # m cant be 0
      {:error, _msg} = Script.create_multi(0, [pk1, pk2, pk3])
      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_multi(0, [])
    end

    test "test create_p2sh_multi" do
      {:ok, pk1} =
        Point.parse_public_key(
          "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"
        )

      {:ok, p2sh, multi} = Script.create_p2sh_multi(2, [pk1, pk2, pk3])
      assert Script.is_p2sh?(p2sh)
      assert Script.is_multi?(multi)

      {:ok, pk1} =
        Point.parse_public_key(
          "03af40079dabd57915a41fc676c9a1e8e9278b9aa7e3b2cf7db63435e357bd5895"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "024a84c829eb98eb69b37be6adcdc206b462b4c9549a0db2dbc91279a2f031a50a"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "02a5264fbc1be9b9a7d03d9637a5534ce8d59a06c4c1f30802fe52e7bf6c1dd971"
        )

      {:ok, p2sh, multi} = Script.create_p2sh_multi(2, [pk1, pk2, pk3])
      assert Script.is_p2sh?(p2sh)
      assert Script.is_multi?(multi)

      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_p2sh_multi(4, [pk1, pk2, pk3])
      # m cant be 0
      {:error, _msg} = Script.create_p2sh_multi(0, [pk1, pk2, pk3])
      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_p2sh_multi(0, [])
    end

    test "test create_p2wsh_multi" do
      {:ok, pk1} =
        Point.parse_public_key(
          "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"
        )

      {:ok, p2wsh, multi} = Script.create_p2wsh_multi(2, [pk1, pk2, pk3])
      assert Script.is_p2wsh?(p2wsh)
      assert Script.is_multi?(multi)

      {:ok, pk1} =
        Point.parse_public_key(
          "03af40079dabd57915a41fc676c9a1e8e9278b9aa7e3b2cf7db63435e357bd5895"
        )

      {:ok, pk2} =
        Point.parse_public_key(
          "024a84c829eb98eb69b37be6adcdc206b462b4c9549a0db2dbc91279a2f031a50a"
        )

      {:ok, pk3} =
        Point.parse_public_key(
          "02a5264fbc1be9b9a7d03d9637a5534ce8d59a06c4c1f30802fe52e7bf6c1dd971"
        )

      {:ok, p2wsh, multi} = Script.create_p2wsh_multi(2, [pk1, pk2, pk3])
      assert Script.is_p2wsh?(p2wsh)
      assert Script.is_multi?(multi)

      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_p2wsh_multi(4, [pk1, pk2, pk3])
      # m cant be 0
      {:error, _msg} = Script.create_p2wsh_multi(0, [pk1, pk2, pk3])
      # m cant be greater than n in m-of-n
      {:error, _msg} = Script.create_p2wsh_multi(0, [])
    end

    test "test create scripts from pubkey" do
      hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, pubkey} = Point.parse_public_key(hex)

      {:ok, p2pkh} = Script.public_key_to_p2pkh(pubkey)
      assert Script.is_p2pkh?(p2pkh)

      # check correct p2pkh format and pkh
      {:ok, op_dup, rest} = Script.pop(p2pkh)
      {:ok, op_h160, rest} = Script.pop(rest)
      {:ok, len, rest} = Script.pop(rest)
      {:ok, pkh, _rest} = Script.pop(rest)
      assert op_dup == 0x76
      assert op_h160 == 0xA9
      assert len == 20
      assert pkh == h160

      {:ok, p2wpkh} = Script.public_key_to_p2wpkh(pubkey)
      assert Script.is_p2wpkh?(p2wpkh)
      # check pkh is correct
      {:ok, witver, rest} = Script.pop(p2wpkh)
      {:ok, len, rest} = Script.pop(rest)
      {:ok, pkh, rest} = Script.pop(rest)
      assert witver == 0
      assert len == 20
      assert pkh == h160
      assert Script.empty?(rest)

      {:ok, p2sh_p2wpkh, p2wpkh} = Script.public_key_to_p2sh_p2wpkh(pubkey)
      assert Script.is_p2sh?(p2sh_p2wpkh)
      assert Script.is_p2wpkh?(p2wpkh)
    end

    test "test get_script_type/1" do
      for s <- @p2pk_scripts do
        {:ok, script} = Script.parse_script(s)
        assert Script.get_script_type(script) == :p2pk
      end

      for s <- @p2pkh_scripts do
        {:ok, script} = Script.parse_script(s)
        assert Script.get_script_type(script) == :p2pkh
      end

      for s <- @p2sh_scripts do
        {:ok, script} = Script.parse_script(s)
        assert Script.get_script_type(script) == :p2sh
      end

      for s <- @p2wpkh_scripts do
        {:ok, script} = Script.parse_script(s)
        assert Script.get_script_type(script) == :p2wpkh
      end

      for s <- @p2wsh_scripts do
        {:ok, script} = Script.parse_script(s)
        assert Script.get_script_type(script) == :p2wsh
      end
    end
  end

  describe "test parsing scripts" do
    test "test parse pushdata1 script" do
      # pushdata1 <data>
      data_hex =
        "c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1"

      s_hex =
        "4c50c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1"

      bin = data_hex |> Base.decode16!(case: :lower)
      {:ok, s} = Script.parse_script(s_hex)
      {:ok, pushdata, s} = Script.pop(s)
      {:ok, data, s} = Script.pop(s)

      assert pushdata == 0x4C
      assert data == bin
      assert Script.empty?(s)

      # op_hash160 pushdata1 <data> op_checksig
      data_hex =
        "c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1"

      s_hex =
        "a94c50c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1ac"

      bin = data_hex |> Base.decode16!(case: :lower)
      {:ok, s} = Script.parse_script(s_hex)
      {:ok, op160, s} = Script.pop(s)
      {:ok, pushdata, s} = Script.pop(s)
      {:ok, data, s} = Script.pop(s)
      {:ok, cs, s} = Script.pop(s)

      assert op160 == 0xA9
      assert pushdata == 0x4C
      assert data == bin
      assert cs == 0xAC
      assert Script.empty?(s)
    end

    test "test parse pushdata2 script" do
      # pushdata2 <data>
      data_hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      s_hex =
        "4de901c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      bin = data_hex |> Base.decode16!(case: :lower)
      {:ok, s} = Script.parse_script(s_hex)
      {:ok, pushdata, s} = Script.pop(s)
      {:ok, data, s} = Script.pop(s)

      assert pushdata == 0x4D
      assert data == bin
      assert Script.empty?(s)

      # hash160 pushdata2 <data> checksig
      data_hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      s_hex =
        "a94de901c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9ac"

      bin = data_hex |> Base.decode16!(case: :lower)

      {:ok, s} = Script.parse_script(s_hex)
      {:ok, op_h160, s} = Script.pop(s)
      {:ok, pushdata, s} = Script.pop(s)
      {:ok, data, s} = Script.pop(s)
      {:ok, op_cs, s} = Script.pop(s)

      assert op_h160 == 0xA9
      assert pushdata == 0x4D
      assert data == bin
      assert op_cs == 0xAC
      assert Script.empty?(s)
    end

    test "test parse p2pkh scriptsig" do
      # from tx 8d44970f599588688044a5b52169497be9b2813c0d8f76a19cf693dafc5acfc0
      s_hex =
        "47304402202cd4021840da717ce426f8bcc9dc1f701aa4939391242b0941a2788610caf240022037aa257d0c0b2b3f29f5f9ee29d161bcac701c604cca83df9d50fd7c397d535a012103f0f8011ca3ae27e757d23852c59192e223c62e490d59a709201392b5dfe55c21"

      sig_hex =
        "304402202cd4021840da717ce426f8bcc9dc1f701aa4939391242b0941a2788610caf240022037aa257d0c0b2b3f29f5f9ee29d161bcac701c604cca83df9d50fd7c397d535a01"

      pubkey_hex = "03f0f8011ca3ae27e757d23852c59192e223c62e490d59a709201392b5dfe55c21"
      {:ok, s} = Script.parse_script(s_hex)
      {:ok, push71, s} = Script.pop(s)
      {:ok, sig, s} = Script.pop(s)
      {:ok, push33, s} = Script.pop(s)
      {:ok, pubkey, _s} = Script.pop(s)

      assert push71 == 71
      assert sig == sig_hex |> Base.decode16!(case: :lower)
      assert push33 == 33
      assert pubkey == pubkey_hex |> Base.decode16!(case: :lower)
    end

    test "test parse p2pk from uncompressed key" do
      # from tx df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a
      s_hex =
        "4104184f32b212815c6e522e66686324030ff7e5bf08efb21f8b00614fb7690e19131dd31304c54f37baa40db231c918106bb9fd43373e37ae31a0befc6ecaefb867ac"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2pk?(s)

      # from tx da69323ec33972675d9594b6569983bfc2257bced36d8df541a2aadfe31db016
      s_hex = "21035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2pk?(s)
    end

    test "test parse p2pkh" do
      s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2pkh?(s)

      # from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "76a914c689464b843e9782e54c662f544e452940357a9888ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2pkh?(s)

      # from tx 0a6140bbf75e73f11b90c4dabf71f83394d493d635c2bbf19d207fb821de74f5
      s_hex = "76a91408be653b5582bb9c1b85ab1da70906946c90acc588ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2pkh?(s)
    end

    test "test parse p2sh" do
      # from tx 0afe8c093add0610e50f647fa5a5e09d72fbc2eed6da6aab045746b69161def2
      s_hex = "a914cbb5d42faa8e9267f3a4ab9eabde9ebc9016ef8787"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2sh?(s)

      # p2wsh from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2sh?(s)
    end

    test "test parse p2wpkh" do
      # from tx fd910133a2febe8e0edbd25c908f0a8339afda29ff820a1f845e8dd2dccc5658
      s_hex = "0014a38e224fc2ead8f32b13e3cef6bbf3520f16378c"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2wpkh?(s)

      # p2sh from tx 0afe8c093add0610e50f647fa5a5e09d72fbc2eed6da6aab045746b69161def2
      s_hex = "a914cbb5d42faa8e9267f3a4ab9eabde9ebc9016ef8787"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2wpkh?(s)

      # p2wsh from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2wpkh?(s)
    end

    test "test parse p2wsh" do
      # from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.is_p2wsh?(s)

      # p2pkh from tx fd910133a2febe8e0edbd25c908f0a8339afda29ff820a1f845e8dd2dccc5658
      s_hex = "0014a38e224fc2ead8f32b13e3cef6bbf3520f16378c"
      {:ok, s} = Script.parse_script(s_hex)

      assert !Script.is_p2wsh?(s)
    end

    test "test parse short script" do
      assert Script.parse_script("") == {:ok, Script.new()}
      assert Script.parse_script("00") == {:ok, %Script{items: [0]}}
      assert Script.parse_script("51") == {:ok, %Script{items: [0x51]}}
      assert Script.parse_script("5151") == {:ok, %Script{items: [0x51, 0x51]}}
    end
  end

  describe "test parse invalid scripts" do
    test "test parse invalid scripts" do
      scripts = [
        "4caa12",
        "004ca112",
        "4c6ac5802547372094c580258025473720941cee958bca07652beaaaa7e6419bc91cee958b802720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9",
        "1",
        "21",
        "31",
        "4c"
      ]

      for hex <- scripts do
        {res, _msg} = Script.parse_script(hex)
        assert res == :error
      end
    end
  end

  describe "test serialize scripts" do
    test "test serialize pushdata1" do
      data_hex =
        "c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1"

      s_hex =
        "4c50c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1"

      {:ok, s1} = Script.parse_script(s_hex)

      bin = data_hex |> Base.decode16!(case: :lower)
      {:ok, s2} = Script.push_data(Script.new(), bin)

      assert s2 == s1
      assert Script.serialize_script(s2) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s2) == s_hex

      s_hex =
        "a94c50c5802547372094c58025802547372094c5802547802c9ca07652be7e8025472547372094c5802547802c9ca07652be7e802547372094c5802547802c9ca07652be7e47802c9ca07652be7e6419bc9aa1ac"

      {:ok, s} = Script.parse_script(s_hex)
      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex
    end

    test "test serialize pushdata2" do
      s_hex =
        "4de901c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex
    end

    test "test serialize common scripts" do
      s_hex = "0014a38e224fc2ead8f32b13e3cef6bbf3520f16378c"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex

      s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex

      s_hex = "a914cbb5d42faa8e9267f3a4ab9eabde9ebc9016ef8787"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex

      s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"

      {:ok, s} = Script.parse_script(s_hex)

      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex
    end

    test "test serialize/parse multisig scripts" do
      for ms <- @raw_multisig_scripts do
        {:ok, multi} = Script.parse_script(ms)
        assert Script.is_multi?(multi)
        assert Script.to_hex(multi) == ms
      end
    end

    test "serialize other scripts" do
      # op_0 op_0 op_0 op_0 op_0 op_1
      s_hex = "000000000051"
      {:ok, s} = Script.parse_script(s_hex)
      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex

      # op_0 op_0 pushbytes_1 <<0x00>>
      s_hex = "00000100"
      {:ok, s} = Script.parse_script(s_hex)
      assert Script.serialize_script(s) == s_hex |> Base.decode16!(case: :lower)
      assert Script.to_hex(s) == s_hex

      # op_0
      s_hex = "00"
      {:ok, s} = Script.parse_script(s_hex)
      assert Script.serialize_script(s) == <<0x00>>
    end
  end

  describe "test display_script/1" do
    test "test display_script/1 with p2pkh" do
      text =
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 c58025473720941cee958bca07652be7e6419bc9 OP_EQUALVERIFY OP_CHECKSIG"

      s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"
      {:ok, s} = Script.parse_script(s_hex)

      assert Script.display_script(s) == text
    end

    test "display_script/1 with random script" do
      text = "OP_0 OP_PUSHDATA1 OP_16 OP_5 OP_RETURN OP_ROLL OP_CHECKSIG OP_NOP1 0102030405"
      s = %Script{items: [0x00, 0x4C, 0x60, 0x55, 0x6A, 0x7A, 0xAC, 0xB0, <<1, 2, 3, 4, 5>>]}

      assert Script.display_script(s) == text
    end

    test "push data 1" do
      text =
        "OP_PUSHDATA1 c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      s = Script.new()

      hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      bin = Utils.hex_to_bin(hex)
      {:ok, s} = Script.push_data(s, bin)

      assert Script.display_script(s) == text
    end

    test "push data 2" do
      text =
        "OP_PUSHDATA2 c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      s = Script.new()

      hex =
        "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"

      bin = Utils.hex_to_bin(hex)
      {:ok, s} = Script.push_data(s, bin)

      assert Script.display_script(s) == text
    end
  end

  describe "test to_address/2" do
    test "test p2sh_p2wpkh address" do
      addr = "3HTC7s9dwBzK9Gn9mzejanBV25i35PvGSQ"
      p2wpkh_addr = "bc1q24sn878fl3s6q8ryted85zskyn0ffyl043pphf"
      hex = "034c3773e6ee01be50be219e5dd14179f0feb0c1fc8cd25fd3cb3ca37f607a4534"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, p2sh, p2wpkh} = Script.create_p2sh_p2wpkh(h160)
      assert Script.to_address(p2sh, :mainnet) == {:ok, addr}
      assert Script.to_address(p2wpkh, :mainnet) == {:ok, p2wpkh_addr}

      addr = "3KjjkKUqDSqPCeAhTFP57Xp87JKsdqJLYH"
      p2wpkh_addr = "bc1qlqhcjnnu2g8fwy9vlju0mtseqf50e95hcz4vne"
      hex = "035d03803d60e65786c328c6ef0077c3b2d017542d6f3a67e23f21568d30f8f619"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, p2sh, p2wpkh} = Script.create_p2sh_p2wpkh(h160)
      assert Script.to_address(p2sh, :mainnet) == {:ok, addr}
      assert Script.to_address(p2wpkh, :mainnet) == {:ok, p2wpkh_addr}
    end

    test "test p2pkh address" do
      # from tx 1af0fbe9141371e29ab870121a3d9ae361d6664d789e367e6341e8a4b3311ea0
      addr = "12wRAwmwVBXrnquwwc8uH5xHT7ExaP6gU3"
      hex = "0247c446b01e77fc0318be2db38f97b441b98bb171cdb467a2efee7276a760ea58"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, s} = Script.create_p2pkh(h160)
      assert Script.to_address(s, :mainnet) == {:ok, addr}

      # from tx d531beedb3c4e0996e3df72318f174505bb0b4f99c0a7c70ba1fcd0f27e45fa8
      addr = "133qBf9RgtwAyn11mrLHPWydTwSsfhwsav"
      hex = "0230016a9764716395085ed329b00928bf04d36f2b803f5cd457df021db42a59df"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, s} = Script.create_p2pkh(h160)
      assert Script.to_address(s, :mainnet) == {:ok, addr}

      # from testnet tx d87beaa61c425eb5d6b4687f8d186df5e4a764483b3a616032741ac0615405ec
      addr = "mrHhy9DgpBbDLoJsACv4QXXY7f2B5Fq5o1"
      hex = "037ed58c914720772c59f7a1e7e76fba0ef95d7c5667119798586301519b9ad2cf"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, s} = Script.create_p2pkh(h160)
      assert Script.to_address(s, :testnet) == {:ok, addr}
    end

    test "test p2wpkh address" do
      # from tx 915924af3d478a1ca5e32b81fe327ee78b24d8475ed90666242dfd4bf52fc33d
      addr = "bc1qtvdt23u5mpkkaxw596s5d5hcjm2qgs68p4k9qe"
      hex = "03e6cf64144a2243816151623a5ddaf47b3be771f4d5e450dfb93ea38372af0ceb"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, s} = Script.create_p2wpkh(h160)
      assert Script.to_address(s, :mainnet) == {:ok, addr}

      # from testnet tx 8bcb4bef012fff4191919f5615b894f43b940bd625162018b0d710c71a9b2603
      addr = "tb1qtk3vfds84nvcrlxucu5a8p8dqz2k6w5e8h9m8d"
      hex = "02ca6a71b4f16b75763cb5467666a94972d18ebda3baf296b37149ffea78dc6129"
      h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
      {:ok, s} = Script.create_p2wpkh(h160)
      assert Script.to_address(s, :testnet) == {:ok, addr}
    end

    test "test p2wsh address" do
      # tx from d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
      addr = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"

      redeem_script =
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"

      h256 = redeem_script |> Base.decode16!(case: :lower) |> Utils.sha256()
      {:ok, s} = Script.create_p2wsh(h256)
      assert Script.to_address(s, :mainnet) == {:ok, addr}
    end

    test "test raw multisig to address" do
      for multi <- @raw_multisigs_with_data do
        {:ok, ms} = Script.parse_script(multi.script_hex)
        {:ok, m, pks} = Script.extract_multi_policy(ms)

        if multi.sh_addr != "" do
          {:ok, p2sh, multi_script} = Script.create_p2sh_multi(m, pks)

          {:ok, addr} = Script.to_address(p2sh, multi.network)

          assert multi_script == ms
          assert addr == multi.sh_addr
        end

        if multi.wsh_addr != "" do
          {:ok, p2wsh, multi_script} = Script.create_p2wsh_multi(m, pks)

          {:ok, addr} = Script.to_address(p2wsh, multi.network)

          assert multi_script == ms
          assert addr == multi.wsh_addr
        end
      end
    end

    test "test bip350 test vectors" do
      for t <- @bip350_test_vectors do
        {:ok, s} = Script.parse_script(t.hex)
        assert Script.to_address(s, t.net) == {:ok, t.b32}
      end
    end

    test "test invalid bip350 test vectors" do
      for t <- @bip_350_invalid_test_vectors do
        assert {:error, _} = Script.parse_script(t)
      end
    end
  end

  describe "test from_address" do
    test "test from_address p2sh" do
      addr = "3HTC7s9dwBzK9Gn9mzejanBV25i35PvGSQ"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2sh?(script)
      assert network == :mainnet

      addr = "3KjjkKUqDSqPCeAhTFP57Xp87JKsdqJLYH"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2sh?(script)
      assert network == :mainnet

      # from tx 266dff8196f461bbdaeef2e3f36d0d488ddaef7784c4c30c1c10f61c50c946f1
      addr = "38znSNNyb7vouwY5b8CptywqkAG98Fpbqa"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2sh?(script)
      assert network == :mainnet

      # from testnet tx baa8253599aa83d12843ee99035b97c90944c2e4b58cb956f1b0b9245290cf4b
      addr = "2Mt4uopJDw128m9RDj41Y3JiFDM6jH38ZCL"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2sh?(script)
      assert network == :testnet

      # from testnet tx baa8253599aa83d12843ee99035b97c90944c2e4b58cb956f1b0b9245290cf4b
      addr = "2MxLK9iAH3kXPGDqVTACpWV4uJ5htXhzdJa"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2sh?(script)
      assert network == :testnet
    end

    test "test from_address p2pkh" do
      # from tx 0a110fa84e4a25c35612019cadaea694925ebb3227da922ee2b013f9200465aa
      addr = "12wRAwmwVBXrnquwwc8uH5xHT7ExaP6gU3"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2pkh?(script)
      assert network == :mainnet

      # from tx 49e714b8cc3b76c72876b1c358422f05139c3f57c26b9872bee79825ad6c4edc
      addr = "133qBf9RgtwAyn11mrLHPWydTwSsfhwsav"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2pkh?(script)
      assert network == :mainnet

      # from testnet tx 3139a85541275582ce40afe906eb6d70c3ea9f244c5a793b27bcbba1a8146279
      addr = "mrHhy9DgpBbDLoJsACv4QXXY7f2B5Fq5o1"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2pkh?(script)
      assert network == :testnet

      # from testnet tx 2af39706c2b96da6d46544459e679f3f8c31f09b3c004a718080d4a5d25059dd
      addr = "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2pkh?(script)
      assert network == :testnet

      # from testnet tx 2af39706c2b96da6d46544459e679f3f8c31f09b3c004a718080d4a5d25059dd
      addr = "mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2pkh?(script)
      assert network == :testnet
    end

    test "test from_address p2wsh" do
      # from tx 576330af0ca5ff19063d0abb56a5f2c68284bd25b4067dd0e05582ece53998f0
      addr = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wsh?(script)
      assert network == :mainnet

      # from tx 1b4895f3d5d11e4b5557ac19b91e250e0e287c4042c78ef07e439088486d3ca6
      addr = "bc1ql8ruf3d5yuuwau49egx0ljcsu7enk52pvyy2jt9vdpsl2zxdefzs0xdexp"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wsh?(script)
      assert network == :mainnet

      # from testnet tx 45e4999d43aacc61ba182f700d2e7ecf62dde579f05c2f0021d3784122673783
      addr = "tb1qxhagtd0mj06ktjpsst9lluyf4yytrm5yh4qjccc5ledfuuwhcyhqppu84v"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wsh?(script)
      assert network == :testnet

      # from testnet tx 6a9e92240f4a8e2e30a31bfdd879f9647bf0ec44df77e1260983da64d411bff5
      addr = "tb1qmexazupzk6hq6xhu0kdtx4ejj2gjrggs3qgsmq0fye7mjkeja85qed89yv"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wsh?(script)
      assert network == :testnet
    end

    test "test from_address p2wpkh" do
      addr = "tb1qtk3vfds84nvcrlxucu5a8p8dqz2k6w5e8h9m8d"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wpkh?(script)
      assert network == :testnet

      addr = "bc1qtvdt23u5mpkkaxw596s5d5hcjm2qgs68p4k9qe"
      {:ok, script, network} = Script.from_address(addr)
      assert Script.is_p2wpkh?(script)
      assert network == :mainnet
    end

    test "test bip350 test vectors" do
      for t <- @bip350_test_vectors do
        {:ok, s, net} = Script.from_address(t.b32)
        assert Script.to_hex(s) == t.hex
        assert net == t.net
      end
    end
  end

  describe "test extract multisig policy" do
    test "extract policy from multisig script" do
      for multi <- @raw_multisigs_with_data do
        {:ok, ms} = Script.parse_script(multi.script_hex)
        {:ok, m, pks} = Script.extract_multi_policy(ms)
        {:ok, ms2} = Script.create_multi(m, pks)

        assert ms == ms2
      end

      for m <- @raw_multisig_scripts do
        {:ok, ms} = Script.parse_script(m)
        {:ok, m, pks} = Script.extract_multi_policy(ms)
        {:ok, ms2} = Script.create_multi(m, pks)

        assert ms == ms2
      end
    end
  end

  describe "full tests" do
    test "test parse, serialize and create addresses for multisig" do
      # from tx 0a6140bbf75e73f11b90c4dabf71f83394d493d635c2bbf19d207fb821de74f5
      redeem_script =
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"

      p2wsh_addr = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
      {:ok, s} = Script.parse_script(redeem_script)

      {:ok, p2wsh} =
        s
        |> Script.serialize_script()
        |> Utils.sha256()
        |> Script.create_p2wsh()

      assert Script.to_address(p2wsh, :mainnet) == {:ok, p2wsh_addr}

      {:ok, op2, s} = Script.pop(s)
      {:ok, push33, s} = Script.pop(s)
      {:ok, pk1, s} = Script.pop(s)
      {:ok, push33_, s} = Script.pop(s)
      {:ok, pk2, s} = Script.pop(s)
      {:ok, push33__, s} = Script.pop(s)
      {:ok, pk3, s} = Script.pop(s)
      {:ok, op3, s} = Script.pop(s)
      {:ok, op_cms, s} = Script.pop(s)

      {:ok, pubkey1} = Bitcoinex.Secp256k1.Point.parse_public_key(pk1)
      {:ok, pubkey2} = Bitcoinex.Secp256k1.Point.parse_public_key(pk2)
      {:ok, pubkey3} = Bitcoinex.Secp256k1.Point.parse_public_key(pk3)

      assert Script.empty?(s)
      assert push33 == 33 and push33_ == 33 and push33__ == 33
      assert op2 == 0x52
      assert op3 == 0x53
      assert op_cms == 0xAE

      assert Bitcoinex.Secp256k1.Point.sec(pubkey1) == pk1
      assert Bitcoinex.Secp256k1.Point.sec(pubkey2) == pk2
      assert Bitcoinex.Secp256k1.Point.sec(pubkey3) == pk3
    end
  end
end
