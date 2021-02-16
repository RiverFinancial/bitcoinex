defmodule Bitcoinex.Secp256k1.PrivateKeyTest do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1.PrivateKey

  alias Bitcoinex.Secp256k1.PrivateKey

  @rfc6979_test_cases [
    # From https://bitcointalk.org/index.php?topic=285142.msg3150733
    %{
      d: 0x1,
      m: "Satoshi Nakamoto",
      k: 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15,
      sig:
        "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8dbbd3162d46e9f9bef7feb87c16dc13b4f6568a87f4e83f728e2443ba586675c"
    },
    %{
      d: 0x1,
      m: "All those moments will be lost in time, like tears in rain. Time to die...",
      k: 0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3,
      sig:
        "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6bab8019bbd8b6924cc4099fe625340ffb1eaac34bf4477daa39d0835429094520"
    },
    %{
      d: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
      m: "Satoshi Nakamoto",
      k: 0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90,
      sig:
        "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d094c632f14e4379fc1ea610a3df5a375152549736425ee17cebe10abbc2a2826c"
    },
    %{
      d: 0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181,
      m: "Alan Turing",
      k: 0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1,
      sig:
        "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15ca72033e1ff5ca1ea8d0c99001cb45f0272d3be7525d3049c0d9e98dc7582b857"
    },
    # from https://bitcointalk.org/index.php?topic=285142.40 
    %{
      d: 0xE91671C46231F833A6406CCBEA0E3E392C76C167BAC1CB013F6F1013980455C2,
      m:
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
      k: 0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D,
      sig:
        "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
    }
  ]

  describe "serialize_private_key/1" do
    test "successfully pad private key" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}

      assert "000000000000000000000000000000000000000000001a224cd1a01427f38b07" ==
               PrivateKey.serialize_private_key(sk)
    end
  end

  describe "wif/2" do
    test "successfully return private key wif encoding" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}

      assert "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E" ==
               PrivateKey.wif!(sk, :mainnet)

      assert "cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm" ==
               PrivateKey.wif!(sk, :testnet)
    end
  end

  describe "parse_wif/1" do
    test "successfully return private key from wif str" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}
      wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E"
      assert {:ok, sk, :mainnet, true} == PrivateKey.parse_wif(wif)
      twif = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm"
      assert {:ok, sk, :testnet, true} == PrivateKey.parse_wif(twif)
    end
  end

  describe "parse & serialize wif" do
    test "successfully return private key from wif str" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}
      wif = PrivateKey.wif!(sk, :mainnet)
      assert {:ok, sk, :mainnet, true} == PrivateKey.parse_wif(wif)
    end
  end

  describe "test deterministic k calculation" do
    test "successfully derive correct k value" do
      for t <- @rfc6979_test_cases do
        p = %PrivateKey{d: t.d}
        z = :binary.decode_unsigned(:crypto.hash(:sha256, t.m))
        assert Bitcoinex.Secp256k1.PrivateKey.deterministic_k(p, z) == %PrivateKey{d: t.k}
      end
    end
  end

  describe "sign/2" do
    test "successfully sign message with private key" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}
      msg = "hello world"

      correct_sig = %Bitcoinex.Secp256k1.Signature{
        r:
          51_171_856_268_621_681_203_379_064_931_680_562_348_117_352_680_621_396_833_116_333_722_055_478_120_934,
        s:
          17_455_962_327_778_698_045_206_777_017_096_967_323_286_973_535_288_379_967_544_467_291_763_458_630_546
      }

      correct_der =
        "3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392"

      z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(msg))
      sig = PrivateKey.sign(sk, z)
      assert sig == correct_sig
      der = Bitcoinex.Secp256k1.Signature.der_serialize_signature(sig)
      assert Base.encode16(der, case: :lower) == correct_der
    end
  end

  describe "fuzz test signing" do
    setup do
      privkey = %PrivateKey{d: 123_414_253_234_542_345_423_623}
      pubkey = PrivateKey.to_point(privkey)
      {:ok, privkey: privkey, pubkey: pubkey}
    end

    test "successfully sign a large number of random sighashes", %{
      privkey: privkey,
      pubkey: pubkey
    } do
      for _ <- 1..1000 do
        z =
          32
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()

        sig = PrivateKey.sign(privkey, z)
        assert Bitcoinex.Secp256k1.verify_signature(pubkey, z, sig)
      end
    end

    test "successfully sign a sighash with a large number of keys" do
      z =
        32
        |> :crypto.strong_rand_bytes()
        |> :binary.decode_unsigned()

      for _ <- 1..1000 do
        secret =
          32
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()

        privkey = %PrivateKey{d: secret}
        pubkey = PrivateKey.to_point(privkey)
        sig = PrivateKey.sign(privkey, z)
        assert Bitcoinex.Secp256k1.verify_signature(pubkey, z, sig)
      end
    end
  end
end
