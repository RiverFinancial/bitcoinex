defmodule Bitcoinex.Secp256k1.EcdsaTest do
  use ExUnit.Case

  doctest Bitcoinex.Secp256k1.Ecdsa

  alias Bitcoinex.Secp256k1.{Ecdsa, Params, Point, PrivateKey, Signature}

  @n Params.curve().n

  @valid_signatures_for_public_key_recovery [
    %{
      message_hash:
        Base.decode16!(
          "CE0677BB30BAA8CF067C88DB9811F4333D131BF8BCF12FE7065D211DCE971008",
          case: :upper
        ),
      signature:
        Base.decode16!(
          "90F27B8B488DB00B00606796D2987F6A5F59AE62EA05EFFE84FEF5B8B0E549984A691139AD57A3F0B906637673AA2F63D1F55CB1A69199D4009EEA23CEADDC93",
          case: :upper
        ),
      recovery_id: 1,
      pubkey: "02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a"
    },
    %{
      message_hash:
        Base.decode16!(
          "5555555555555555555555555555555555555555555555555555555555555555",
          case: :upper
        ),
      signature:
        Base.decode16!(
          "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
          case: :upper
        ),
      recovery_id: 0,
      pubkey: "02c1ab1d7b32c1adcdab9d378c2ae75ee27822541c6875beed3255f981f0dea378"
    }
  ]

  @invalid_signatures_for_public_key_recovery [
    %{
      # invalid curve point
      message_hash:
        Base.decode16!(
          "00C547E4F7B0F325AD1E56F57E26C745B09A3E503D86E00E5255FF7F715D3D1C",
          case: :upper
        ),
      signature:
        Base.decode16!(
          "00B1693892219D736CABA55BDB67216E485557EA6B6AF75F37096C9AA6A5A75F00B940B1D03B21E36B0E47E79769F095FE2AB855BD91E3A38756B7D75A9C4549",
          case: :upper
        ),
      recovery_id: 0
    },
    %{
      # Low r and s.
      message_hash:
        Base.decode16!(
          "BA09EDC1275A285FB27BFE82C4EEA240A907A0DBAF9E55764B8F318C37D5974F",
          case: :upper
        ),
      signature:
        Base.decode16!(
          "00000000000000000000000000000000000000000000000000000000000000002C0000000000000000000000000000000000000000000000000000000000000004",
          case: :upper
        ),
      recovery_id: 1
    },
    %{
      # invalid signature
      message_hash:
        Base.decode16!(
          "5555555555555555555555555555555555555555555555555555555555555555",
          case: :upper
        ),
      signature:
        Base.decode16!(
          "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          case: :upper
        ),
      recovery_id: 0
    }
  ]

  @valid_signature_pubkey_sighash_sets [
    %{
      # valid signature from private_key used in privatekey_test.exs and msg "hello world"
      privkey: %PrivateKey{d: 123_414_253_234_542_345_423_623},
      # 3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392
      signature: %Signature{
        r:
          51_171_856_268_621_681_203_379_064_931_680_562_348_117_352_680_621_396_833_116_333_722_055_478_120_934,
        s:
          17_455_962_327_778_698_045_206_777_017_096_967_323_286_973_535_288_379_967_544_467_291_763_458_630_546
      },
      # "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      pubkey: %Point{
        x:
          26_725_119_729_089_203_965_150_132_282_997_341_343_516_273_140_835_737_223_575_952_640_907_021_258_522,
        y:
          35_176_335_436_138_229_778_595_179_837_068_778_482_032_382_451_813_967_420_917_290_469_529_927_283_651
      },
      msg: "hello world"
    }
  ]

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

  # No published RFC6979 vector exercises z >= n, because no message hashes to
  # a value that large in practice. These were generated with python-ecdsa
  # 0.19.2, an independent implementation, which reproduces all of
  # @rfc6979_test_cases above exactly:
  #
  #     from ecdsa import rfc6979
  #     import hashlib
  #     n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  #     rfc6979.generate_k(n, d, hashlib.sha256, z.to_bytes(32, "big"))
  #
  # Note that (d: 1, z: n) and (d: 1, z: 0) below share a k: that is the
  # bits2octets reduction, confirmed by an implementation that is not ours.
  @rfc6979_reduction_test_cases [
    %{
      # z == n, the input a strict > comparison gets wrong
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      k: 0x010497D369B3D525CA15EC29C104A694210BB59FF6CABFC10AFE6DF0283896DF
    },
    %{
      # z == 0, the value z == n reduces to
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0x0000000000000000000000000000000000000000000000000000000000000000,
      k: 0x010497D369B3D525CA15EC29C104A694210BB59FF6CABFC10AFE6DF0283896DF
    },
    %{
      # z == n + 1
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142,
      k: 0x9A409DAB05968059DA3EFB323DC67C96F234571B965FD39810CA0643FBB795AC
    },
    %{
      # z == n
      d: 0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      k: 0xFE5C2172613635E945784D70D7CBFDEF33719A5B661711DB2D684A7799DE32DF
    },
    %{
      # z == 2^256 - 1, the largest a 32-byte hash can be
      d: 0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
      k: 0xAF12E23175D8C6A77C6FA469C454870A6E7229D07F8E6E206189DB60985C948E
    },
    %{
      # z == n + 12345
      d: 0xE91671C46231F833A6406CCBEA0E3E392C76C167BAC1CB013F6F1013980455C2,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036717A,
      k: 0xD8F60463AC4719152E20A3C3031E2DD42E9D6BE6B0BA0B1C117DC6F701B4C75A
    },
    %{
      # z == n
      d: 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      k: 0x604ADEA240A4FE28A8A8D87DE7C70FEA679A252C796EC76196AA53C1BB4D79E6
    },
    %{
      # z == n + 1, with d == n - 1
      d: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142,
      k: 0x8B019446AA53C1E9EC19B87CC6229A79954DEB5AC752E13D874EA6911DA70CE5
    }
  ]

  # Deterministic signatures from libsecp256k1 (via coincurve 21.0.0), the
  # implementation Bitcoin Core signs with. Unlike the k-only vectors above,
  # these pin the whole signing path end to end: RFC6979 nonce derivation, the
  # r/s computation, low-s normalization, and DER encoding.
  #
  #     from coincurve import PrivateKey
  #     PrivateKey(d.to_bytes(32, "big")).sign(z.to_bytes(32, "big"), hasher=None).hex()
  #
  # The z == n and z == 2^256 - 1 cases are worth noting: libsecp256k1 reduces
  # the message the same way RFC6979 bits2octets does, so its signature at
  # z == n is byte-for-byte the one it produces at z == 0.
  @libsecp256k1_signature_test_cases [
    %{
      # sha256("Satoshi Nakamoto")
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E,
      der:
        "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
    },
    %{
      # sha256("Alan Turing")
      d: 0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181,
      z: 0x4BA38D48A60F1B29E9EB726EAFF08B2E83D8D81E031666FEE50E85900D7DC1EF,
      der:
        "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
    },
    %{
      # double_sha256("hello world")
      d: 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
      z: 0xBC62D4B80D9E36DA29C16C5D4D9F11731F36052C72401A76C23C0FB5A9B74423,
      der:
        "3044022008b772f5016f3d4d7ee74e8abd864e74a2ce1737695b77c82b5ef41967820f0d02206133f649c1719feb414f2d7389649ca303be5fc18cfb20de36cdeb5bb17c30a1"
    },
    %{
      # z == 0
      d: 0xE91671C46231F833A6406CCBEA0E3E392C76C167BAC1CB013F6F1013980455C2,
      z: 0x0000000000000000000000000000000000000000000000000000000000000000,
      der:
        "3045022100a16a97c44ac41c22edc3773fbac1298e2e87d0bff3c1d14cdc27adc9ab5ee57e02202badd4686a4d8f9bf506c5505a2a6afb1feb801f0f970e114eccaccb23764dce"
    },
    %{
      # sha256("bitcoinex"), d == n - 1
      d: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
      z: 0x32A95CD4352F083547FAFC9659E3E570D471DF8EB4C98BBFD3F176684BD42C02,
      der:
        "304402204f1bddc63916162929b7060bf0bc368fba7524e33c00828a49dd26ef7f15985f0220172060464c2796e715ebd23c6b06a360231630efcd55ec46b2242f5ec1608b02"
    },
    %{
      # z == n, which libsecp256k1 reduces to 0 exactly as bits2octets does
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      der:
        "3045022100a0b37f8fba683cc68f6574cd43b39f0343a50008bf6ccea9d13231d9e7e2e1e4022011edc8d307254296264aebfc3dc76cd8b668373a072fd64665b50000e9fcce52"
    },
    %{
      # z == 2^256 - 1, above n
      d: 0x0000000000000000000000000000000000000000000000000000000000000001,
      z: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
      der:
        "304402207cb38cc5712e9e11a767615f6080dbc111c9cdd613eb98999fd92a86bafd454002207923ca1f4d03471d2866f776ef8a6d3cac099b427331aeb245aa9dafeddcf115"
    }
  ]

  # Boundary values of z, in particular the ones around the bits2octets
  # reduction at z == n. A 32-byte hash can take any of these values.
  @z_boundaries [
    0,
    1,
    @n - 1,
    @n,
    @n + 1,
    @n + 12_345,
    Bitwise.bsl(1, 256) - 1
  ]

  defp random_z do
    32
    |> :crypto.strong_rand_bytes()
    |> :binary.decode_unsigned()
  end

  defp random_secret do
    d = random_z()
    if d >= 1 and d < @n, do: d, else: random_secret()
  end

  describe "test deterministic k calculation" do
    test "successfully derive correct k value" do
      for t <- @rfc6979_test_cases do
        p = %PrivateKey{d: t.d}
        z = :binary.decode_unsigned(:crypto.hash(:sha256, t.m))
        assert Ecdsa.deterministic_k(p, z) == %PrivateKey{d: t.k}
      end
    end

    test "matches python-ecdsa at and above the bits2octets reduction boundary" do
      for t <- @rfc6979_reduction_test_cases do
        assert Ecdsa.deterministic_k(%PrivateKey{d: t.d}, t.z) == %PrivateKey{d: t.k},
               "deterministic_k diverged from python-ecdsa at d=0x#{Integer.to_string(t.d, 16)}, z=0x#{Integer.to_string(t.z, 16)}"
      end
    end

    test "reduces z by n exactly as bits2octets does, so k(n + x) == k(x)" do
      # RFC 6979 2.3.4 subtracts q from z when z >= q. z == n (x == 0) is the
      # only input where a strict > comparison differs, and it is the case a
      # naive implementation gets wrong.
      for t <- @rfc6979_test_cases, x <- [0, 1, 2, 12_345, Bitwise.bsl(1, 128)] do
        p = %PrivateKey{d: t.d}
        assert Ecdsa.deterministic_k(p, @n + x) == Ecdsa.deterministic_k(p, x)
      end
    end

    test "always returns a k in [1, n-1]" do
      for _ <- 1..100 do
        %PrivateKey{d: k} = Ecdsa.deterministic_k(%PrivateKey{d: random_secret()}, random_z())
        assert k >= 1 and k < @n
      end

      for t <- @rfc6979_test_cases, z <- @z_boundaries do
        %PrivateKey{d: k} = Ecdsa.deterministic_k(%PrivateKey{d: t.d}, z)
        assert k >= 1 and k < @n
      end
    end

    test "k depends on both the private key and the message hash" do
      z = random_z()
      d1 = random_secret()
      d2 = random_secret()

      k1 = Ecdsa.deterministic_k(%PrivateKey{d: d1}, z)
      # same inputs, same k
      assert k1 == Ecdsa.deterministic_k(%PrivateKey{d: d1}, z)
      # different key, different k
      assert k1 != Ecdsa.deterministic_k(%PrivateKey{d: d2}, z)
      # different message, different k
      assert k1 != Ecdsa.deterministic_k(%PrivateKey{d: d1}, z + 1)
    end
  end

  describe "interoperability with libsecp256k1" do
    test "sign/2 reproduces libsecp256k1's deterministic signatures byte for byte" do
      for t <- @libsecp256k1_signature_test_cases do
        der =
          %PrivateKey{d: t.d}
          |> Ecdsa.sign(t.z)
          |> Signature.der_serialize_signature()
          |> Base.encode16(case: :lower)

        assert der == t.der,
               "diverged from libsecp256k1 at d=0x#{Integer.to_string(t.d, 16)}, z=0x#{Integer.to_string(t.z, 16)}"
      end
    end
  end

  describe "interoperability with OpenSSL (:crypto)" do
    test "signatures produced by sign/2 verify under :crypto" do
      for _ <- 1..1000 do
        privkey = %PrivateKey{d: random_secret()}
        pubkey = PrivateKey.to_point(privkey)

        digest = :crypto.strong_rand_bytes(32)
        z = :binary.decode_unsigned(digest)

        der =
          privkey
          |> Ecdsa.sign(z)
          |> Signature.der_serialize_signature()

        pubkey_bytes = pubkey |> Point.serialize_public_key() |> Base.decode16!(case: :lower)

        assert :crypto.verify(:ecdsa, :sha256, {:digest, digest}, der, [
                 pubkey_bytes,
                 :secp256k1
               ])
      end
    end

    test "signatures produced by :crypto verify under verify_signature/3" do
      for _ <- 1..1000 do
        d = random_secret()
        privkey = %PrivateKey{d: d}
        pubkey = PrivateKey.to_point(privkey)

        digest = :crypto.strong_rand_bytes(32)
        z = :binary.decode_unsigned(digest)
        secret_bytes = Bitcoinex.Utils.pad(:binary.encode_unsigned(d), 32, :leading)

        der = :crypto.sign(:ecdsa, :sha256, {:digest, digest}, [secret_bytes, :secp256k1])

        assert {:ok, sig} = Signature.der_parse_signature(der)
        assert Ecdsa.verify_signature(pubkey, z, sig)
      end
    end

    test "verify_signature/3 rejects a signature over a different message" do
      privkey = %PrivateKey{d: random_secret()}
      pubkey = PrivateKey.to_point(privkey)
      z = random_z()
      sig = Ecdsa.sign(privkey, z)

      assert Ecdsa.verify_signature(pubkey, z, sig)
      refute Ecdsa.verify_signature(pubkey, z - 1, sig)
      refute Ecdsa.verify_signature(pubkey, z, %Signature{sig | r: sig.r + 1})
      refute Ecdsa.verify_signature(pubkey, z, %Signature{sig | s: sig.s + 1})
      refute Ecdsa.verify_signature(PrivateKey.to_point(%PrivateKey{d: random_secret()}), z, sig)
    end
  end

  describe "ecdsa_recover_compact/3" do
    test "successfully recover a public key from a signature" do
      for t <- @valid_signatures_for_public_key_recovery do
        assert {:ok, recovered_pubkey} =
                 Ecdsa.ecdsa_recover_compact(t.message_hash, t.signature, t.recovery_id)

        assert recovered_pubkey == t.pubkey
      end
    end

    test "unsuccessfully recover a public key from a signature" do
      for t <- @invalid_signatures_for_public_key_recovery do
        assert {:error, _error} =
                 Ecdsa.ecdsa_recover_compact(t.message_hash, t.signature, t.recovery_id)
      end
    end
  end

  describe "sign/2" do
    test "successfully sign message with private key" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}
      msg = "hello world"

      correct_sig = %Signature{
        r:
          51_171_856_268_621_681_203_379_064_931_680_562_348_117_352_680_621_396_833_116_333_722_055_478_120_934,
        s:
          17_455_962_327_778_698_045_206_777_017_096_967_323_286_973_535_288_379_967_544_467_291_763_458_630_546
      }

      correct_der =
        "3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392"

      z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(msg))
      sig = Ecdsa.sign(sk, z)
      assert sig == correct_sig
      der = Signature.der_serialize_signature(sig)
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

        sig = Ecdsa.sign(privkey, z)
        assert Ecdsa.verify_signature(pubkey, z, sig)
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
        sig = Ecdsa.sign(privkey, z)
        assert Ecdsa.verify_signature(pubkey, z, sig)
      end
    end
  end

  describe "verify_signature/3" do
    test "successfully verify signature with pubkey and message hash" do
      for t <- @valid_signature_pubkey_sighash_sets do
        z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(t.msg))
        sig = Ecdsa.sign(t.privkey, z)
        assert sig == t.signature
        assert Ecdsa.verify_signature(t.pubkey, z, sig)
      end
    end
  end
end
