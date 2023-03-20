defmodule Bitcoinex.Secp256k1.Secp256k1Test do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1

  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.Signature

  @valid_der_signatures [
    %{
      # valid signature from 3ea1a64c550ff91c6faba076aa776faa60aa524b48a54801d458d1c927333c8f:0
      der_signature:
        Base.decode16!(
          "3044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        ),
      obj_signature: %Secp256k1.Signature{
        r:
          3_086_008_707_114_705_845_761_137_809_128_827_774_006_369_836_063_216_572_143_683_251_326_398_205_321,
        s:
          48_832_473_706_270_939_780_454_642_696_934_734_127_348_929_209_136_601_810_472_271_862_324_755_985_375
      }
      # pubkey: 027246ae6ffc3e4be3a2b3ee7392dc484a1d285f190a0532a514db5be823bcdd81
    },
    %{
      # valid signature from 40352adf6fba255e083c60a21f9f85774ce7c97017f542bf22c63be2ef9f366b:0
      # no high bits
      der_signature:
        Base.decode16!(
          "30440220363d2376abd4d166ee712210a8b92fc8713b93140103a618eeafd41d1497dca20220175894aee64dbfb35199a351b8fe2742aea529092e0473de3227f848eee162f6",
          case: :lower
        ),
      obj_signature: %Secp256k1.Signature{
        r:
          24_532_916_254_939_660_922_795_650_783_597_793_726_391_618_675_384_527_964_949_105_336_796_168_314_018,
        s:
          10_559_704_232_859_480_938_506_730_553_108_837_258_684_636_748_731_694_899_240_401_738_284_146_975_478
      }
      # pubkey: 027246ae6ffc3e4be3a2b3ee7392dc484a1d285f190a0532a514db5be823bcdd81
    },
    %{
      # valid signature from f8f6704f1e80da23d1865627046eaec1f3d1a3288937bf3d12b9a3327aaa91de:0
      # r high bit
      der_signature:
        Base.decode16!(
          "3045022100974eb42bbc729f95f537cc41d52b6029731a2149cbce8dfb9e335f76a0e8b024022056dbeffa20d7b4231708f110b1789ad5b021fcb235e75099d50b502eabf5cae9",
          case: :lower
        ),
      obj_signature: %Secp256k1.Signature{
        r:
          68_438_297_700_591_931_769_061_022_939_284_422_764_636_608_635_142_803_529_940_449_930_283_506_511_908,
        s:
          39_287_500_746_169_653_973_150_952_458_317_583_883_135_951_896_192_490_367_558_600_116_141_508_905_705
      }
    },
    %{
      # valid signature from private_key used in privatekey_test.exs and msg "hello world"
      der_signature:
        Base.decode16!(
          "3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392",
          case: :lower
        ),
      obj_signature: %Secp256k1.Signature{
        r:
          51_171_856_268_621_681_203_379_064_931_680_562_348_117_352_680_621_396_833_116_333_722_055_478_120_934,
        s:
          17_455_962_327_778_698_045_206_777_017_096_967_323_286_973_535_288_379_967_544_467_291_763_458_630_546
      }
    }
  ]

  @invalid_der_signatures [
    %{
      # invalid signature - incorrect prefix
      der_signature:
        Base.decode16!(
          "4044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    },
    %{
      # invalid signature - sighash appended
      der_signature:
        Base.decode16!(
          "3044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df01",
          case: :lower
        )
    },
    %{
      # invalid signature - missing key marker
      der_signature:
        Base.decode16!(
          "30442006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    },
    %{
      # invalid signature - incorrect length byte
      der_signature:
        Base.decode16!(
          "3043022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    }
  ]

  @valid_schnorr_signatures [
    "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"
  ]

  describe "der_parse_signature/1" do
    test "successfully parse valid signature from DER binary" do
      for t <- @valid_der_signatures do
        {state, parsed_sig} = Secp256k1.Signature.der_parse_signature(t.der_signature)
        assert state == :ok
        assert parsed_sig == t.obj_signature
        assert Secp256k1.Signature.der_serialize_signature(t.obj_signature) == t.der_signature
      end
    end

    test "unsuccessfully parse signature from DER binary" do
      for t <- @invalid_der_signatures do
        assert {:error, _error} = Secp256k1.Signature.der_parse_signature(t.der_signature)
      end
    end
  end

  describe "parse_signature/1" do
    test "parse 64-byte schnorr signatures from binary" do
      for t <- @valid_schnorr_signatures do
        {res, _sig} =
          t
          |> Base.decode16!(case: :upper)
          |> Signature.parse_signature()

        assert res == :ok
      end
    end

    test "parse 64-byte schnorr signatures from string" do
      for t <- @valid_schnorr_signatures do
        {res, _sig} =
          t
          |> Signature.parse_signature()

        assert res == :ok
      end
    end

    test "ensure equavalent sigs parsed from string and binary" do
      for t <- @valid_schnorr_signatures do
        {:ok, sig1} =
          t
          |> Base.decode16!(case: :upper)
          |> Signature.parse_signature()

        {:ok, sig2} =
          t
          |> Signature.parse_signature()

        assert sig1 == sig2
      end
    end
  end
end
