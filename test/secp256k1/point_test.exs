defmodule Bitcoinex.Secp256k1.PointTest do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1.Point

  alias Bitcoinex.Secp256k1.Point

  describe "serialize_public_key/1" do
    test "successfully pad public key" do
      assert "020003b94aecea4d0a57a6c87cf43c50c8b3736f33ab7fd34f02441b6e94477689" ==
               Point.serialize_public_key(%Point{
                 x:
                   6_579_384_254_631_425_969_190_483_614_785_133_746_155_874_651_439_631_590_927_590_192_220_436_105,
                 y:
                   71_870_263_570_581_286_056_939_190_487_148_011_225_641_308_782_404_760_504_903_461_107_415_970_265_024
               })
    end
  end

  describe "parse_public_key/1" do
    test "successfully parse public key from sec" do
      sec =
        Base.decode16!("033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a",
          case: :lower
        )

      assert Point.parse_public_key(sec) ==
               %Point{
                 x:
                   26_725_119_729_089_203_965_150_132_282_997_341_343_516_273_140_835_737_223_575_952_640_907_021_258_522,
                 y:
                   35_176_335_436_138_229_778_595_179_837_068_778_482_032_382_451_813_967_420_917_290_469_529_927_283_651
               }
    end

    test "successfully parse uncompressed key from sec" do
      sec =
        Base.decode16!(
          "048fdc3d8944cc8d8fe6c666c41a8ed42e60aa399861a756707e127a80b383d178edfbf94dda0487f7910d130f2a37a0647be9335eab5b8d3aa5242445e1604024",
          case: :lower
        )

      assert Point.parse_public_key(sec) ==
               %Point{
                 x: 0x8FDC3D8944CC8D8FE6C666C41A8ED42E60AA399861A756707E127A80B383D178,
                 y: 0xEDFBF94DDA0487F7910D130F2A37A0647BE9335EAB5B8D3AA5242445E1604024
               }
    end

    test "successfully parse compressed key from sec hex" do
      sec = "0299d7ff3d96c731e54e75637798cab801fe80827191e280f53427bc8915323e8b"

      pk = %Point{
        x:
          69_585_499_557_921_076_123_288_400_932_281_161_043_766_220_600_235_811_505_715_105_664_976_077_078_155,
        y:
          102_549_807_389_226_195_103_316_638_704_859_105_787_106_440_500_810_433_784_118_696_258_589_643_376_818,
        z: 0
      }

      assert Point.parse_public_key(sec) == pk
      assert Point.serialize_public_key(pk) == sec
    end
  end

  describe "sec/1" do
    test "successfully calculate SEC encoding and hash160 of public key" do
      correct_hash160 = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"

      hash160 =
        %Point{
          x:
            26_725_119_729_089_203_965_150_132_282_997_341_343_516_273_140_835_737_223_575_952_640_907_021_258_522,
          y:
            35_176_335_436_138_229_778_595_179_837_068_778_482_032_382_451_813_967_420_917_290_469_529_927_283_651
        }
        |> Point.sec()
        |> Bitcoinex.Utils.hash160()
        |> Base.encode16(case: :lower)

      assert correct_hash160 == hash160
    end
  end
end
