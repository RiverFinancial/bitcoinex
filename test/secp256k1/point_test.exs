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
      sec = Base.decode16!("033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a", case: :lower)
      assert Point.parse_public_key(sec) ==
               %Point{
                 x:
                 26725119729089203965150132282997341343516273140835737223575952640907021258522,
                 y:
                 35176335436138229778595179837068778482032382451813967420917290469529927283651
               }
    end
    test "successfully parse uncompressed key from sec" do
      sec = Base.decode16!("048fdc3d8944cc8d8fe6c666c41a8ed42e60aa399861a756707e127a80b383d178edfbf94dda0487f7910d130f2a37a0647be9335eab5b8d3aa5242445e1604024", case: :lower)
      assert Point.parse_public_key(sec) == 
        %Point{
          x: 0x8fdc3d8944cc8d8fe6c666c41a8ed42e60aa399861a756707e127a80b383d178,
          y: 0xedfbf94dda0487f7910d130f2a37a0647be9335eab5b8d3aa5242445e1604024
        }
    end
  end

  describe "sec/1" do
    test "successfully calculate SEC encoding and hash160 of public key" do
      correct_hash160 = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
      hash160 = %Point{
          x: 26725119729089203965150132282997341343516273140835737223575952640907021258522,
          y: 35176335436138229778595179837068778482032382451813967420917290469529927283651
        }
        |> Point.sec()
        |> Bitcoinex.Utils.hash160()
        |> Base.encode16(case: :lower)
      assert correct_hash160 == hash160
    end
  end
end