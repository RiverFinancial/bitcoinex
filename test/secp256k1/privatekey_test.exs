defmodule Bitcoinex.Secp256k1.PrivateKeyTest do
  use ExUnit.Case, async: true
  doctest Bitcoinex.Secp256k1.PrivateKey

  alias Bitcoinex.Secp256k1.PrivateKey

  @invalid_d 121_323_999_992_657_324_658_723_658_726_345_764_256_782_657_878_654_278_542_782_453_786_524_378_542_738

  describe "serialize_private_key/1" do
    test "successfully pad private key" do
      sk = %PrivateKey{d: 123_414_253_234_542_345_423_623}

      assert "000000000000000000000000000000000000000000001a224cd1a01427f38b07" ==
               PrivateKey.serialize_private_key(sk)
    end
  end

  describe "to_point/1" do
    test "invalid private key" do
      sk = %PrivateKey{d: @invalid_d}

      assert {:error, "invalid private key out of range."} ==
               PrivateKey.to_point(sk)
    end

    test "valid from integer" do
      assert PrivateKey.to_point(1) ==
               %Bitcoinex.Secp256k1.Point{
                 x:
                   55_066_263_022_277_343_669_578_718_895_168_534_326_250_603_453_777_594_175_500_187_360_389_116_729_240,
                 y:
                   32_670_510_020_758_816_978_083_085_130_507_043_184_471_273_380_659_243_275_938_904_335_757_337_482_424,
                 z: 0
               }
    end

    test "invalid private key from integer" do
      assert {:error, "invalid private key out of range."} ==
               PrivateKey.to_point(@invalid_d)
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
end
