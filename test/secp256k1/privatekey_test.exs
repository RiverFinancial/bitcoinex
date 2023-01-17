defmodule Bitcoinex.Secp256k1.PrivateKeyTest do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1.PrivateKey

  alias Bitcoinex.Secp256k1.PrivateKey

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
end
