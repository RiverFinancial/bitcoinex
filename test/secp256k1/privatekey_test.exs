defmodule Bitcoinex.Secp256k1.PrivateKeyTest do
    use ExUnit.Case
    doctest Bitcoinex.Secp256k1.PrivateKey
  
    alias Bitcoinex.Secp256k1.PrivateKey
  
    describe "serialize_private_key/1" do
        test "successfully pad private key" do
            sk = %PrivateKey{s: 123414253234542345423623}
            assert "000000000000000000000000000000000000000000001a224cd1a01427f38b07" == 
                PrivateKey.serialize_private_key(sk)
        end
    end

    describe "wif/2" do
        test "successfully return private key wif encoding" do
            sk = %PrivateKey{s: 123414253234542345423623}
            assert "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E" ==
                PrivateKey.wif(sk, :mainnet)
            assert "cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm" ==
                PrivateKey.wif(sk, :testnet)
        end
    end

    describe "sign/2" do
        test "successfully sign message with private key" do
            sk = %PrivateKey{s: 123414253234542345423623}
            msg = "hello world"
            correct_sig = %Bitcoinex.Secp256k1.Signature{
                r: 51171856268621681203379064931680562348117352680621396833116333722055478120934,
                s: 17455962327778698045206777017096967323286973535288379967544467291763458630546
            }
            z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(msg))
            sig = PrivateKey.sign(sk, z)
            assert sig == correct_sig
        end
    end


end