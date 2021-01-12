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
                PrivateKey.wif!(sk, :mainnet)
            assert "cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm" ==
                PrivateKey.wif!(sk, :testnet)
        end
    end

    describe "parse_wif/1" do
        test "successfully return private key from wif str" do
            sk = %PrivateKey{s: 123414253234542345423623}
            wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E"
            assert {:ok, sk, :mainnet, true} == PrivateKey.parse_wif(wif)
            twif = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm"
            assert {:ok, sk, :testnet, true} == PrivateKey.parse_wif(twif)
        end
    end

    describe "parse & serialize wif" do
        test "successfully return private key from wif str" do
            sk = %PrivateKey{s: 123414253234542345423623}
            wif = PrivateKey.wif!(sk, :mainnet)
            assert {:ok, sk, :mainnet, true} == PrivateKey.parse_wif(wif)
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
            correct_der = "3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392"
            z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(msg))
            sig = PrivateKey.sign(sk, z)
            assert sig == correct_sig
            der = Bitcoinex.Secp256k1.Signature.der_serialize_signature(sig)
            assert Base.encode16(der, case: :lower) == correct_der
        end
    end

    describe "fuzz test signing" do
        setup do
            privkey = %PrivateKey{s: 123414253234542345423623}
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
                privkey = %PrivateKey{s: secret}
                pubkey = PrivateKey.to_point(privkey)
                sig = PrivateKey.sign(privkey, z)
                assert Bitcoinex.Secp256k1.verify_signature(pubkey, z, sig)
            end
        end
    end



end