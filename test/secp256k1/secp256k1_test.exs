defmodule Bitcoinex.Secp256k1.Secp256k1Test do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1

  alias Bitcoinex.Secp256k1

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

  @valid_der_signatures [
    %{
      #valid signature from 3ea1a64c550ff91c6faba076aa776faa60aa524b48a54801d458d1c927333c8f:0
      der_signature:
        Base.decode16!(
          "3044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        ),
      obj_signature:
        %Secp256k1.Signature{
          r: 3086008707114705845761137809128827774006369836063216572143683251326398205321,
          s: 48832473706270939780454642696934734127348929209136601810472271862324755985375
        }
        #pubkey: 027246ae6ffc3e4be3a2b3ee7392dc484a1d285f190a0532a514db5be823bcdd81
    },
    %{
      #valid signature from 40352adf6fba255e083c60a21f9f85774ce7c97017f542bf22c63be2ef9f366b:0
      # no high bits
      der_signature:
        Base.decode16!(
          "30440220363d2376abd4d166ee712210a8b92fc8713b93140103a618eeafd41d1497dca20220175894aee64dbfb35199a351b8fe2742aea529092e0473de3227f848eee162f6",
          case: :lower
        ),
        obj_signature:
          %Secp256k1.Signature{
            r: 24532916254939660922795650783597793726391618675384527964949105336796168314018,        
            s: 10559704232859480938506730553108837258684636748731694899240401738284146975478
          },
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
        obj_signature:
          %Secp256k1.Signature{
            r: 68438297700591931769061022939284422764636608635142803529940449930283506511908,
            s: 39287500746169653973150952458317583883135951896192490367558600116141508905705
          }
    },
    %{
      # valid signature from private_key used in privatekey_test.exs and msg "hello world"
      der_signature:
        Base.decode16!(
          "3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392",
          case: :lower
        ),
      obj_signature:
        %Secp256k1.Signature{
          r: 51171856268621681203379064931680562348117352680621396833116333722055478120934,
          s: 17455962327778698045206777017096967323286973535288379967544467291763458630546
        },
    }
  ]

  @invalid_der_signatures [
    %{
      #invalid signature - incorrect prefix
      der_signature:
        Base.decode16!(
          "4044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    },
    %{
      #invalid signature - sighash appended
      der_signature:
        Base.decode16!(
          "3044022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df01",
          case: :lower
        )
    },
    %{
      #invalid signature - missing key marker
      der_signature:
        Base.decode16!(
          "30442006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    },
    %{
      #invalid signature - incorrect length byte
      der_signature:
        Base.decode16!(
          "3043022006d29e78c6698c6338b2c216aa15a455b50833c6d850078e1a29292df8a38d8902206bf6335e3eee06df655933a31653e9d8e2ef39abb71c12065bc4f9a98e8473df",
          case: :lower
        )
    }
  ]

  @valid_signature_pubkey_sighash_sets [
    %{
      # valid signature from private_key used in privatekey_test.exs and msg "hello world"
      privkey:
       %Secp256k1.PrivateKey{s: 123414253234542345423623},
      # 3044022071223e8822fafbc0b09336d3f2a92fd7970a354d40185d69a297e0500e6c91e602202697b97c52da81a9328fd65a0ad883545f162cc3e5e2c70ea226c0d1cd4ae392
      signature: 
        %Secp256k1.Signature{
          r: 51171856268621681203379064931680562348117352680621396833116333722055478120934,
          s: 17455962327778698045206777017096967323286973535288379967544467291763458630546
        },
      # "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
      pubkey: 
        %Secp256k1.Point{
          x: 26725119729089203965150132282997341343516273140835737223575952640907021258522,
          y: 35176335436138229778595179837068778482032382451813967420917290469529927283651
        },
      msg: "hello world"
    },
  ]

  describe "ecdsa_recover_compact/3" do
    test "successfully recover a public key from a signature" do
      for t <- @valid_signatures_for_public_key_recovery do
        assert {:ok, recovered_pubkey} =
                 Secp256k1.ecdsa_recover_compact(t.message_hash, t.signature, t.recovery_id)

        assert recovered_pubkey == t.pubkey
      end
    end

    test "unsuccessfully recover a public key from a signature" do
      for t <- @invalid_signatures_for_public_key_recovery do
        assert {:error, _error} =
                 Secp256k1.ecdsa_recover_compact(t.message_hash, t.signature, t.recovery_id)
      end
    end
  end

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

  describe "verify_signature/3" do
    test "successfully verify signature with pubkey and message hash" do
      for t <- @valid_signature_pubkey_sighash_sets do
        z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(t.msg))
        sig = Secp256k1.PrivateKey.sign(t.privkey, z)
        assert sig == t.signature
        assert Secp256k1.verify_signature(t.pubkey, z, sig)
      end
    end
  end
end
