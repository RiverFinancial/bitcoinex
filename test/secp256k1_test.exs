defmodule Bitcoinex.Secp256k1Test do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1

  alias Bitcoinex.Secp256k1

  @valid_signatures_for_public_key_recovery [
    %{
      message_hash:
        :binary.encode_unsigned(
          0xCE0677BB30BAA8CF067C88DB9811F4333D131BF8BCF12FE7065D211DCE971008
        ),
      signature:
        :binary.encode_unsigned(
          0x90F27B8B488DB00B00606796D2987F6A5F59AE62EA05EFFE84FEF5B8B0E549984A691139AD57A3F0B906637673AA2F63D1F55CB1A69199D4009EEA23CEADDC93
        ),
      recovery_id: 1,
      pubkey: "02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a"
    }
  ]

  @invalid_signatures_for_public_key_recovery [
    %{
      # invalid curve point
      message_hash:
        :binary.encode_unsigned(
          0x00C547E4F7B0F325AD1E56F57E26C745B09A3E503D86E00E5255FF7F715D3D1C
        ),
      signature:
        <<0x00>> <>
          :binary.encode_unsigned(
            0x00B1693892219D736CABA55BDB67216E485557EA6B6AF75F37096C9AA6A5A75F00B940B1D03B21E36B0E47E79769F095FE2AB855BD91E3A38756B7D75A9C4549
          ),
      recovery_id: 0
    },
    %{
      # Low r and s.
      message_hash:
        :binary.encode_unsigned(
          0xBA09EDC1275A285FB27BFE82C4EEA240A907A0DBAF9E55764B8F318C37D5974F
        ),
      signature:
        :binary.encode_unsigned(
          0x00000000000000000000000000000000000000000000000000000000000000002C0000000000000000000000000000000000000000000000000000000000000004
        ),
      recovery_id: 1
    }
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
end
