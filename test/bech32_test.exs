defmodule Bitcoinex.Bech32Test do
  use ExUnit.Case
  doctest Bitcoinex.Bech32

  alias Bitcoinex.Bech32

  @valid_bech32 [
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
  ]

  @invalid_bech32_hrp_char_out_of_range [
    <<0x20, "1nwldj5">>,
    <<0x7F, "1axkwrx">>,
    <<0x90::utf8, "1eym55h">>
  ]

  @invalid_bech32_max_length_exceeded [
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
  ]

  @invalid_bech32_no_separator_character [
    "pzry9x0s0muk"
  ]

  @invalid_bech32_empty_hrp [
    "1pzry9x0s0muk",
    "10a06t8",
    "1qzzfhee"
  ]

  @invalid_bech32_checksum [
    "A12UEL5A"
  ]

  @invalid_bech32_invalid_data_character [
    "x1b4n0q5v"
  ]

  @invalid_bech32_too_short_checksum [
    "li1dgmt3"
  ]

  @invalid_bech32_invalid_character_in_checksum [
    <<"de1lg7wt", 0xFF::utf8>>
  ]

  describe "decode/1" do
    test "successfully decode with valid bech32" do
      for bech <- @valid_bech32 do
        assert {:ok, {hrp, data}} = Bech32.decode(bech)
        assert hrp != nil

        # encode after decode should be the same(after downcase) as before
        {:ok, new_bech} = Bech32.encode(hrp, data)
        assert new_bech == String.downcase(bech)
      end
    end

    test "fail to decode with invalid bech32 out of ranges" do
      for bech <- @invalid_bech32_hrp_char_out_of_range do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :hrp_char_out_opf_range
      end
    end

    test "fail to decode with invalid bech32 overall max length exceeded" do
      for bech <- @invalid_bech32_max_length_exceeded do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :overall_max_length_exceeded
      end
    end

    test "fail to decode with invalid bech32 no separator character" do
      for bech <- @invalid_bech32_no_separator_character do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :no_separator_character
      end
    end

    test "fail to decode with invalid bech32 empty hrp" do
      for bech <- @invalid_bech32_empty_hrp do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :empty_hrp
      end
    end

    test "fail to decode with invalid data character" do
      for bech <- @invalid_bech32_invalid_data_character do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :contain_invalid_data_char
      end
    end

    test "fail to decode with too short checksum" do
      for bech <- @invalid_bech32_too_short_checksum do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :too_short_checksum
      end
    end

    test "fail to decode with invalid character in checksum" do
      for bech <- @invalid_bech32_invalid_character_in_checksum do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :contain_invalid_data_char
      end
    end

    test "fail to decode with invalid checksum" do
      for bech <- @invalid_bech32_checksum do
        assert {:error, msg} = Bech32.decode(bech)
        assert msg == :invalid_checksum
      end
    end
  end

  describe "encode/2" do
    test "successfully encode with valid hrp and empty data" do
      assert {:ok, _bech} = Bech32.encode("bc", [])
    end

    test "successfully encode with valid hrp and non empty valid data" do
      assert {:ok, _bech} = Bech32.encode("bc", [1, 2])
    end

    test "successfully encode with invalid string data" do
      assert {:ok, _bech} = Bech32.encode("bc", "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    end

    test "fail to encode with valid hrp and non empty valid string data" do
      assert {:error, bech} = Bech32.encode("bc", "qpzry9x8gf2tvdw0s3jn54khce6mua7lo")
    end

    test "fail to encode with overall encoded length is over 90" do
      data = for _ <- 1..82, do: 1
      assert {:error, :overall_max_length_exceeded} = Bech32.encode("bc", data)
    end

    test "fail to encode with hrp contain invalid char(out of 1 to 83 US-ASCII)" do
      data = [1]
      assert {:error, :hrp_char_out_opf_range} = Bech32.encode(" ", data)
      assert {:error, :hrp_char_out_opf_range} = Bech32.encode("\ł", data)
      assert {:error, :hrp_char_out_opf_range} = Bech32.encode("中文", data)
    end
  end
end
