defmodule Bitcoinex.UtilsTest do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.Utils

  alias Bitcoinex.Utils

  describe "pbkdf2/5" do
    # BIP-39 seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations, 64 bytes.
    # Vector from trezor/python-mnemonic vectors.json (english[0], passphrase "TREZOR").
    test "derives the BIP-39 vector seed with sha512" do
      mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

      seed =
        Base.decode16!(
          "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
          case: :lower
        )

      assert Utils.pbkdf2(:sha512, mnemonic, "mnemonic" <> "TREZOR", 2048, 64) == seed
    end

    # RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector.
    test "derives the RFC 7914 vector with sha256" do
      expected =
        Base.decode16!(
          "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
          case: :lower
        )

      assert Utils.pbkdf2(:sha256, "passwd", "salt", 1, 64) == expected
    end

    test "key_len controls output size" do
      assert byte_size(Utils.pbkdf2(:sha256, "pw", "salt", 1, 16)) == 16
      assert byte_size(Utils.pbkdf2(:sha512, "pw", "salt", 1, 100)) == 100
    end
  end

  describe "int_list_to_bits/2" do
    test "packs 11-bit indices MSB-first" do
      # 1 -> 00000000001, 2 -> 00000000010, 3 -> 00000000011
      assert Utils.int_list_to_bits([1, 2, 3], 11) ==
               <<1::size(11), 2::size(11), 3::size(11)>>
    end

    test "packs 10-bit indices" do
      assert Utils.int_list_to_bits([1023, 0], 10) == <<1023::size(10), 0::size(10)>>
    end

    test "packs the maximum 11-bit value" do
      assert Utils.int_list_to_bits([2047], 11) == <<2047::size(11)>>
    end

    test "empty list yields empty bitstring" do
      assert Utils.int_list_to_bits([], 10) == <<>>
    end

    property "round-trips against the bitstring comprehension" do
      check all(
              width <- StreamData.member_of([10, 11]),
              ints <- StreamData.list_of(StreamData.integer(0..(2 ** width - 1)), max_length: 50)
            ) do
        bits = Utils.int_list_to_bits(ints, width)
        assert bit_size(bits) == length(ints) * width
        assert for(<<i::size(width) <- bits>>, do: i) == ints
      end
    end
  end
end
