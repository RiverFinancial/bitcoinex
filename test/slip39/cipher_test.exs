defmodule Bitcoinex.SLIP39.CipherTest do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.SLIP39.Cipher

  alias Bitcoinex.SLIP39.Cipher
  alias Bitcoinex.Utils

  @ms16 Base.decode16!("0ff784df000c4380a5ed683f7e6e3dcf", case: :lower)
  @ms32 Base.decode16!(
          "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92",
          case: :lower
        )

  describe "encrypt/5 and decrypt/5" do
    test "reject odd-length and empty input at the function boundary" do
      for bad <- [<<1>>, :binary.copy(<<1>>, 17), <<>>] do
        assert_raise FunctionClauseError, fn -> Cipher.encrypt(bad, "", 0, 0, false) end
        assert_raise FunctionClauseError, fn -> Cipher.decrypt(bad, "", 0, 0, false) end
      end
    end

    test "round-trip identity across ext, e, passphrase, and MS length" do
      for ms <- [@ms16, @ms32],
          passphrase <- ["", "TREZOR"],
          e <- [0, 1],
          ext <- [true, false] do
        ems = Cipher.encrypt(ms, passphrase, e, 3141, ext)
        assert byte_size(ems) == byte_size(ms)
        assert ems != ms
        assert Cipher.decrypt(ems, passphrase, e, 3141, ext) == ms
      end
    end

    test "extendable flag selects the salt" do
      ems_ext = Cipher.encrypt(@ms16, "pw", 0, 123, true)
      ems_orig = Cipher.encrypt(@ms16, "pw", 0, 123, false)

      # ext == true (empty salt) vs ext == false ("shamir" <> id) must differ
      # for otherwise-identical inputs.
      assert ems_ext != ems_orig

      # Extendable shares use an empty salt, so the identifier is ignored.
      assert Cipher.encrypt(@ms16, "pw", 0, 456, true) == ems_ext

      # Non-extendable shares salt with "shamir" <> <<id::16>>, so the
      # identifier changes the ciphertext.
      refute Cipher.encrypt(@ms16, "pw", 0, 456, false) == ems_orig
    end

    test "iteration exponent is threaded into the round function" do
      ems_e0 = Cipher.encrypt(@ms16, "pw", 0, 123, true)
      ems_e1 = Cipher.encrypt(@ms16, "pw", 1, 123, true)

      assert ems_e0 != ems_e1
      # decrypting with the wrong exponent yields a different (wrong) MS
      refute Cipher.decrypt(ems_e0, "pw", 1, 123, true) == @ms16
    end

    # Official vector index 0 from test/data/slip39_vectors.json:
    # "1. Valid mnemonic without sharing (128 bits)", passphrase "TREZOR".
    # The Share codec does not exist yet (PR S5), so the EMS and cipher
    # parameters are hand-extracted from the mnemonic's wire layout by
    # extract_share_params/1 below.
    test "known-answer: decrypts the EMS embedded in official vector 1" do
      mnemonic =
        "duckling enlarge academic academic agency result length solution fridge " <>
          "kidney coal piece deal husband erode duke ajar critical decision keyboard"

      ms = Base.decode16!("bb54aac4b89dc868ba37d9cc21b2cece", case: :lower)

      {identifier, extendable, iteration_exponent, ems} =
        extract_share_params(mnemonic, byte_size(ms))

      # Lock down the extraction itself so a helper bug cannot mask a cipher bug.
      assert identifier == 7945
      assert extendable == false
      assert iteration_exponent == 0

      assert Cipher.decrypt(ems, "TREZOR", iteration_exponent, identifier, extendable) == ms
      # encryption is the exact inverse
      assert Cipher.encrypt(ms, "TREZOR", iteration_exponent, identifier, extendable) == ems
    end

    # Official vector index 19 from test/data/slip39_vectors.json:
    # "20. Valid mnemonic without sharing (256 bits)", passphrase "TREZOR".
    # A 33-word share exercises a longer EMS and a different pad width (4 bits)
    # than the 128-bit vector, catching half-splitting or length bugs that a
    # same-length round-trip cannot.
    test "known-answer: decrypts the EMS embedded in official vector 20 (256 bits)" do
      mnemonic =
        "theory painting academic academic armed sweater year military elder discuss " <>
          "acne wildlife boring employer fused large satoshi bundle carbon diagnose " <>
          "anatomy hamster leaves tracks paces beyond phantom capital marvel lips " <>
          "brave detect luck"

      ms = @ms32

      {identifier, extendable, iteration_exponent, ems} =
        extract_share_params(mnemonic, byte_size(ms))

      # Lock down the extraction itself so a helper bug cannot mask a cipher bug.
      assert identifier == 29_172
      assert extendable == false
      assert iteration_exponent == 0

      assert Cipher.decrypt(ems, "TREZOR", iteration_exponent, identifier, extendable) == ms
      # encryption is the exact inverse
      assert Cipher.encrypt(ms, "TREZOR", iteration_exponent, identifier, extendable) == ems
    end
  end

  property "decrypt(encrypt(ms, ...), ...) == ms" do
    check all(
            half_len <- integer(8..16),
            ms <- binary(length: half_len * 2),
            passphrase <- string(:ascii, max_length: 16),
            e <- integer(0..2),
            ext <- boolean(),
            identifier <- integer(0..0x7FFF)
          ) do
      ems = Cipher.encrypt(ms, passphrase, e, identifier, ext)
      assert Cipher.decrypt(ems, passphrase, e, identifier, ext) == ms
    end
  end

  # TODO(S5): replace this hand-rolled extraction with the real Share codec
  # once it lands, so the known-answer test exercises production parsing rather
  # than a test-local reimplementation of the wire layout.
  #
  # Hand-extracts (identifier, extendable, iteration_exponent, ems) from a
  # 1-of-1 SLIP-39 share mnemonic, following the wire layout in the SLIP-39
  # spec (each word is a 10-bit index into priv/slip39_english.txt):
  #
  #   N words * 10 bits total; the last 3 words (30 bits) are the RS1024
  #   checksum, leaving (N - 3) * 10 data bits:
  #
  #   <<identifier::15, ext::1, iteration_exponent::4,
  #     group_index::4, group_threshold-1::4, group_count-1::4,
  #     member_index::4, member_threshold-1::4,          # 40 metadata bits
  #     padding::pad_bits, share_value::binary-size(n)>>  # padded share value
  #
  #   The share value is left-padded with zero bits to word-align the mnemonic.
  #   For a 1-of-1 share the share value IS the encrypted master secret (EMS),
  #   whose byte length equals the master secret's, so the caller passes
  #   `ems_bytes` and the padding width is whatever remains. (The pad width is
  #   not always < 8 — a 24-byte secret pads with 8 bits — so it cannot be
  #   inferred from the value length alone; the caller-supplied size is exact.)
  defp extract_share_params(mnemonic, ems_bytes) do
    indices =
      mnemonic
      |> String.split()
      # strip the 3 RS1024 checksum words
      |> Enum.drop(-3)
      |> Enum.map(&Map.fetch!(word_index(), &1))

    bits = Utils.int_list_to_bits(indices, 10)
    pad_bits = bit_size(bits) - 40 - ems_bytes * 8

    <<identifier::15, ext_bit::1, iteration_exponent::4, _group_index::4, _group_threshold_m1::4,
      _group_count_m1::4, _member_index::4, _member_threshold_m1::4, 0::size(pad_bits),
      ems::binary-size(ems_bytes)>> = bits

    {identifier, ext_bit == 1, iteration_exponent, ems}
  end

  defp word_index do
    "priv/slip39_english.txt"
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.with_index()
    |> Map.new()
  end
end
