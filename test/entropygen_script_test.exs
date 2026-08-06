# Load the script without running its CLI entrypoint.
System.put_env("ENTROPYGEN_SKIP_MAIN", "1")
Code.require_file("../scripts/entropygen.exs", __DIR__)

defmodule EntropyGenScriptTest do
  use ExUnit.Case, async: true

  setup_all do
    {:ok, words} = EntropyGen.load_wordlist()
    %{words: words}
  end

  describe "load_wordlist/0" do
    test "loads and verifies the vendored BIP-39 English wordlist", %{words: words} do
      assert tuple_size(words) == 2048
      assert elem(words, 0) == "abandon"
      assert elem(words, 2047) == "zoo"
    end
  end

  describe "self_check/1" do
    test "passes against the official BIP-39 vectors", %{words: words} do
      assert EntropyGen.self_check(words) == :ok
    end

    test "fails on a corrupted wordlist", %{words: words} do
      corrupted = put_elem(words, 3, "bogus")
      assert {:error, "BIP-39 self-check failed" <> _} = EntropyGen.self_check(corrupted)
    end
  end

  describe "encode_mnemonic/2" do
    # Official BIP-39 test vectors (128-bit entropy).
    @vectors [
      {"00000000000000000000000000000000",
       "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
      {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
       "legal winner thank year wave sausage worth useful legal winner thank yellow"},
      {"80808080808080808080808080808080",
       "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
      {"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
      {"9e885d952ad362caeb4efe34a8e91bd2",
       "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"}
    ]

    test "encodes official BIP-39 vectors", %{words: words} do
      for {ent_hex, expected} <- @vectors do
        ent = Base.decode16!(ent_hex, case: :lower)
        assert Enum.join(EntropyGen.encode_mnemonic(ent, words), " ") == expected
      end
    end
  end

  describe "parse_hex_csv/1" do
    test "parses comma-separated hex, ignoring spaces and empty segments" do
      assert EntropyGen.parse_hex_csv("00ff, a1b2c3d4e5f6,,DEADbeef") ==
               {:ok,
                [
                  <<0x00, 0xFF>>,
                  <<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>,
                  <<0xDE, 0xAD, 0xBE, 0xEF>>
                ]}
    end

    test "rejects non-hex input" do
      assert EntropyGen.parse_hex_csv("00ff,xyz") ==
               {:error, "inputs must be comma-separated hex strings"}
    end

    test "rejects odd-length hex" do
      assert EntropyGen.parse_hex_csv("abc") ==
               {:error, "inputs must be comma-separated hex strings"}
    end

    test "rejects empty input" do
      assert EntropyGen.parse_hex_csv("") == {:error, "no entropy given"}
      assert EntropyGen.parse_hex_csv(" , ,") == {:error, "no entropy given"}
    end
  end

  describe "mnemonic_words/2" do
    # Expected words computed with the Python reference implementation:
    # ent = sha256d(blob)[:16]; cs = sha256(ent)[0] >> 4;
    # val = int(ent) << 4 | cs; 12 big-endian 11-bit indices.
    test "matches the Python reference for deadbeef", %{words: words} do
      blob = Base.decode16!("deadbeef", case: :lower)

      assert EntropyGen.mnemonic_words(blob, words) ==
               ~w(chimney upgrade duck team hint dance boring woman differ radar clap kangaroo)
    end

    test "matches the Python reference for concatenated blobs", %{words: words} do
      blob = Base.decode16!("00ff", case: :lower) <> Base.decode16!("a1b2c3d4e5f6", case: :lower)

      assert EntropyGen.mnemonic_words(blob, words) ==
               ~w(mask range moral panda forget debris build loyal girl success wrist knee)
    end
  end

  describe "finalize_pool/1" do
    test "matches the Python reference construction" do
      # sha256d(<<0>> <> pool) <> sha256d(<<1>> <> pool) for pool "fixed test pool 123"
      expected =
        "3f1cb2073ad16f8524f46b857622224f525cff5402eabe8e8d9b81070ff7ab80" <>
          "2af64c6783f38941015943e5e693bc47a6b84f533e29c8f2566d7cf91c7f5bc0"

      out = EntropyGen.finalize_pool("fixed test pool 123")
      assert byte_size(out) == 64
      assert Base.encode16(out, case: :lower) == expected
    end
  end
end
