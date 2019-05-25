defmodule Bitcoinex.Base58Test do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.Base58

  @base58_alphabets ~c(123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
  alias Bitcoinex.Base58

  describe "int_to_bin/1" do
    property "bin_to_int(int_to_bin(x)) should return x" do
      check all int <- filter(integer(), &(&1 >= 0)) do
        assert Base58.bin_to_int(Base58.int_to_bin(int)) == int
      end
    end
  end

  describe "bin_to_int/1" do
    property "int_to_bin(bin_to_int(x)) should return x" do
      check all base58 <- base58_string_stream() do
        assert Base58.int_to_bin(Base58.bin_to_int(base58)) == base58
      end
    end
  end

  describe "str_to_bin/1" do
    property "bin_to_str(str_to_bin(x)) should return x" do
      check all base58_str <- base58_string_stream() do
        assert Base58.bin_to_str(Base58.str_to_bin(base58_str)) == base58_str
      end
    end
  end

  defp base58_string_stream() do
    filter(
      list_of(one_of(@base58_alphabets |> Enum.map(&constant(&1))))
      |> map(&List.to_string/1)
      |> map(&remove_pad_one/1),
      &(&1 != "")
    )
  end

  defp remove_pad_one(<<?1, rest::binary>>) do
    remove_pad_one(rest)
  end

  defp remove_pad_one(result) do
    result
  end
end
