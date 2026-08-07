defmodule Bitcoinex.LightningNetwork.InvoiceAmountTest do
  use ExUnit.Case
  use ExUnitProperties

  import Bitwise

  alias Bitcoinex.{Bech32, Utils}
  alias Bitcoinex.LightningNetwork.Invoice
  alias Bitcoinex.Secp256k1.{Ecdsa, Point, PrivateKey}

  @moduledoc """
  Exercises BOLT#11 human-readable-part amount parsing.

  The amount is parsed with exact integer arithmetic, so these tests focus on
  the cases where an implementation built on floats (or on any fixed-precision
  decimal) would go wrong: amounts beyond a float's 53-bit integer range,
  multipliers whose value is not representable in binary floating point
  (0.001, 0.000001, ...), and the BOLT#11 rule governing the `p` multiplier.

  Since the amount lives in the signed human-readable part, every case is
  driven through `Invoice.decode/1` on a freshly-signed invoice rather than
  against the (private) parsing function.
  """

  # BOLT#11 test key
  @privkey %PrivateKey{
    d: 0xE126F68F7EAFCC8B74F54D269FE206BE715000F94DAC067D1C04A8CA3B2DB734
  }
  @timestamp 1_496_314_658
  @payment_hash Base.decode16!(
                  "0001020304050607080900010203040506070809000102030405060708090102",
                  case: :lower
                )

  @milli_satoshi_per_bitcoin 100_000_000_000

  # The multiplier values as BOLT#11 states them, expressed exactly as
  # 1 / divisor so that the reference math below never touches a float.
  @multiplier_divisors %{
    nil => 1,
    # 0.001
    "m" => 1_000,
    # 0.000001
    "u" => 1_000_000,
    # 0.000000001
    "n" => 1_000_000_000,
    # 0.000000000001
    "p" => 1_000_000_000_000
  }

  describe "decode/1 amount: BOLT#11 test vectors" do
    test "each multiplier converts to the amount BOLT#11 specifies" do
      # {amount string in the hrp, expected amount_msat}
      vectors = [
        {"1", 100_000_000_000},
        {"2", 200_000_000_000},
        {"21000000", 2_100_000_000_000_000_000},
        {"1m", 100_000_000},
        {"20m", 2_000_000_000},
        {"25m", 2_500_000_000},
        {"24", 2_400_000_000_000},
        {"1u", 100_000},
        {"2500u", 250_000_000},
        {"320u", 32_000_000},
        {"1n", 100},
        {"10n", 1_000},
        {"24000000n", 2_400_000_000},
        {"9678785340n", 967_878_534_000},
        {"10p", 1},
        {"1230p", 123},
        {"9678785340p", 967_878_534}
      ]

      for {amount_str, expected_msat} <- vectors do
        assert {:ok, invoice} = decode_with_amount(amount_str)

        assert invoice.amount_msat == expected_msat,
               "#{amount_str} decoded to #{invoice.amount_msat}, expected #{expected_msat}"
      end
    end

    test "an omitted amount leaves amount_msat nil" do
      assert {:ok, invoice} = decode_with_amount("")
      assert invoice.amount_msat == nil
    end

    test "an explicit zero amount is 0 msat, not nil" do
      assert {:ok, invoice} = decode_with_amount("0")
      assert invoice.amount_msat == 0
    end
  end

  describe "decode/1 amount: precision" do
    test "amounts above 2^53 are exact" do
      # A float64 holds integers exactly only up to 2^53. Each of these is
      # chosen so that a float round-trip would visibly perturb the result.
      # {amount string, expected amount_msat}
      vectors = [
        # 2^53 + 1 nano-bitcoin
        {"9007199254740993n", 900_719_925_474_099_300},
        # 2^53 + 1 pico-bitcoin, last decimal 0 => 2^53*10 + 10
        {"90071992547409930p", 9_007_199_254_740_993},
        # 2^63 - 1, rounded down to a valid pico amount
        {"9223372036854775800p", 922_337_203_685_477_580},
        # every decimal digit set, so any lost bit shows up
        {"12345678901234567890p", 1_234_567_890_123_456_789},
        # more than 2^64 pico-bitcoin
        {"184467440737095516150p", 18_446_744_073_709_551_615},
        # 21M BTC expressed in pico-bitcoin: the whole supply, exactly
        {"21000000000000000000p", 2_100_000_000_000_000_000},
        {"21000000000000000000n", 2_100_000_000_000_000_000_000},
        {"999999999999999999999999999999m", 99_999_999_999_999_999_999_999_999_999_900_000_000}
      ]

      for {amount_str, expected_msat} <- vectors do
        assert {:ok, invoice} = decode_with_amount(amount_str)

        assert invoice.amount_msat == expected_msat,
               "#{amount_str} decoded to #{invoice.amount_msat}, expected #{expected_msat}"
      end
    end

    test "the smallest amount each multiplier can express is exact" do
      # 0.001, 0.000001, 0.000000001 and 0.000000000001 are all inexact as
      # float64, so `1 * multiplier * 100_000_000_000` computed in floating
      # point does not land on a whole number of millisatoshi.
      assert {:ok, %{amount_msat: 100_000_000}} = decode_with_amount("1m")
      assert {:ok, %{amount_msat: 100_000}} = decode_with_amount("1u")
      assert {:ok, %{amount_msat: 100}} = decode_with_amount("1n")
      assert {:ok, %{amount_msat: 1}} = decode_with_amount("10p")
    end

    test "amount_msat is always an integer, never a float" do
      for amount_str <- ["1", "1m", "1u", "1n", "10p", "21000000000000000000p"] do
        assert {:ok, invoice} = decode_with_amount(amount_str)
        assert is_integer(invoice.amount_msat), "#{amount_str} produced a non-integer amount"
      end
    end

    property "decoded amount matches exact rational arithmetic, for every multiplier" do
      check all(
              amount <- integer(1..1_000_000_000_000_000_000_000),
              multiplier <- member_of([nil, "m", "u", "n", "p"]),
              max_runs: 300
            ) do
        # keep the pico amount valid per BOLT#11 without biasing the digits
        amount = if multiplier == "p", do: amount * 10, else: amount

        amount_str = "#{amount}#{multiplier}"

        # the definition straight from the spec: amount * multiplier bitcoin,
        # converted to msat, in exact integer arithmetic
        numerator = amount * @milli_satoshi_per_bitcoin
        divisor = @multiplier_divisors[multiplier]
        assert rem(numerator, divisor) == 0
        expected_msat = div(numerator, divisor)

        assert {:ok, invoice} = decode_with_amount(amount_str)
        assert invoice.amount_msat == expected_msat
      end
    end

    property "amounts are monotonic and unit conversions agree" do
      check all(amount <- integer(1..10_000_000_000), max_runs: 100) do
        # 1 unit = 1000 of the next-smaller unit, exactly, at every scale
        assert {:ok, %{amount_msat: btc}} = decode_with_amount("#{amount}")
        assert {:ok, %{amount_msat: milli}} = decode_with_amount("#{amount * 1_000}m")
        assert {:ok, %{amount_msat: micro}} = decode_with_amount("#{amount * 1_000_000}u")
        assert {:ok, %{amount_msat: nano}} = decode_with_amount("#{amount * 1_000_000_000}n")

        assert {:ok, %{amount_msat: pico}} =
                 decode_with_amount("#{amount * 1_000_000_000_000}p")

        assert btc == milli
        assert btc == micro
        assert btc == nano
        assert btc == pico
      end
    end
  end

  describe "decode/1 amount: the BOLT#11 pico rule" do
    # "if the `multiplier` is `p` and the last decimal of `amount` is not 0:
    #  MUST fail the payment."
    test "a pico amount whose last decimal is not 0 fails" do
      for last_digit <- 1..9 do
        amount_str = "123#{last_digit}p"

        assert {:error, :sub_msat_precision_amount} = decode_with_amount(amount_str),
               "#{amount_str} should have failed the sub-msat precision check"
      end
    end

    test "a pico amount whose last decimal is 0 succeeds" do
      for prefix <- 1..9 do
        amount_str = "#{prefix}0p"
        assert {:ok, invoice} = decode_with_amount(amount_str)
        assert invoice.amount_msat == prefix
      end
    end

    test "the single-digit pico amounts below 1 msat all fail" do
      for amount <- 1..9 do
        assert {:error, :sub_msat_precision_amount} = decode_with_amount("#{amount}p")
      end
    end

    test "the rule applies to the last decimal, not to the rounded value" do
      # 15p is 1.5 msat: it is rejected outright, never rounded to 1 or 2 msat
      assert {:error, :sub_msat_precision_amount} = decode_with_amount("15p")
      assert {:error, :sub_msat_precision_amount} = decode_with_amount("25p")
      # a huge pico amount with a non-zero last decimal fails just the same,
      # even though the fractional part is negligible next to the total
      assert {:error, :sub_msat_precision_amount} =
               decode_with_amount("210000000000000000001p")
    end

    property "a pico amount succeeds exactly when its last decimal is 0" do
      check all(amount <- integer(1..1_000_000_000_000_000), max_runs: 200) do
        result = decode_with_amount("#{amount}p")

        if rem(amount, 10) == 0 do
          assert {:ok, invoice} = result
          assert invoice.amount_msat == div(amount, 10)
        else
          assert {:error, :sub_msat_precision_amount} = result
        end
      end
    end

    test "the pico rule does not apply to the other multipliers" do
      # only `p` can express a sub-msat amount, so a non-zero last decimal is
      # fine everywhere else
      assert {:ok, %{amount_msat: 100}} = decode_with_amount("1n")
      assert {:ok, %{amount_msat: 1_234_500_000}} = decode_with_amount("12345u")
      assert {:ok, %{amount_msat: 1_234_500_000_000}} = decode_with_amount("12345m")
      assert {:ok, %{amount_msat: 1_234_500_000_000_000}} = decode_with_amount("12345")
    end
  end

  describe "decode/1 amount: rejected amounts" do
    test "an unknown multiplier fails" do
      for multiplier <- ~w(x k s b c y z l) do
        assert {:error, :invalid_amount} = decode_with_amount("2500#{multiplier}")
      end
    end

    test "a non-digit inside the amount fails" do
      for amount_str <- ["1a0m", "1a0", "1.5m", "1_000m", "1e3m", "1+0m", "1-0m"] do
        assert {:error, :invalid_amount} = decode_with_amount(amount_str)
      end
    end

    test "two multipliers fail" do
      assert {:error, :invalid_amount} = decode_with_amount("2500mm")
      assert {:error, :invalid_amount} = decode_with_amount("2500um")
    end

    test "a leading zero fails" do
      for amount_str <- ["01", "0100", "010m", "00", "0m", "0p"] do
        assert {:error, :amount_with_leading_zero} = decode_with_amount(amount_str)
      end
    end
  end

  # Builds and signs an invoice whose human-readable part carries `amount_str`,
  # then decodes it. The amount is covered by the invoice signature, so it
  # cannot be tested by patching the hrp of an existing invoice.
  defp decode_with_amount(amount_str) do
    hrp = "lnbc" <> amount_str

    data =
      base32(@timestamp, 7) ++
        tagged_field(1, bytes_to_base32(@payment_hash)) ++
        tagged_field(13, bytes_to_base32("test"))

    {:ok, encoded} =
      Bech32.encode(hrp, data ++ signature_base32(hrp, data), :bech32, :infinity)

    Invoice.decode(encoded)
  end

  # a tagged field is type (1) + big-endian length (2) + data, all base32
  defp tagged_field(type, data) do
    length = Enum.count(data)
    [type] ++ base32(length, 2) ++ data
  end

  defp base32(value, length) do
    for shift <- (length - 1)..0//-1, do: value >>> (5 * shift) &&& 0x1F
  end

  defp bytes_to_base32(bytes) do
    {:ok, base32} = Bech32.convert_bits(:binary.bin_to_list(bytes), 8, 5)
    base32
  end

  # signs sha256(hrp || data) and returns the 65-byte recoverable signature
  # (r || s || recovery id) as 104 base32 values, per BOLT#11
  defp signature_base32(hrp, data) do
    {:ok, data_bytes} = Bech32.convert_bits(data, 5, 8)
    hash = Utils.sha256(:erlang.binary_to_list(hrp) ++ data_bytes)

    %{r: r, s: s} = Ecdsa.sign(@privkey, :binary.decode_unsigned(hash))
    compact_sig = <<r::size(256), s::size(256)>>

    pubkey = @privkey |> PrivateKey.to_point() |> Point.serialize_public_key()

    recovery_id =
      Enum.find(0..3, fn id ->
        Ecdsa.ecdsa_recover_compact(hash, compact_sig, id) == {:ok, pubkey}
      end)

    assert recovery_id != nil, "no recovery id recovers the signing key"

    bytes_to_base32(compact_sig <> <<recovery_id>>)
  end
end
