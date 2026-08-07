defmodule Bitcoinex.LightningNetwork.InvoiceAmountTest do
  use ExUnit.Case
  use ExUnitProperties

  import Bitwise

  alias Bitcoinex.{Bech32, Utils}
  alias Bitcoinex.LightningNetwork.Invoice
  alias Bitcoinex.Secp256k1.{Ecdsa, Point, PrivateKey}

  @moduledoc """
  Exercises BOLT#11 human-readable-part amount parsing.

  The vectors here are taken from other implementations rather than computed
  from our own reading of the spec, so that this is a differential test and
  not a restatement of `Invoice`:

    * `lnd` — the `TestDecodeAmount` table in `zpay32/invoice_internal_test.go`
      (github.com/lightningnetwork/lnd), reproduced case for case below, and
      the `toMSat` conversions in `zpay32/amountunits.go`, used as the
      reference the property tests compare against. lnd gives each multiplier
      its own whole-millisatoshi factor and special-cases `p` (`p < 10` and
      `p % 10 != 0` are errors, otherwise `p / 10`). `Invoice` instead follows
      core lightning and counts in tenths of a millisatoshi so that one table
      covers every multiplier, so this is a genuinely different decomposition
      and a real cross-check rather than the same arithmetic written twice.
    * BOLT#11 — the signed example invoices in `11-payment-encoding.md`
      (github.com/lightning/bolts), used verbatim with the amounts the spec
      annotates them with.

  On top of those, `describe "precision"` covers amounts that exceed what a
  float64 or a `uint64` can hold. lnd and core lightning both carry the amount
  in a `uint64`, so no vector from either can reach that range; Elixir integers
  are arbitrary precision, and the reference there is exact rational math.

  The amount lives in the signed human-readable part, so it cannot be tested
  by patching the hrp of an existing invoice. Cases that are not spec vectors
  are therefore driven through `Invoice.decode/1` on an invoice this module
  builds and signs.
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

  # lnd's toMSat table (zpay32/amountunits.go): a whole-millisatoshi factor per
  # multiplier. `p` has no entry — it is not expressible in whole millisatoshi,
  # so lnd special-cases it in lnd_to_msat/2 below.
  @lnd_to_msat %{
    nil => @milli_satoshi_per_bitcoin,
    "m" => 100_000_000,
    "u" => 100_000,
    "n" => 100
  }

  describe "decode/1 amount: lnd zpay32 TestDecodeAmount vectors" do
    test "every amount lnd accepts decodes to the millisatoshi lnd expects" do
      # {amount string in the hrp, expected msat} — the `valid: true` rows of
      # lnd's TestDecodeAmount, in order, with lnd's own comments.
      vectors = [
        # pBTC
        {"10p", 1},
        # pBTC
        {"1000p", 100},
        # nBTC
        {"1n", 100},
        # nBTC
        {"9000n", 900_000},
        # uBTC
        {"9u", 900_000},
        # uBTC
        {"2000u", 200_000_000},
        # mBTC
        {"2m", 200_000_000},
        # mBTC
        {"2000m", 200_000_000_000},
        # BTC
        {"2", 200_000_000_000},
        # BTC
        {"2000", 200_000_000_000_000},
        # BTC
        {"2009", 200_900_000_000_000},
        # BTC
        {"1234", 123_400_000_000_000},
        # BTC
        {"21000000", 2_100_000_000_000_000_000}
      ]

      for {amount_str, expected_msat} <- vectors do
        assert {:ok, invoice} = decode_with_amount(amount_str)

        assert invoice.amount_msat == expected_msat,
               "#{amount_str} decoded to #{invoice.amount_msat}, expected #{expected_msat}"
      end
    end

    test "every amount lnd rejects is rejected" do
      # the `valid: false` rows of lnd's TestDecodeAmount. lnd reports a single
      # error per row; bitcoinex distinguishes which check failed, so the atom
      # is pinned here alongside lnd's reason.
      vectors = [
        # lnd: trailing digits after the multiplier
        {"20n00", :invalid_amount},
        # lnd: unknown multiplier
        {"2000y", :invalid_amount},
        # lnd: two multipliers
        {"2000mm", :invalid_amount},
        # lnd: two multipliers
        {"2000nm", :invalid_amount},
        # lnd: multiplier with no amount. rejected earlier here, when resolving
        # the network: BOLT#11 requires a digit to follow the network prefix
        {"m", :invalid_network},
        # lnd: "too small". 1p is 0.1 msat, so its last decimal is not 0
        {"1p", :sub_msat_precision_amount},
        # lnd: "not divisible by 10"
        {"1109p", :sub_msat_precision_amount},
        # lnd: negative amount. also rejected when resolving the network, since
        # "-" is not a digit
        {"-10p", :invalid_network}
      ]

      for {amount_str, expected_error} <- vectors do
        assert {:error, ^expected_error} = decode_with_amount(amount_str),
               "#{amount_str} should have been rejected with #{expected_error}"
      end
    end

    test "an empty amount is no amount, rather than an error" do
      # lnd's table has `{amount: "", valid: false}`, but lnd only reaches
      # decodeAmount when the hrp carries an amount at all. BOLT#11: "if the
      # `amount` is empty: SHOULD indicate to the payer that amount is
      # unspecified" — so an hrp of just "lnbc" is a valid amountless invoice.
      assert {:ok, invoice} = decode_with_amount("")
      assert invoice.amount_msat == nil
    end
  end

  describe "decode/1 amount: BOLT#11 example invoices" do
    test "each signed example decodes to the amount the spec annotates" do
      # verbatim from the Examples section of 11-payment-encoding.md, with the
      # amounts the spec states in the field-by-field breakdown under each
      vectors = [
        # no amount (11-payment-encoding.md line 372)
        {"lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql",
         nil},
        # 2500u = 2500 micro-bitcoin (11-payment-encoding.md line 400)
        {"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh",
         250_000_000},
        # 20m = 20 milli-bitcoin (11-payment-encoding.md line 456)
        {"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44",
         2_000_000_000},
        # 20m = 20 milli-bitcoin, on testnet (11-payment-encoding.md line 481)
        {"lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8",
         2_000_000_000},
        # 9678785340p = 9678785340 pico-bitcoin (11-payment-encoding.md line 639)
        {"lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz",
         967_878_534},
        # 25m = 25 milli-bitcoin (11-payment-encoding.md line 673)
        {"lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa",
         2_500_000_000},
        # 10m = 10 milli-bitcoin (11-payment-encoding.md line 750)
        {"lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc",
         1_000_000_000}
      ]

      for {encoded, expected_msat} <- vectors do
        assert {:ok, invoice} = Invoice.decode(encoded)

        assert invoice.amount_msat == expected_msat,
               "#{String.slice(encoded, 0..20)}... decoded to #{inspect(invoice.amount_msat)}, " <>
                 "expected #{inspect(expected_msat)}"
      end
    end

    test "the spec's two invalid-amount examples are rejected" do
      # Invalid multiplier (11-payment-encoding.md line 844)
      assert {:error, :invalid_amount} =
               Invoice.decode(
                 "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j"
               )

      # Invalid sub-millisatoshi precision (11-payment-encoding.md line 847)
      assert {:error, :sub_msat_precision_amount} =
               Invoice.decode(
                 "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x"
               )
    end
  end

  describe "decode/1 amount: precision" do
    # No vector in this block can come from lnd or core lightning: both carry
    # the amount in a uint64, so neither can express these. The reference is
    # exact rational arithmetic.

    test "amounts beyond a float's exact integer range are exact" do
      # a float64 holds integers exactly only up to 2^53
      vectors = [
        # 2^53 + 1 nano-bitcoin
        {"9007199254740993n", 900_719_925_474_099_300},
        # 2^53 + 1 pico-bitcoin, rounded to a valid pico amount
        {"90071992547409930p", 9_007_199_254_740_993},
        # every decimal digit set, so any lost bit shows up
        {"12345678901234567890p", 1_234_567_890_123_456_789}
      ]

      for {amount_str, expected_msat} <- vectors do
        assert {:ok, invoice} = decode_with_amount(amount_str)

        assert invoice.amount_msat == expected_msat,
               "#{amount_str} decoded to #{invoice.amount_msat}, expected #{expected_msat}"
      end
    end

    test "amounts beyond a uint64 are exact" do
      # 2^64 - 1 msat is the largest lnd or core lightning can hold; BOLT#11
      # itself places no bound on the amount, so decoding must not wrap
      vectors = [
        # 2^64 - 1 msat exactly, the last amount a uint64 implementation holds
        {"184467440737095516150p", 18_446_744_073_709_551_615},
        # one msat past it
        {"184467440737095516160p", 18_446_744_073_709_551_616},
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
      # point does not land on a whole number of millisatoshi
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

    property "decoded amount matches lnd's conversion, for every multiplier" do
      check all(
              amount <- integer(1..1_000_000_000_000_000_000_000),
              multiplier <- member_of([nil, "m", "u", "n", "p"]),
              max_runs: 300
            ) do
        result = decode_with_amount("#{amount}#{multiplier}")

        # lnd accepts and rejects here, so both branches are exercised: `p`
        # amounts are generated unbiased, and roughly nine in ten of them are
        # the sub-millisatoshi amounts lnd's pBtcToMSat refuses
        case lnd_to_msat(amount, multiplier) do
          {:ok, expected_msat} ->
            assert {:ok, invoice} = result
            assert invoice.amount_msat == expected_msat

          :error ->
            assert {:error, :sub_msat_precision_amount} = result
        end
      end
    end

    property "unit conversions agree across every multiplier" do
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
      # lnd rejects these as "minimum amount is 10p"
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

    test "a leading zero fails" do
      for amount_str <- ["01", "0100", "010m", "00", "0m", "0p"] do
        assert {:error, :amount_with_leading_zero} = decode_with_amount(amount_str)
      end
    end

    test "an explicit zero amount is 0 msat, not nil" do
      assert {:ok, invoice} = decode_with_amount("0")
      assert invoice.amount_msat == 0
    end
  end

  # lnd's conversion, from zpay32/amountunits.go: mBtcToMSat and friends are a
  # single multiplication by the @lnd_to_msat factor, and pBtcToMSat rejects
  # `p < 10` ("minimum amount is 10p") and `p % 10 != 0` ("not expressible in
  # msat"). Returns {:ok, msat} or :error. Elixir integers are unbounded, so
  # this is lnd's arithmetic without lnd's uint64 ceiling.
  defp lnd_to_msat(amount, "p") do
    if amount < 10 or rem(amount, 10) != 0, do: :error, else: {:ok, div(amount, 10)}
  end

  defp lnd_to_msat(amount, multiplier), do: {:ok, amount * @lnd_to_msat[multiplier]}

  # Builds and signs an invoice whose human-readable part carries `amount_str`,
  # then decodes it. The amount is covered by the invoice signature, so it
  # cannot be tested by patching the hrp of an existing invoice.
  defp decode_with_amount(amount_str) do
    hrp = "lnbc" <> amount_str

    data =
      base32(@timestamp, 7) ++
        tagged_field(1, bytes_to_base32(@payment_hash)) ++
        tagged_field(13, bytes_to_base32("test"))

    case Bech32.encode(hrp, data ++ signature_base32(hrp, data), :bech32, :infinity) do
      {:ok, encoded} -> Invoice.decode(encoded)
      {:error, error} -> flunk("could not encode an invoice for #{inspect(hrp)}: #{error}")
    end
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
