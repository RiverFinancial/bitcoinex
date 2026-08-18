defmodule Bitcoinex.LightningNetwork.Invoice do
  @moduledoc """
  Includes BOLT#11 Invoice serialization.

  Reference: https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
  """

  alias Bitcoinex.{Bech32, Network, Segwit}
  alias Bitcoinex.LightningNetwork.HopHint

  import Bitwise
  # consider using https://github.com/ejpcmac/typed_struct

  @default_min_final_cltv_expiry 18
  @default_expiry 3600

  @enforce_keys [:network, :destination, :payment_hash, :timestamp]
  defstruct [
    :network,
    :destination,
    :payment_hash,
    :amount_msat,
    :timestamp,
    :description,
    :description_hash,
    fallback_addresses: [],
    route_hints: [],
    expiry: @default_expiry,
    min_final_cltv_expiry: @default_min_final_cltv_expiry
  ]

  @type t() :: %__MODULE__{
          network: Network.network_name(),
          destination: String.t(),
          payment_hash: String.t(),
          amount_msat: non_neg_integer | nil,
          timestamp: integer(),
          expiry: integer() | nil,
          # description and description_hash are either both non-nil or nil
          description: String.t() | nil,
          description_hash: String.t() | nil,
          # one per f field with a known version, most-preferred first
          fallback_addresses: list(String.t()),
          min_final_cltv_expiry: non_neg_integer,
          # each route hint (one per r field) is a list of one or more hops
          route_hints: list(list(HopHint.t()))
        }

  @prefix "ln"
  # TODO move it to bitcoin asset?
  @milli_satoshi_per_bitcoin 100_000_000_000
  # The BOLT#11 multipliers, as the exact number of *deci*-millisatoshi (0.1
  # msat) in one unit of `amount`, keyed by the multiplier character — `nil`
  # meaning no multiplier, i.e. whole bitcoin. One pico-bitcoin is 0.1 msat, so
  # counting in deci-millisatoshi is what gives every multiplier a whole-number
  # entry in one table; core lightning's common/bolt11.c scales by ten for the
  # same reason. This map is the only place a multiplier is named — it is also
  # what split_multiplier/1 tests to decide which characters are multipliers at
  # all, so the set of valid multipliers and their values cannot drift apart.
  @deci_milli_satoshi_per_multiplier %{
    nil => 10 * @milli_satoshi_per_bitcoin,
    "m" => div(10 * @milli_satoshi_per_bitcoin, 1_000),
    "u" => div(10 * @milli_satoshi_per_bitcoin, 1_000_000),
    "n" => div(10 * @milli_satoshi_per_bitcoin, 1_000_000_000),
    "p" => div(10 * @milli_satoshi_per_bitcoin, 1_000_000_000_000)
  }
  # the 512 bit signature + 8 bit recovery ID.
  @signature_base32_length 104
  @timestamp_base32_length 7
  @sha256_hash_base32_length 52
  @pubkey_base32_length 53
  @hop_hint_length 51
  # BOLT#11 places no upper bound on invoice length (it lifts BIP-173's
  # 90-character limit), but decoding untrusted input must be bounded, so we
  # match rust-lightning's limit: 7089 characters, the capacity of the
  # largest QR code (version 40, numeric mode, error-correction level L).
  @max_invoice_length 7089
  @type error :: atom

  @doc """
   Decode accepts a Bech32 encoded string invoice and deserializes it.

   Invoices longer than #{@max_invoice_length} characters (the capacity of
   the largest QR code) are rejected with `{:error, :overall_max_length_exceeded}`.
  """
  @spec decode(String.t()) :: {:ok, t} | {:error, error}
  def decode(invoice) when is_binary(invoice) do
    with {:ok, {_encoding_type, hrp, data}} <- Bech32.decode(invoice, @max_invoice_length),
         {:ok, {network, amount_msat}} <- parse_hrp(hrp),
         {invoice_data, signature_data} = split_at(data, -@signature_base32_length),
         {:ok, parsed_data} <-
           parse_invoice_data(invoice_data, network),
         {:ok, destination} <-
           validate_and_parse_signature_data(
             Map.get(parsed_data, :destination),
             hrp,
             invoice_data,
             signature_data
           ) do
      __MODULE__
      |> struct(
        Map.merge(
          parsed_data,
          %{
            network: network,
            amount_msat: amount_msat,
            destination: destination
          }
        )
      )
      |> validate_invoice()
    end
  end

  @doc """
   Returns the expiry of the invoice.
  """
  @spec expires_at(Bitcoinex.LightningNetwork.Invoice.t()) :: DateTime.t()
  def expires_at(%__MODULE__{} = invoice) do
    expiry = invoice.expiry
    DateTime.from_unix!(invoice.timestamp + expiry)
  end

  # checking some invariant for invoice
  # TODO Could we use ecto(without SQL) for this?
  defp validate_invoice(%__MODULE__{} = invoice) do
    cond do
      is_nil(invoice.network) ->
        {:error, :network_missing}

      !is_nil(invoice.amount_msat) && invoice.amount_msat < 0 ->
        {:error, :negative_amount_msat}

      is_nil(invoice.payment_hash) ->
        {:error, :payment_hash_missing}

      is_nil(invoice.description) && is_nil(invoice.description_hash) ->
        {:error, :both_description_and_description_hash_present}

      !is_nil(invoice.description) && !is_nil(invoice.description_hash) ->
        {:error, :both_description_and_description_hash_missing}

      String.length(invoice.payment_hash) != 64 ->
        {:error, :invalid_payment_hash_length}

      !is_nil(invoice.description_hash) && String.length(invoice.description_hash) != 64 ->
        {:error, :invalid_payment_hash}

      # String.length(invoice.destination) != 64 ->
      #   {:error, :invalid_destination_length}

      true ->
        {:ok, invoice}
    end
  end

  defp validate_and_parse_signature_data(destination, hrp, invoice_data, signature_data)
       when is_list(invoice_data) and is_list(signature_data) do
    with {:ok, signature_data_in_byte} <- Bech32.convert_bits(signature_data, 5, 8),
         {signature, [recoveryId]} = split_at(signature_data_in_byte, -1),
         {:ok, invoice_data_in_byte} <- Bech32.convert_bits(invoice_data, 5, 8) do
      to_sign = (hrp |> :erlang.binary_to_list()) ++ invoice_data_in_byte
      signature = signature |> byte_list_to_binary
      hash = to_sign |> Bitcoinex.Utils.sha256()

      # TODO if destination exist from tagged field, we dun need to recover but to verify it with signature
      # but that require convert lg sig before using secp256k1 to verify it
      # TODO refactor too nested
      case Bitcoinex.Secp256k1.Ecdsa.ecdsa_recover_compact(hash, signature, recoveryId) do
        {:ok, pubkey} ->
          if is_nil(destination) or destination == pubkey do
            {:ok, pubkey}
          else
            {:error, :invalid_invoice_signature}
          end

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp parse_invoice_data(data, network) when is_list(data) do
    {timstamp_data, tagged_fields_data} = split_at(data, @timestamp_base32_length)

    with {:ok, timestamp} <- parse_timestamp(timstamp_data),
         {:ok, parsed_data} <-
           parse_tagged_fields(tagged_fields_data, network) do
      {:ok, Map.put(parsed_data, :timestamp, timestamp)}
    end
  end

  defp parse_tagged_fields(data, network) when is_list(data) do
    do_parse_tagged_fields(data, %{}, network)
  end

  defp do_parse_tagged_fields([type, data_length1, data_length2 | rest], acc, network) do
    data_length = data_length1 <<< 5 ||| data_length2

    if Enum.count(rest) < data_length do
      {:error, :invalid_field_length}
    else
      {data, new_rest} = split_at(rest, data_length)

      case(parse_tagged_field(type, data, acc, network)) do
        {:ok, acc} ->
          do_parse_tagged_fields(new_rest, acc, network)

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp do_parse_tagged_fields(_, acc, _network) do
    {:ok, acc}
  end

  defp parse_tagged_field(type, data, acc, network) do
    case type do
      1 ->
        if Map.has_key?(acc, :payment_hash) do
          {:ok, acc}
        else
          case parse_payment_hash(data) do
            {:ok, payment_hash} ->
              {:ok, Map.put(acc, :payment_hash, payment_hash)}

            {:error, error} ->
              {:error, error}
          end
        end

      # r field HopHints. BOLT#11 allows multiple r fields, each containing
      # one full route hint (a list of one or more hops), so accumulate them.
      3 ->
        case parse_hop_hints(data) do
          # BOLT#11 requires an r field to contain "one or more entries",
          # so an empty one is invalid; skip it rather than fail
          {:ok, []} ->
            {:ok, acc}

          {:ok, hop_hints} ->
            {:ok, Map.update(acc, :route_hints, [hop_hints], &(&1 ++ [hop_hints]))}

          {:error, error} ->
            {:error, error}
        end

      # x field
      6 ->
        if Map.has_key?(acc, :expiry) do
          {:ok, acc}
        else
          expiry = parse_expiry(data)
          {:ok, Map.put(acc, :expiry, expiry)}
        end

      # f field fallback address. BOLT#11 allows one or more f fields
      # (most-preferred first), so accumulate them.
      9 ->
        case parse_fallback_address(data, network) do
          # BOLT#11 readers "MUST skip over f fields that use an unknown version";
          # a later f field may still carry a known version
          {:ok, nil} ->
            {:ok, acc}

          {:ok, fallback_address} ->
            {:ok,
             Map.update(acc, :fallback_addresses, [fallback_address], &(&1 ++ [fallback_address]))}

          {:error, error} ->
            {:error, error}
        end

      # d field
      13 ->
        if Map.has_key?(acc, :description) do
          {:ok, acc}
        else
          case parse_description(data) do
            {:ok, description} ->
              {:ok, Map.put(acc, :description, description)}

            {:error, error} ->
              {:error, error}
          end
        end

      # n field destination
      19 ->
        case acc do
          %{destination: destination} when destination != nil ->
            {:ok, acc}

          _ ->
            case parse_destination(data) do
              {:ok, destination} ->
                {:ok, Map.put(acc, :destination, destination)}

              {:error, error} ->
                {:error, error}
            end
        end

      # h field description hash
      23 ->
        if Map.has_key?(acc, :description_hash) do
          {:ok, acc}
        else
          case parse_description_hash(data) do
            {:ok, description_hash} ->
              {:ok, Map.put(acc, :description_hash, description_hash)}

            {:error, error} ->
              {:error, error}
          end
        end

      # c field MINIMUM Fianl CLTV Expiry
      24 ->
        if Map.has_key?(acc, :min_final_cltv_expiry) do
          {:ok, acc}
        else
          min_final_cltv_expiry = parse_min_final_cltv_expiry(data)
          {:ok, Map.put(acc, :min_final_cltv_expiry, min_final_cltv_expiry)}
        end

      _ ->
        {:ok, acc}
    end
  end

  defp parse_timestamp(data) do
    {:ok, base32_to_integer(data)}
  end

  defp parse_payment_hash(data) when is_list(data) do
    if Enum.count(data) == @sha256_hash_base32_length do
      case Bech32.convert_bits(data, 5, 8, false) do
        {:ok, converted_data} ->
          {:ok, converted_data |> :binary.list_to_bin() |> Base.encode16(case: :lower)}

        {:error, error} ->
          {:error, error}
      end
    else
      {:error, :invalid_payment_hash_length}
    end
  end

  defp parse_description(data) do
    case Bech32.convert_bits(data, 5, 8, false) do
      {:ok, description} ->
        {:ok, :binary.list_to_bin(description)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp parse_expiry(data) do
    base32_to_integer(data)
  end

  @spec base32_to_integer(maybe_improper_list()) :: any()
  def base32_to_integer(data) when is_list(data) do
    Enum.reduce(data, 0, fn val, acc ->
      acc <<< 5 ||| val
    end)
  end

  defp parse_destination(data) when is_list(data) do
    if Enum.count(data) == @pubkey_base32_length do
      case Bech32.convert_bits(data, 5, 8, false) do
        {:ok, data_in_bytes} ->
          {:ok, bytes_to_hex_string(data_in_bytes)}

        {:error, error} ->
          {:error, error}
      end
    else
      {:ok, nil}
    end
  end

  defp parse_description_hash(data) when is_list(data) do
    if Enum.count(data) == @sha256_hash_base32_length do
      case Bech32.convert_bits(data, 5, 8, false) do
        {:ok, data_in_bytes} ->
          {:ok, data_in_bytes |> bytes_to_hex_string}

        {:error, error} ->
          {:error, error}
      end
    else
      {:ok, nil}
    end
  end

  # an empty f field carries no version, so there is nothing to decode;
  # skip it (like an unknown version) rather than fail the whole invoice
  defp parse_fallback_address([], _network) do
    {:ok, nil}
  end

  defp parse_fallback_address([version | rest], network) do
    case version do
      0 ->
        case Bech32.convert_bits(rest, 5, 8, false) do
          {:ok, witness} ->
            case Enum.count(witness) do
              witness_program_lenghh when witness_program_lenghh in [20, 32] ->
                Segwit.encode_address(network, 0, witness)

              _ ->
                {:error, :invalid_witness_program_length}
            end

          err ->
            err
        end

      17 ->
        case Bech32.convert_bits(rest, 5, 8, false) do
          # a P2PKH fallback address must carry a 20-byte pubkey hash
          {:ok, pub_key_hash} when length(pub_key_hash) == 20 ->
            {:ok,
             Bitcoinex.Address.encode(
               pub_key_hash |> :binary.list_to_bin(),
               network,
               :p2pkh
             )}

          {:ok, _} ->
            {:error, :invalid_pubkey_hash_length}

          err ->
            err
        end

      18 ->
        case Bech32.convert_bits(rest, 5, 8, false) do
          # a P2SH fallback address must carry a 20-byte script hash
          {:ok, script_hash} when length(script_hash) == 20 ->
            {:ok,
             Bitcoinex.Address.encode(
               script_hash |> :binary.list_to_bin(),
               network,
               :p2sh
             )}

          {:ok, _} ->
            {:error, :invalid_script_hash_length}

          err ->
            err
        end

      # ignore unknown version
      _ ->
        {:ok, nil}
    end
  end

  defp parse_hop_hints(data) when is_list(data) do
    with {:ok, data_in_byte} <- Bech32.convert_bits(data, 5, 8, false),
         {_, true} <-
           {:validate_hop_hint_data_length, rem(Enum.count(data_in_byte), @hop_hint_length) == 0} do
      hop_hints =
        data_in_byte
        |> Enum.chunk_every(@hop_hint_length)
        |> Enum.map(&parse_hop_hint/1)

      {:ok, hop_hints}
    else
      {:validate_hop_hint_data_length, false} ->
        {:error, :invalid_hop_hint_data_length}

      {:error, error} ->
        {:error, error}
    end
  end

  defp parse_integer_from_hex_str!(hex_str) do
    {hex_str, ""} = Integer.parse(hex_str, 16)
    hex_str
  end

  # exoect they are list of integer in byte
  defp parse_hop_hint(data) when is_list(data) do
    # 64 bits
    {node_id_data, rest} = data |> split_at(33)
    node_id = node_id_data |> bytes_to_hex_string
    # 64 bits
    {channel_id_data, rest} = rest |> split_at(8)
    channel_id = channel_id_data |> bytes_to_hex_string |> parse_integer_from_hex_str!
    # 32 bits
    {fee_base_m_sat_data, rest} = rest |> split_at(4)
    fee_base_m_sat = fee_base_m_sat_data |> bytes_to_hex_string |> parse_integer_from_hex_str!
    # 32 bits
    {fee_proportional_millionths_data, rest} = rest |> split_at(4)

    fee_proportional_millionths =
      fee_proportional_millionths_data |> bytes_to_hex_string |> parse_integer_from_hex_str!

    cltv_expiry_delta = rest |> bytes_to_hex_string |> parse_integer_from_hex_str!

    %HopHint{
      node_id: node_id,
      channel_id: channel_id,
      fee_base_m_sat: fee_base_m_sat,
      fee_proportional_millionths: fee_proportional_millionths,
      cltv_expiry_delta: cltv_expiry_delta
    }
  end

  defp parse_min_final_cltv_expiry(data) when is_list(data) do
    base32_to_integer(data)
  end

  # defp get_pubkey_to_address_magicbyte(network, script_type) do
  #   case {network, script_type} do
  #     {:mainnet, :p2pkh} ->
  #       0x00

  #     {:mainnet, :p2sh} ->
  #       0x05

  #     {network, :p2pkh} when network in [:testnet, :regtest] ->
  #       0x6F

  #     {network, :p2sh} when network in [:testnet, :regtest] ->
  #       0xC4
  #   end
  # end

  defp parse_network(@prefix <> rest_hrp) do
    case Enum.find(Network.supported_networks(), fn %{hrp_segwit_prefix: hrp_segwit_prefix} ->
           if String.starts_with?(rest_hrp, hrp_segwit_prefix) do
             size = bit_size(hrp_segwit_prefix)

             case rest_hrp do
               # without amount
               ^hrp_segwit_prefix ->
                 true

               # with amount. a valid segwit_prefix must be following with base10 digit
               # ?0..?9 means range of codepoint of 0 - 9
               # it shoudln't include 0 but that's not responsiblity of passing network function here
               <<_::size(size), i, _::binary>> when i in ?0..?9 ->
                 true

               _ ->
                 false
             end
           end
         end) do
      nil ->
        {:error, :invalid_network}

      network ->
        {:ok, network}
    end
  end

  defp parse_hrp(hrp) do
    with {_, @prefix <> rest_hrp} <- {:strip_prefix, hrp},
         {_, {:ok, %{name: network_name, hrp_segwit_prefix: hrp_segwit_prefix}}} <-
           {:parse_network, parse_network(hrp)} do
      hrp_segwit_prefix_size = byte_size(hrp_segwit_prefix)

      case rest_hrp do
        ^hrp_segwit_prefix ->
          {:ok, {network_name, nil}}

        _ ->
          amount_str = String.slice(rest_hrp, hrp_segwit_prefix_size..-1//1)

          case calculate_milli_satoshi(amount_str) do
            {:ok, amount} ->
              {:ok, {network_name, amount}}

            {:error, error} ->
              {:error, error}
          end
      end
    else
      {:strip_prefix, _} ->
        {:error, :no_ln_prefix}

      # parse_network/1 already returns an {:error, atom} tuple; re-wrapping it
      # produced {:error, {:error, :invalid_network}}, which contradicts this
      # module's `@type error :: atom`
      {:parse_network, {:error, error}} ->
        {:error, error}
    end
  end

  # Converts the amount in the human-readable part into millisatoshi, per the
  # BOLT#11 requirements on `amount`:
  #
  #   - it "MUST encode `amount` as a positive decimal integer with no leading
  #     0s", and a reader "MUST fail the payment" if `amount` "contains a
  #     non-digit OR is followed by anything except a `multiplier`"
  #   - if the `multiplier` is present, a reader "MUST multiply `amount` by the
  #     `multiplier` value to derive the amount required for payment"
  #   - "if the `multiplier` is `p` and the last decimal of `amount` is not 0:
  #     MUST fail the payment"
  #
  # Note that the `p` rule is a rule about the final *decimal digit* of the
  # amount string, not about the rounding of some computed value: it exists
  # because one pico-bitcoin is 0.1 msat, and HTLCs cannot carry sub-msat
  # amounts. Once it has been applied, every amount converts exactly, so all
  # arithmetic here is on integers — no floats, no rounding, and therefore no
  # precision to lose.
  defp calculate_milli_satoshi(amount_str) do
    if String.length(amount_str) > 1 and String.starts_with?(amount_str, "0") do
      {:error, :amount_with_leading_zero}
    else
      {amount, multiplier} = split_multiplier(amount_str)

      cond do
        !decimal_digits?(amount) ->
          {:error, :invalid_amount}

        multiplier == "p" and !String.ends_with?(amount, "0") ->
          {:error, :sub_msat_precision_amount}

        true ->
          {:ok, to_milli_satoshi(String.to_integer(amount), multiplier)}
      end
    end
  end

  defp split_multiplier(amount_str) do
    case String.split_at(amount_str, -1) do
      {amount, multiplier}
      when is_map_key(@deci_milli_satoshi_per_multiplier, multiplier) ->
        {amount, multiplier}

      _ ->
        {amount_str, nil}
    end
  end

  # \A and \z (rather than ^ and $) so that a trailing newline is not a digit
  defp decimal_digits?(str), do: String.match?(str, ~r/\A[0-9]+\z/)

  # The table counts deci-millisatoshi, so every multiplier — `p` included — is
  # one multiplication and one division by ten. That division is exact: every
  # entry but `p`'s is a multiple of ten, and a `p` amount has already been
  # required to end in a 0. split_multiplier/1 only yields keys of the table, so
  # the fetch cannot fail.
  defp to_milli_satoshi(amount, multiplier) do
    div(amount * Map.fetch!(@deci_milli_satoshi_per_multiplier, multiplier), 10)
  end

  defp bytes_to_hex_string(bytes) when is_list(bytes) do
    bytes |> :binary.list_to_bin() |> Base.encode16(case: :lower)
  end

  defp byte_list_to_binary(bytes) when is_list(bytes) do
    bytes |> :binary.list_to_bin()
  end

  @spec split_at(Enum.t(), integer()) :: {list(Enum.t()), list(Enum.t())}
  defp split_at(xs, index) when index >= 0 do
    {Enum.take(xs, index), Enum.drop(xs, index)}
  end

  defp split_at(xs, index) when index < 0 do
    {Enum.drop(xs, index), Enum.take(xs, index)}
  end
end
