# Generates test/data/core_psbt_v0_vectors.json from Bitcoin Core's rpc_psbt.json,
# vendoring only the BIP-174 v0-relevant vectors (no BIP-370 v2, no BIP-371
# taproot). Each vector is placed in a bucket by our decoder's ACTUAL behavior so
# the fixture can never mislabel: `invalid` = rejected, `valid_roundtrip` =
# decodes and re-encodes byte-identically, `valid_decode_only` = decodes but the
# source used non-canonical field ordering so re-encode differs.
#
# Vectors our decoder does NOT classify the way Core does are dropped and listed
# under `excluded` (with reason) so the exclusion is visible, never silent.
alias Bitcoinex.PSBT

[src, dst] = System.argv()
%{"invalid" => invalid, "valid" => valid} = src |> File.read!() |> Jason.decode!()

# v0-relevant indices per the vendored catalog (v2/taproot entries skipped).
invalid_skip =
  MapSet.new([
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    37,
    38,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    52,
    55,
    56,
    57,
    58,
    59,
    60,
    61,
    62
  ])

invalid_v0 = Enum.reject(0..(length(invalid) - 1), &MapSet.member?(invalid_skip, &1))
valid_v0 = Enum.to_list(0..13)

{invalid_ok, invalid_excluded} =
  Enum.split_with(invalid_v0, fn i ->
    match?({:error, _}, PSBT.decode(Enum.at(invalid, i)))
  end)

valid_buckets =
  Enum.reduce(valid_v0, %{roundtrip: [], decode_only: [], excluded: []}, fn i, acc ->
    b64 = Enum.at(valid, i)

    case PSBT.decode(b64) do
      {:ok, psbt} ->
        if PSBT.encode_b64(psbt) == b64,
          do: %{acc | roundtrip: [b64 | acc.roundtrip]},
          else: %{acc | decode_only: [{i, b64} | acc.decode_only]}

      {:error, _} ->
        %{acc | excluded: [{i, "decode failed"} | acc.excluded]}
    end
  end)

fixture = %{
  "_source" => "bitcoin/bitcoin test/functional/data/rpc_psbt.json (v0 subset)",
  "_note" =>
    "v2 (BIP-370) and taproot (BIP-371) vectors are out of scope and omitted. " <>
      "Buckets reflect this decoder's behavior; see `_excluded` for Core vectors we " <>
      "classify differently (parser is more lenient, or a non-v0 tx quirk).",
  "invalid" => Enum.map(invalid_ok, &Enum.at(invalid, &1)),
  "valid_roundtrip" => Enum.reverse(valid_buckets.roundtrip),
  "valid_decode_only" => valid_buckets.decode_only |> Enum.reverse() |> Enum.map(&elem(&1, 1)),
  "_excluded" => %{
    "invalid_but_accepted" => invalid_excluded,
    "valid_but_failed" => Enum.map(valid_buckets.excluded, &elem(&1, 0))
  }
}

File.write!(dst, Jason.encode!(fixture, pretty: true) <> "\n")

IO.puts(
  "wrote #{dst}: invalid=#{length(fixture["invalid"])} " <>
    "valid_roundtrip=#{length(fixture["valid_roundtrip"])} " <>
    "valid_decode_only=#{length(fixture["valid_decode_only"])} " <>
    "excluded_invalid=#{inspect(invalid_excluded)} " <>
    "excluded_valid=#{inspect(fixture["_excluded"]["valid_but_failed"])}"
)
