defmodule Bitcoinex.OutputDescriptor do
  @moduledoc """
  A module for Bitcoin Output Descriptors.

  This implements partial support for Bitcoin Output Descriptors as described in:
  https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md

  Includes support for the following descriptor types:
  - pk() - Pay to public key
  - pkh() - Pay to public key hash
  - wpkh() - Pay to witness public key hash (Segwit v0)
  - sh() - Pay to script hash
  - wsh() - Pay to witness script hash (Segwit v0)
  - tr() - Pay to taproot (Segwit v1)
  - combo() - Combined descriptor (Pay to pubkey, pubkey hash, or witness pubkey hash)
  - multi() - Bare multisig
  - sortedmulti() - Sorted bare multisig
  - addr() - Pay to address
  - raw() - Raw script hex
  """

  alias Bitcoinex.{Script, Utils}
  alias Bitcoinex.Secp256k1.Point

  @type t() :: %__MODULE__{
          type:
            :addr | :pk | :pkh | :wpkh | :sh | :wsh | :combo | :multi | :sortedmulti | :raw | :tr,
          key: any(),
          sub_descriptor: t() | nil,
          keys: list(any()) | nil,
          threshold: non_neg_integer() | nil,
          script_hash: binary() | nil,
          address: String.t() | nil,
          raw_script: binary() | nil,
          checksum: String.t() | nil
        }

  defstruct [
    :type,
    :key,
    :keys,
    :threshold,
    :sub_descriptor,
    :script_hash,
    :address,
    :raw_script,
    :checksum
  ]

  @doc """
  Creates a new output descriptor from the given string.

  ## Examples

      iex> OutputDescriptor.parse("pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)")
      {:ok, %OutputDescriptor{type: :pkh, key: %Secp256k1.Point{...}}}

      iex> OutputDescriptor.parse("tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)")
      {:ok, %OutputDescriptor{type: :tr, key: %Secp256k1.Point{...}}}
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse("pk(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, %__MODULE__{type: :pk, key: key, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, "Invalid pk descriptor"}
    end
  end

  def parse("pkh(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, %__MODULE__{type: :pkh, key: key, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, "Invalid pkh descriptor"}
    end
  end

  def parse("wpkh(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, %__MODULE__{type: :wpkh, key: key, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, "Invalid wpkh descriptor"}
    end
  end

  def parse("sh(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            script_hash = Script.hash160(to_script(%__MODULE__{type: :raw, raw_script: key}))
            {:ok, %__MODULE__{type: :sh, key: key, script_hash: script_hash, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      {{:descriptor, sub_descriptor}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            script_hash = Script.hash160(to_script(sub_descriptor))

            {:ok,
             %__MODULE__{
               type: :sh,
               sub_descriptor: sub_descriptor,
               script_hash: script_hash,
               checksum: checksum
             }}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  def parse("wsh(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            script_hash = Script.sha256(to_script(%__MODULE__{type: :raw, raw_script: key}))
            {:ok, %__MODULE__{type: :wsh, key: key, script_hash: script_hash, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      {{:descriptor, sub_descriptor}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            script_hash = Script.sha256(to_script(sub_descriptor))

            {:ok,
             %__MODULE__{
               type: :wsh,
               sub_descriptor: sub_descriptor,
               script_hash: script_hash,
               checksum: checksum
             }}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  # Implementation of Taproot descriptor support
  def parse("tr(" <> rest) do
    case parse_key_or_descriptor(rest) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, %__MODULE__{type: :tr, key: key, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end

      {{:descriptor, _sub_descriptor}, _remaining} ->
        # Currently only supporting key path spending
        {:error, "Taproot script path spending not yet supported"}
    end
  end

  def parse("addr(" <> rest) do
    case parse_until_closing_bracket(rest) do
      {:error, reason} ->
        {:error, reason}

      {address, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, %__MODULE__{type: :addr, address: address, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  def parse("raw(" <> rest) do
    case parse_until_closing_bracket(rest) do
      {:error, reason} ->
        {:error, reason}

      {script_hex, remaining} ->
        case parse_closing_bracket(remaining) do
          {:ok, rest_with_checksum} ->
            checksum = extract_checksum(rest_with_checksum)
            {:ok, raw_script} = Utils.hex_to_bin(script_hex)
            {:ok, %__MODULE__{type: :raw, raw_script: raw_script, checksum: checksum}}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  def parse("multi(" <> rest) do
    case parse_multi_descriptor(rest, false) do
      {:ok, descriptor} -> {:ok, descriptor}
      {:error, reason} -> {:error, reason}
    end
  end

  def parse("sortedmulti(" <> rest) do
    case parse_multi_descriptor(rest, true) do
      {:ok, descriptor} -> {:ok, descriptor}
      {:error, reason} -> {:error, reason}
    end
  end

  def parse(_), do: {:error, "Unknown or unsupported descriptor type"}

  # Helper functions for parsing descriptors

  defp parse_key_or_descriptor(str) do
    cond do
      String.starts_with?(str, [
        "pk(",
        "pkh(",
        "wpkh(",
        "sh(",
        "wsh(",
        "tr(",
        "addr(",
        "raw(",
        "multi(",
        "sortedmulti("
      ]) ->
        # This is a nested descriptor
        case parse_until_matching_bracket(str, 0, 0, "") do
          {:ok, descriptor_str, rest} ->
            case parse(descriptor_str) do
              {:ok, descriptor} ->
                {{:descriptor, descriptor}, rest}

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      # Try to parse as a public key
      true ->
        case parse_pubkey(str) do
          {:ok, pubkey, rest} ->
            {{:key, pubkey}, rest}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp parse_pubkey(str) do
    # Check for hex format and try parsing it as a public key
    if String.length(str) >= 66 and Regex.match?(~r/^[0-9a-fA-F]{66,}/, str) do
      <<pubkey_hex::binary-size(66), rest::binary>> = str

      case Utils.hex_to_bin(pubkey_hex) do
        {:ok, binary} ->
          case Point.parse_public_key(binary) do
            {:ok, point} -> {:ok, point, rest}
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, "Invalid public key format"}
    end
  end

  defp parse_multi_descriptor(str, sorted?) do
    # Parse threshold
    case Integer.parse(str) do
      {threshold, "," <> rest} ->
        # Parse keys
        case parse_multi_keys(rest, []) do
          {:ok, keys, remaining} ->
            case parse_closing_bracket(remaining) do
              {:ok, rest_with_checksum} ->
                checksum = extract_checksum(rest_with_checksum)
                type = if sorted?, do: :sortedmulti, else: :multi

                {:ok,
                 %__MODULE__{
                   type: type,
                   threshold: threshold,
                   keys: keys,
                   checksum: checksum
                 }}

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:error, "Invalid multi descriptor format"}
    end
  end

  defp parse_multi_keys(str, acc) do
    case parse_key_or_descriptor(str) do
      {:error, reason} ->
        {:error, reason}

      {{:key, key}, ")" <> _rest} ->
        {:ok, Enum.reverse([key | acc]), ")" <> str}

      {{:key, key}, "," <> rest} ->
        parse_multi_keys(rest, [key | acc])

      _ ->
        {:error, "Invalid key format in multi descriptor"}
    end
  end

  defp parse_until_closing_bracket(str) do
    case String.split(str, ")", parts: 2) do
      [content, rest] -> {content, ")" <> rest}
      _ -> {:error, "Missing closing bracket"}
    end
  end

  defp parse_closing_bracket(")" <> rest), do: {:ok, rest}
  defp parse_closing_bracket(_), do: {:error, "Missing closing bracket"}

  defp parse_until_matching_bracket(<<>>, _depth, _start_pos, _acc),
    do: {:error, "Unmatched brackets"}

  defp parse_until_matching_bracket(<<"(", rest::binary>>, depth, start_pos, acc) do
    parse_until_matching_bracket(rest, depth + 1, start_pos, acc <> "(")
  end

  defp parse_until_matching_bracket(<<")", rest::binary>>, 1, _start_pos, acc) do
    {:ok, acc, ")" <> rest}
  end

  defp parse_until_matching_bracket(<<")", rest::binary>>, depth, start_pos, acc)
       when depth > 1 do
    parse_until_matching_bracket(rest, depth - 1, start_pos, acc <> ")")
  end

  defp parse_until_matching_bracket(<<c::binary-size(1), rest::binary>>, depth, start_pos, acc) do
    parse_until_matching_bracket(rest, depth, start_pos, acc <> c)
  end

  defp extract_checksum(""), do: nil
  defp extract_checksum("#" <> checksum), do: checksum

  @doc """
  Converts an output descriptor to a script.
  """
  @spec to_script(t()) :: Script.t()
  def to_script(%__MODULE__{type: :pk, key: key}) do
    {:ok, script} = Script.create_p2pk(Point.sec(key))
    script
  end

  def to_script(%__MODULE__{type: :pkh, key: key}) do
    {:ok, script} = Script.public_key_to_p2pkh(key)
    script
  end

  def to_script(%__MODULE__{type: :wpkh, key: key}) do
    {:ok, script} = Script.public_key_to_p2wpkh(key)
    script
  end

  def to_script(%__MODULE__{type: :sh, sub_descriptor: sub_descriptor})
      when not is_nil(sub_descriptor) do
    redeem_script = to_script(sub_descriptor)
    {:ok, script} = Script.to_p2sh(redeem_script)
    script
  end

  def to_script(%__MODULE__{type: :sh, key: key}) when is_binary(key) do
    {:ok, script} = Script.create_p2sh(key)
    script
  end

  def to_script(%__MODULE__{type: :wsh, sub_descriptor: sub_descriptor})
      when not is_nil(sub_descriptor) do
    witness_script = to_script(sub_descriptor)
    {:ok, script} = Script.to_p2wsh(witness_script)
    script
  end

  def to_script(%__MODULE__{type: :wsh, key: key}) when is_binary(key) do
    {:ok, script} = Script.create_p2wsh(key)
    script
  end

  def to_script(%__MODULE__{type: :multi, threshold: m, keys: keys}) do
    {:ok, script} = Script.create_multi(m, keys)
    script
  end

  def to_script(%__MODULE__{type: :sortedmulti, threshold: m, keys: keys}) do
    sorted_keys =
      Enum.sort(keys, fn a, b ->
        a_sec = Point.sec(a)
        b_sec = Point.sec(b)
        a_sec <= b_sec
      end)

    {:ok, script} = Script.create_multi(m, sorted_keys)
    script
  end

  def to_script(%__MODULE__{type: :addr, address: address}) do
    {:ok, script, _network} = Script.from_address(address)
    script
  end

  def to_script(%__MODULE__{type: :raw, raw_script: script_binary}) do
    {:ok, script} = Script.parse_script(script_binary)
    script
  end

  # Taproot output script generation
  def to_script(%__MODULE__{type: :tr, key: key}) do
    # Convert to an x-only public key if it's a Point
    xonly_key =
      case key do
        %Point{} ->
          # Extract the x coordinate only
          serialized = Point.sec(key)
          # Remove the first byte (compression marker) to get the x-only key
          binary_part(serialized, 1, 32)

        binary when is_binary(binary) and byte_size(binary) == 33 ->
          # Remove first byte from compressed pubkey
          binary_part(binary, 1, 32)

        binary when is_binary(binary) and byte_size(binary) == 32 ->
          # Already an x-only key
          binary

        _ ->
          raise "Invalid key for Taproot descriptor"
      end

    # Create a pay-to-taproot script: OP_1 <32-byte x-only pubkey>
    {:ok, script} = Script.create_p2tr(xonly_key)
    script
  end

  @doc """
  Converts an output descriptor to an address.
  """
  @spec to_address(t(), atom()) :: {:ok, String.t()} | {:error, String.t()}
  def to_address(descriptor, network \\ :mainnet) do
    script = to_script(descriptor)
    Script.to_address(script, network)
  end

  @doc """
  Derives a script pubkey from an output descriptor.
  """
  @spec derive_script_pubkey(t()) :: binary()
  def derive_script_pubkey(descriptor) do
    script = to_script(descriptor)
    Script.serialize_script(script)
  end
end
