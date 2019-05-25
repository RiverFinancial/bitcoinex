defmodule Bitcoinex.Address do
  @moduledoc """
  Base58, Bech32 address support.
  Bitcoin Address Validation
  reference of p2sh p2pkh validation: https://rosettacode.org/wiki/Bitcoin/address_validation#Erlang
  """
  alias Bitcoinex.Segwit
  @type address_type :: :p2pkh | :p2sh | :p2wpkh | :p2wsh
  @address_type ~w(p2pkh p2sh p2wpkh p2wsh)a

  @spec is_valid?(String.t(), Bitcoinex.Network.network_name()) :: boolean
  def is_valid?(address, network_name) do
    Enum.any?(@address_type, &is_valid?(address, network_name, &1))
  end

  @spec is_valid?(String.t(), Bitcoinex.Network.network_name(), address_type) :: boolean
  def is_valid?(address, network_name, :p2pkh) do
    network = apply(Bitcoinex.Network, network_name, [])
    is_valid_base58_check_address?(address, network.p2pkh_version_decimal_prefix)
  end

  def is_valid?(address, network_name, :p2sh) do
    network = apply(Bitcoinex.Network, network_name, [])
    is_valid_base58_check_address?(address, network.p2sh_version_decimal_prefix)
  end

  def is_valid?(address, network_name, address_type) when address_type in [:p2wpkh, :p2wsh] do
    case Segwit.decode_address(address) do
      {:ok, {^network_name, _, _}} ->
        true

      # network is not same as network set in config
      {:ok, {_network_name, _, _}} ->
        false

      {:error, _error} ->
        false
    end
  end

  def supported_address_types() do
    @address_type
  end

  defp is_valid_base58_check_address?(address, valid_prefix) do
    with {:ok, <<address::bytes-size(21), checksum::bytes-size(4)>>} <-
           safe_base58_to_binary(address),
         <<^valid_prefix::8, _::binary>> <-
           address,
         <<four_bytes::bytes-size(4), _::binary>> <-
           :crypto.hash(:sha256, :crypto.hash(:sha256, address)) do
      checksum == four_bytes
    else
      _ ->
        false
    end
  end

  defp safe_base58_to_binary(base58) do
    {:ok, Bitcoinex.Base58.str_to_bin(base58)}
  rescue
    e ->
      {:error, e}
  end
end
