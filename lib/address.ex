defmodule Bitcoinex.Address do
  @moduledoc """
  Base58, Bech32 address support.
  Bitcoin Address Validation
  reference of p2sh p2pkh validation: https://rosettacode.org/wiki/Bitcoin/address_validation#Erlang
  """
  alias Bitcoinex.{Segwit, Base58Check, Network}
  @type address_type :: :p2pkh | :p2sh | :p2wpkh | :p2wsh
  @address_types ~w(p2pkh p2sh p2wpkh p2wsh)a

  # TODO: write tests
  def encode(pubkey, network_name, :p2pkh) do
    network = Network.get_network(network_name)
    decimal_prefix = network.p2pkh_version_decimal_prefix

    Base58Check.encode(<<decimal_prefix>> <> pubkey)
  end

  # TODO: write tests
  def encode(script_hash, network_name, :p2sh) do
    network = Network.get_network(network_name)
    decimal_prefix = network.p2sh_version_decimal_prefix
    Base58Check.encode(<<decimal_prefix>> <> script_hash)
  end

  @spec is_valid?(String.t(), Bitcoinex.Network.network_name()) :: boolean
  def is_valid?(address, network_name) do
    Enum.any?(@address_types, &is_valid?(address, network_name, &1))
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

  def is_valid?(address, network_name, :p2wpkh) do
    case Segwit.decode_address(address) do
      {:ok, {^network_name, witness_version, witness_program}} ->
        if witness_version == 0 and length(witness_program) == 20 do
            true
        else
            false
        end
      # network is not same as network set in config
      {:ok, {_network_name, _, _}} ->
        false

      {:error, _error} ->
        false
    end
  end

  def is_valid?(address, network_name, :p2wsh) do
    case Segwit.decode_address(address) do
      {:ok, {^network_name, witness_version, witness_program}} ->
        if witness_version == 0 and length(witness_program) == 32 do
            true
        else
            false
        end
      # network is not same as network set in config
      {:ok, {_network_name, _, _}} ->
        false

      {:error, _error} ->
        false
    end
  end

  def supported_address_types() do
    @address_types
  end

  defp is_valid_base58_check_address?(address, valid_prefix) do
    case Base58Check.decode(address) do
      {:ok, <<^valid_prefix::8, _::binary>>} ->
        true

      _ ->
        false
    end
  end

  @spec decode_type(String.t(), Bitcoinex.Network.network_name()) ::
          {:ok, address_type} | {:error, term()}
  def decode_type(address, network_name) do
    case Enum.find(@address_types, &is_valid?(address, network_name, &1)) do
      nil -> {:error, :decode_error}
      type -> {:ok, type}
    end
  end
end
