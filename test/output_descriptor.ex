defmodule Bitcoinex.OutputDescriptorTest do
  use ExUnit.Case
  doctest Bitcoinex.OutputDescriptor

  alias Bitcoinex.{OutputDescriptor, Script, Key, Utils, Secp256k1}
  alias Bitcoinex.Secp256k1.Point

  test "parse pk descriptor" do
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)
    {:ok, pub_key_bin} = Secp256k1.Point.sec_serialize(pub_key)
    pub_key_hex = Utils.bin_to_hex(pub_key_bin)

    descriptor_str = "pk(#{pub_key_hex})"

    assert {:ok, descriptor} = OutputDescriptor.parse(descriptor_str)
    assert descriptor.type == :pk
    assert %Point{} = descriptor.key

    # Test script generation
    script = OutputDescriptor.to_script(descriptor)
    assert Script.is_p2pk?(script)
  end

  test "parse pkh descriptor" do
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)
    {:ok, pub_key_bin} = Secp256k1.Point.sec_serialize(pub_key)
    pub_key_hex = Utils.bin_to_hex(pub_key_bin)

    descriptor_str = "pkh(#{pub_key_hex})"

    assert {:ok, descriptor} = OutputDescriptor.parse(descriptor_str)
    assert descriptor.type == :pkh
    assert %Point{} = descriptor.key

    # Test script generation
    script = OutputDescriptor.to_script(descriptor)
    assert Script.is_p2pkh?(script)
  end

  test "parse wpkh descriptor" do
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)
    {:ok, pub_key_bin} = Secp256k1.Point.sec_serialize(pub_key)
    pub_key_hex = Utils.bin_to_hex(pub_key_bin)

    descriptor_str = "wpkh(#{pub_key_hex})"

    assert {:ok, descriptor} = OutputDescriptor.parse(descriptor_str)
    assert descriptor.type == :wpkh
    assert %Point{} = descriptor.key

    # Test script generation
    script = OutputDescriptor.to_script(descriptor)
    assert Script.is_p2wpkh?(script)
  end

  test "parse tr descriptor with public key" do
    # Create a test key
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)
    {:ok, pub_key_bin} = Secp256k1.Point.sec_serialize(pub_key)
    pub_key_hex = Utils.bin_to_hex(pub_key_bin)

    descriptor_str = "tr(#{pub_key_hex})"

    assert {:ok, descriptor} = OutputDescriptor.parse(descriptor_str)
    assert descriptor.type == :tr
    assert %Point{} = descriptor.key

    # Test script generation
    script = OutputDescriptor.to_script(descriptor)
    assert is_binary(Script.serialize_script(script))
    assert Script.is_p2tr?(script)

    # Test address generation
    {:ok, address} = OutputDescriptor.to_address(descriptor, :mainnet)
    assert String.starts_with?(address, "bc1p")
  end

  test "tr descriptor supports mainnet and testnet addresses" do
    # Create a test key
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)

    # Create descriptor
    tr_descriptor = %OutputDescriptor{
      type: :tr,
      key: pub_key,
      checksum: nil
    }

    # Test mainnet address
    {:ok, mainnet_address} = OutputDescriptor.to_address(tr_descriptor, :mainnet)
    assert String.starts_with?(mainnet_address, "bc1p")

    # Test testnet address
    {:ok, testnet_address} = OutputDescriptor.to_address(tr_descriptor, :testnet)
    assert String.starts_with?(testnet_address, "tb1p")
  end

  test "tr descriptor rejects script path spending" do
    # Try to create a nested tr descriptor (not supported yet)
    {:ok, priv_key} = Key.new_private_key()
    {:ok, pub_key} = Key.to_public_key(priv_key)
    {:ok, pub_key_bin} = Secp256k1.Point.sec_serialize(pub_key)
    pub_key_hex = Utils.bin_to_hex(pub_key_bin)

    inner_descriptor_str = "pkh(#{pub_key_hex})"
    {:ok, inner_descriptor} = OutputDescriptor.parse(inner_descriptor_str)

    # This should fail as script path spending is not yet supported
    assert {:error, _} = OutputDescriptor.parse("tr(#{inner_descriptor_str})")
  end

  test "multi descriptor" do
    # Create test keys
    {:ok, priv_key1} = Key.new_private_key()
    {:ok, pub_key1} = Key.to_public_key(priv_key1)
    {:ok, pub_key_bin1} = Secp256k1.Point.sec_serialize(pub_key1)
    pub_key_hex1 = Utils.bin_to_hex(pub_key_bin1)

    {:ok, priv_key2} = Key.new_private_key()
    {:ok, pub_key2} = Key.to_public_key(priv_key2)
    {:ok, pub_key_bin2} = Secp256k1.Point.sec_serialize(pub_key2)
    pub_key_hex2 = Utils.bin_to_hex(pub_key_bin2)

    descriptor_str = "multi(1,#{pub_key_hex1},#{pub_key_hex2})"

    assert {:ok, descriptor} = OutputDescriptor.parse(descriptor_str)
    assert descriptor.type == :multi
    assert descriptor.threshold == 1
    assert length(descriptor.keys) == 2

    # Test script generation
    script = OutputDescriptor.to_script(descriptor)
    assert Script.is_multi?(script)
  end
end
