defmodule Bitcoinex.DescriptorTest do
	use ExUnit.Case
	doctest Bitcoinex.Descriptor

	alias Bitcoinex.{Descriptor, ExtendedKey, Secp256k1.Point, Secp256k1.PrivateKey}

	# 0-15 are from https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
	# >15 are original examples and probably edge cases

	@pk_descriptors [
		# 0 describes a P2PK output with the specified public key.
		"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
		# 11 describes a P2PK output with the public key of the specified xpub.
		"pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)",
		# 16 describes a P2PK to a mainnet private key
		"pk(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",
		# 17 describes a P2PK to a testnet private key
    "pk(cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm)",
		# 18 describes a P2PK to a mainnet private key with HD origin info
		"pk([d34db33f]KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",
		# 19 describes a P2PK to a mainnet private key with HD origin and ancestor path info
		"pk([d34db33f/44'/0'/0']KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",
	]

	@pkh_descriptors [
		# 1 describes a P2PKH output with the specified public key.
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
		# 12 describes a P2PKH output with child key 1/2 of the specified xpub.
		"pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)",
		# 13 describes a set of P2PKH outputs, but additionally specifies that the specified xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0'.
		"pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)",
		# 20 describes a P2PKH to a mainnet private key
		"pkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",
		# 21 describes a P2PKH to a testnet private key
    "pkh(cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm)",
	]

	@wpkh_descriptors [
		# 2 describes a P2WPKH output with the specified public key.
		"wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
		# 21 describes a P2WPKH to a mainnet private key
		"wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",
		# 22 describes a P2WPKH to a testnet private key
    "wpkh(cMahea7zqjxrtgAbB7LSGbcQUr1uX1okdzTtkBA29TFk41r74ddm)",
	]

	@sh_descriptors [
		# 3 describes a P2SH-P2WPKH output with the specified public key.
		"sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
		# 5 describes an (overly complicated) P2SH-P2WSH-P2PKH output with the specified public key.
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
		# 7 describes a P2SH 2-of-2 multisig output with keys in the specified order.
		"sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
		# 8 describes a P2SH 2-of-2 multisig output with keys sorted lexicographically in the resulting redeemScript.
		"sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
		# 10 describes a P2SH-P2WSH 1-of-3 multisig output with keys in the specified order.
		"sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))",
	]

	@wsh_descriptors [
		# 9 describes a P2WSH 2-of-3 multisig output with keys in the specified order.
		"wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))",
		# 14 describes a set of 1-of-2 P2WSH multisig outputs where the first multisig key is the 1/0/i child of the first specified xpub and the second multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default).
		"wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
		# 15 describes a set of 1-of-2 P2WSH multisig outputs where one multisig key is the 1/0/i child of the first specified xpub and the other multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default). The order of public keys in the resulting witnessScripts is determined by the lexicographic order of the public keys at that index.
		"wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
	]

	@combo_descriptors [
		# 4 describes any P2PK, P2PKH, P2WPKH, or P2SH-P2WPKH output with the specified public key.
		"combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
	]

	@multi_descriptors [
		# 6 describes a bare 1-of-2 multisig output with keys in the specified order.
		"multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
		# taken from 9, describes a 2-of-3 multisig output with keys in the specified order.
		"multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)",
		# taken from 14, describes a set of 1-of-2 P2WSH multisig outputs where the first multisig key is the 1/0/i child of the first specified xpub and the second multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default).
		"multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)",
	]

	@sorted_multi_descriptors [
		# taken from 15, describes a set of 1-of-2 P2WSH multisig outputs where one multisig key is the 1/0/i child of the first specified xpub and the other multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default). The order of public keys in the resulting witnessScripts is determined by the lexicographic order of the public keys at that index.
		"sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)"
	]

	@all_descriptors @pk_descriptors ++ @pkh_descriptors ++ @wpkh_descriptors
		++ @sh_descriptors ++ @wsh_descriptors ++ @combo_descriptors ++ @multi_descriptors
		++ @sorted_multi_descriptors

	describe "parse descriptor" do
	end

	describe "test parse/serialize pair" do
		test "parse and serialize descriptor" do
			for d <- @all_descriptors do
				{:ok, desc} = Descriptor.parse_descriptor(d)
				assert Descriptor.serialize_descriptor(desc) == d
			end
		end
	end

	describe "test create descriptor" do
		test "create p2pk" do
			# ex0 from @pk_descriptors
			{:ok, pk} = Point.parse_public_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
			{:ok, desc} = Descriptor.create_p2pk(pk)
			assert Descriptor.serialize_descriptor(desc) == "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"

			# ex11 from @pk_descriptors
			{:ok, xpub} = ExtendedKey.parse_extended_key("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
			{:ok, desc} = Descriptor.create_p2pk(xpub)
			assert Descriptor.serialize_descriptor(desc) == "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)"

			# ex16 from @pk_descriptors
			{:ok, priv, _,_} = PrivateKey.parse_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E")
			{:ok, desc} = Descriptor.create_p2pk(priv)
			assert Descriptor.serialize_descriptor(desc) == "pk(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)"
		end

		test "create p2pkh" do
			# 13 describes a set of P2PKH outputs, but additionally specifies that the specified xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0'.
			# "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)",
			# 20 describes a P2PKH to a mainnet private key
			# "pkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E)",

			# ex1 from @pkh_descriptors
			{:ok, pk} = Point.parse_public_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
			{:ok, desc} = Descriptor.create_p2pkh(pk)
			assert Descriptor.serialize_descriptor(desc) == "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"

			# ex12 from @pkh_descriptors
			{:ok, xpub} = ExtendedKey.parse_extended_key("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
			{:ok, deriv} = ExtendedKey.DerivationPath.from_string("1/2")
			#TODO make it easier to create Descriptors with path data
			dkey = Descriptor.DKey.from_key(xpub, %{desc_path: deriv})
			{:ok, desc} = Descriptor.create_p2pkh(dkey)
			assert Descriptor.serialize_descriptor(desc) == "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)"

		end


	end

end

# alias Bitcoinex.{
#   ExtendedKey,
#   ExtendedKey.DerivationPath,
#   Descriptor.DKey,
#   Secp256k1.Point,
#   Secp256k1.PrivateKey
# }

# {:ok, px} =
#   "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
#   |> ExtendedKey.parse_extended_key()

# {:ok, dp} = DerivationPath.from_string("44'/0'/0'/")
# {:ok, ddp} = DerivationPath.from_string("0/1'/*'")
# {:ok, cx} = ExtendedKey.derive_extended_key(px, dp)
# fp = ExtendedKey.get_fingerprint(cx)
# dk = %DKey{key: cx, ancestor_path: dp, fingerprint: fp, descendant_path: ddp}
# DKey.serialize(dk)

# {:ok, sk, network, _comp} =
#   PrivateKey.parse_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi4ZxKRdkhWeLbjoGkhRF5E")

# dk2 = %DKey{key: {sk, network}}

# {:ok, pk} =
#   Point.parse_public_key("020003b94aecea4d0a57a6c87cf43c50c8b3736f33ab7fd34f02441b6e94477689")

# dk3 = %DKey{key: pk}

# "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*"

# "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*'"
