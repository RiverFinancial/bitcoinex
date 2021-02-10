defmodule Bitcoinex.Secp256k1.ExtendedKeyTest do
	use ExUnit.Case
	doctest Bitcoinex.ExtendedKey

	alias Bitcoinex.ExtendedKey


	@softcap Bitcoinex.Secp256k1.Math.pow(2,31)
	# @hardcap @softcap * @softcap

	@invalid_xkeys [
		#changed prefix
		"zpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		#invalid char
		"xpubi61MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		#invalid prefix
		"apub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		#invalid len
		"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet",
		#invalid len
		"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1E",
		## add: invalid len (with valid checksum)
		## add: invalid prefix with valid cs
	]

	@bip32_test_case %{
		# test vectors from bip32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
		#seed: "000102030405060708090a0b0c0d0e0f",
		xpub_m: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		xprv_m: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",

		xpub_m_0h: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		xprv_m_0h: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",

		xpub_m_0h_1: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
		xprv_m_0h_1: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",

		xpub_m_0h_1_2h: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
		xprv_m_0h_1_2h: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",

		xpub_m_0h_1_2h_2: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
		xprv_m_0h_1_2h_2: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",

		xpub_m_0h_1_2h_2_1000000000: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
		xprv_m_0h_1_2h_2_1000000000: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
	}

	@bip49_test_case %{
		masterseedWords: ~w(abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about),
  	masterseed: "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd", #(testnet)

  	# Account 0, root: m/49'/1'/0'
  	account0Xpriv: "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n", #(testnet)
  	account0Xpub: "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY", #(testnet)

  	# Account 0, first receiving private key: m/49'/1'/0'/0/0
  	account0recvPrivateKey: "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ",
  	account0recvPrivateKeyHex: "c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8",
  	account0recvPublicKeyHex: "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",

  	# Address derivation
  	keyhash: "38971f73930f6c141d977ac4fd4a727c854935b3",
  	scriptSig: "001438971f73930f6c141d977ac4fd4a727c854935b3",
  	addressBytes: "336caa13e08b96080a32b5d818d59b4ab3b36742",

  	# addressBytes base58check encoded for testnet
  	address: "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",# (testnet)
	}

	@bip84_test_case %{
		# test case from BIP 84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
		# mnemonic: ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
		c_rootpriv: "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
		c_rootpriv_obj: %ExtendedKey{
				  chaincode: <<121, 35, 64, 141, 173, 211, 199, 181, 110, 237, 21, 86, 119, 7,
				    174, 94, 93, 202, 8, 157, 233, 114, 224, 127, 59, 134, 4, 80, 226, 163, 183,
				    14>>,
				  checksum: <<118, 109, 143, 162>>,
				  child_num: <<0, 0, 0, 0>>,
				  depth: <<0>>,
				  key: <<0, 24, 55, 193, 190, 142, 41, 149, 236, 17, 205, 162, 176, 102, 21, 27,
				    226, 207, 180, 138, 223, 158, 71, 177, 81, 212, 106, 218, 179, 162, 28, 223,
				    103>>,
				  parent: <<0, 0, 0, 0>>,
				  prefix: <<4, 178, 67, 12>>
				},
		c_rootpub: "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF",
		c_rootpub_obj: %ExtendedKey{
		  chaincode: <<121, 35, 64, 141, 173, 211, 199, 181, 110, 237, 21, 86, 119, 7,
		    174, 94, 93, 202, 8, 157, 233, 114, 224, 127, 59, 134, 4, 80, 226, 163, 183,
		    14>>,
		  checksum: <<121, 191, 126, 202>>,
		  child_num: <<0, 0, 0, 0>>,
		  depth: <<0>>,
		  key: <<3, 217, 2, 243, 95, 86, 14, 4, 112, 198, 51, 19, 199, 54, 145, 104,
		    217, 215, 223, 45, 73, 191, 41, 95, 217, 251, 124, 177, 9, 204, 238, 4,
		    148>>,
		  parent: <<0, 0, 0, 0>>,
		  prefix: <<4, 178, 71, 70>>
		},
		# Account 0, root: m/84'/0'/0'
		c_xpriv: "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
		c_xpub: "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
		# Account 0, first receiving address: m/84'/0'/0'/0/0
		c_privkey: "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
		c_pubkey: "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
		c_address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
	}
	


	describe "parse_extended_key/1" do
		test "successfully parse extended zprv" do
			t = @bip84_test_case
			#priv
			assert ExtendedKey.parse_extended_key(t.c_rootpriv) == t.c_rootpriv_obj
			assert ExtendedKey.display(t.c_rootpriv_obj) == t.c_rootpriv
			#pub
			assert ExtendedKey.parse_extended_key(t.c_rootpub) == t.c_rootpub_obj
			assert ExtendedKey.display(t.c_rootpub_obj) == t.c_rootpub
		end
	end

	describe "to_extended_public_key/1" do
		test "successfully turn zprv into zpub" do
			t = @bip84_test_case
			assert ExtendedKey.to_extended_public_key(t.c_rootpriv_obj) == t.c_rootpub_obj
		end
	end

	describe "BIP84 tests" do

		test "successfully derive zprv child key at path m/84'/0'/0'/" do
			t = @bip84_test_case
			child_key = 
				t.c_rootpriv_obj
				|> ExtendedKey.derive_private_child(@softcap + 84)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(@softcap)
			assert ExtendedKey.display(child_key) == t.c_xpriv
		end

		test "successfully derive zpub child key at path m/84'/0'/0'/" do
			t = @bip84_test_case
			child_key = 
				t.c_rootpriv_obj
				|> ExtendedKey.derive_private_child(@softcap + 84)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_public_child(@softcap)
			assert ExtendedKey.display(child_key) == t.c_xpub
		end

		test "successfully derive private key WIF at m/84'/0'/0'/0/0" do
			t = @bip84_test_case
			child_key = 
				t.c_rootpriv_obj
				|> ExtendedKey.derive_private_child(@softcap + 84)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(0)
				|> ExtendedKey.derive_private_child(0)
				|> ExtendedKey.to_private_key()
			assert Bitcoinex.Secp256k1.PrivateKey.wif!(child_key, :mainnet) == t.c_privkey
		end

		test "successfully derive account xpub and then public key at m/84'/0'/0'/0/0" do
			t = @bip84_test_case
			child_key = 
				t.c_rootpriv_obj
				|> ExtendedKey.derive_private_child(@softcap + 84)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_public_child(@softcap)
				|> ExtendedKey.derive_public_child(0)
				|> ExtendedKey.derive_public_child(0)
				|> ExtendedKey.to_public_key()
			assert Bitcoinex.Secp256k1.Point.serialize_public_key(child_key) == t.c_pubkey
		end

	end

	describe "BIP49 tests" do

		test "successfully derive private keys from account yprv  " do
			t = @bip49_test_case
			prvkey = 
				t.account0Xpriv
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_private_child(0)
				|> ExtendedKey.derive_private_child(0)
				|> ExtendedKey.to_private_key()
			assert Bitcoinex.Secp256k1.PrivateKey.wif!(prvkey, :testnet) == t.account0recvPrivateKey
		end

		test "successfully derive public key from account ypub  " do
			t = @bip49_test_case
			pubkey = 
				t.account0Xpub
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_public_child(0)
				|> ExtendedKey.derive_public_child(0)
				|> ExtendedKey.to_public_key()
			assert Bitcoinex.Secp256k1.Point.serialize_public_key(pubkey) == t.account0recvPublicKeyHex
		end

	end

	describe "BIP32 tests" do

		test "BIP32 tests: successfully convert xprv to xpub." do
			t = @bip32_test_case
			
			xprv = ExtendedKey.parse_extended_key(t.xprv_m)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

			xprv = ExtendedKey.parse_extended_key(t.xprv_m_0h)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m_0h)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

			xprv = ExtendedKey.parse_extended_key(t.xprv_m_0h_1)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m_0h_1)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

			xprv = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

			xprv = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

			xprv = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2_1000000000)
			xpub = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2_1000000000)
			assert ExtendedKey.to_extended_public_key(xprv) == xpub

		end

		test "BIP32 tests: derive prv keys in sequence" do
			t = @bip32_test_case
			#derive prv child from prv parent
			m_0h_xprv = 
				t.xprv_m
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_private_child(@softcap)
			assert ExtendedKey.parse_extended_key(t.xprv_m_0h) == m_0h_xprv
			
			#derive child m/0'/1
			m_0h_1_xprv = ExtendedKey.derive_private_child(m_0h_xprv, 1)
			assert ExtendedKey.parse_extended_key(t.xprv_m_0h_1) == m_0h_1_xprv
		end

		test "BIP32 tests: derive pub keys from master prv key" do
			t = @bip32_test_case
			m_0h_xpub = 
				t.xprv_m
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_public_child(@softcap)
			assert ExtendedKey.parse_extended_key(t.xpub_m_0h) == m_0h_xpub
			m_0h_1_2h_xpub = 
				t.xprv_m
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(1)
				|> ExtendedKey.derive_public_child(@softcap + 2)
			assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h) == m_0h_1_2h_xpub

		end
		
		test "BIP32 tests: derive m/0'/1/2'/2/1000000000 from master key" do
			t = @bip32_test_case
			m_0h_1_2h_2_1000000000_xprv = 
				t.xprv_m
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(1)
				|> ExtendedKey.derive_private_child(@softcap + 2)
				|> ExtendedKey.derive_private_child(2)
				|> ExtendedKey.derive_private_child(1000000000)
			assert ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2_1000000000) == m_0h_1_2h_2_1000000000_xprv
		end

		test "BIP32 tests: derive pub child from pub parent" do
			t = @bip32_test_case
			m_0h_1_xpub = 
				t.xpub_m_0h
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_public_child(1)
			assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1) == m_0h_1_xpub

			m_0h_1_2h_2_xpub = 
				t.xpub_m_0h_1_2h
				|> ExtendedKey.parse_extended_key()
				|> ExtendedKey.derive_public_child(2)
			assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2) == m_0h_1_2h_2_xpub

			m_0h_1_2h_2_1000000000_xpub =
				m_0h_1_2h_2_xpub
				|> ExtendedKey.derive_public_child(1000000000)
			assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2_1000000000) == m_0h_1_2h_2_1000000000_xpub
		end

	end
	describe "Invalid Key testing" do

		test "invalid key testing" do
			for t <- @invalid_xkeys do
				{err, _} = ExtendedKey.parse_extended_key(t)
				assert err == :error
			end
		end

	end


end

				
# Test Parse from String, Parse from bytes
# Test parse and serialize
# test parse each prefix
# test fail on public key->hardened child





# r_xprv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
# r_xpub = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
		# {:ok, xprv} = Bitcoinex.Base58.decode(r_xprv)
		# xprv = Bitcoinex.Base58.append_checksum(xprv)
# xprv = Bitcoinex.ExtendedKey.parse_extended_key(r_xprv)
# xpub = Bitcoinex.ExtendedKey.to_extended_public_key(xprv)
# xpub = Bitcoinex.ExtendedKey.parse_extended_key(xpub)


# r_xprv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
# xprv = Bitcoinex.ExtendedKey.parse_extended_key(r_xprv)
# child_84 = Bitcoinex.ExtendedKey.derive_private_child(xprv, Bitcoinex.Secp256k1.Math.pow(2, 31) + 84)
# child_84_0 = Bitcoinex.ExtendedKey.derive_private_child(child_84, Bitcoinex.Secp256k1.Math.pow(2, 31) )
# child_84_0_0 = Bitcoinex.ExtendedKey.derive_private_child(child_84_0, Bitcoinex.Secp256k1.Math.pow(2, 31) )

# Bitcoinex.ExtendedKey.display(child_84_0_0)

# r_child_xprv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
# Bitcoinex.ExtendedKey.parse_extended_key(r_child_xprv)


xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
xpub = Bitcoinex.ExtendedKey.parse_extended_key(xpub)
Bitcoinex.ExtendedKey.derive_public_child(xpub, 1)
