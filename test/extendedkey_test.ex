defmodule Bitcoinex.Secp256k1.ExtendedKeyTest do
	use ExUnit.Case
	doctest Bitcoinex.ExtendedKey

	alias Bitcoinex.ExtendedKey


	@softcap Bitcoinex.Secp256k1.Math.pow(2,31)
	# @hardcap @softcap * @softcap

	@bip84_test_case %{
		# test case from BIP 84
		# mnemonic = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
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

	describe "derive_child_key/2" do
		test "successfully derive zprv child key at path m/84'/0'/0'/" do
			t = @bip84_test_case
			child_key = 
				t.c_rootpriv_obj
				|> ExtendedKey.derive_private_child(@softcap + 84)
				|> ExtendedKey.derive_private_child(@softcap)
				|> ExtendedKey.derive_private_child(@softcap)
			assert ExtendedKey.display(child_key) == t.c_xpriv
		end
	end
end

				
# Test Parse from String, Parse from bytes
# Test parse and serialize
# test parse each prefix





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