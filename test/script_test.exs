
defmodule Bitcoinex.ScriptTest do
  use ExUnit.Case
  doctest Bitcoinex.ScriptTest

  alias Bitcoinex.Script

	describe "push_data/2" do
		test "push public key" do
			s = Script.new()
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			bin = Base.decode16!(hex, case: :lower)
			s = Script.push_data(s, bin)

		end

		test "push pubkey hash" do
			s = Script.new()
			hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
			bin = Base.decode16!(hex, case: :lower)
			Script.push_data(s, bin)
		end


	end

end

alias Bitcoinex.Script
alias Bitcoinex.Secp256k1.Point
#P2SH
s = Script.new()
hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
bin = Base.decode16!(hex, case: :lower)
s = Script.push_op(s, 0x87)
s = Script.push_data(s, bin)
s = Script.push_op(s, 0xa9)
Script.display_script(s)
Script.is_p2sh(s)

#P2PKH
s2 = Script.new()
hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
bin = Base.decode16!(hex, case: :lower)
h160 = Bitcoinex.Utils.hash160(bin)
s2 = Script.push_op(s2, :op_checksig)
s2 = Script.push_op(s2, :op_equalverify)
s2 = Script.push_data(s2, h160)
s2 = Script.push_op(s2, :op_hash160)
s2 = Script.push_op(s2, :op_dup)
Script.display_script(s2)
Script.is_p2pkh(s2)


# PARSE P2PKH

alias Bitcoinex.Script
s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"
s = Script.parse_script(s_hex)
Script.display_script(s)

s2 = Script.new()
hex = "c58025473720941cee958bca07652be7e6419bc9"
bin = Bitcoinex.Utils.hex_to_bin(hex)
s2 = Script.push_op(s2, :op_checksig)
s2 = Script.push_op(s2, :op_equalverify)
s2 = Script.push_data(s2, bin)
s2 = Script.push_op(s2, :op_hash160)
s2 = Script.push_op(s2, :op_dup)
Script.to_hex(s2)

# script with pushdata2 

s3 = Script.new()
hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
bin = Bitcoinex.Utils.hex_to_bin(hex)
s3 = Script.push_op(s3, :op_checksig)
s3 = Script.push_op(s3, :op_equalverify)
s3 = Script.push_data(s3, bin)
# c_hex = "4c6ac5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc988ac"


# pushdata4
s4 = Script.new()
hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
bin = Bitcoinex.Utils.hex_to_bin(hex)
s4 = Script.push_op(s4, :op_checksig)
s4 = Script.push_op(s4, :op_equalverify)
s4 = Script.push_data(s4, bin)
# c_hex = "4de901c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc988ac"