
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
Script.display(s)
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
Script.display(s2)
Script.is_p2pkh(s2)