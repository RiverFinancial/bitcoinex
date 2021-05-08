defmodule Bitcoinex.ScriptTest do
	use ExUnit.Case
	doctest Bitcoinex.Script

  alias Bitcoinex.{Script, Utils}
	alias Bitcoinex.Secp256k1.Point

	describe "test basics functions" do

		test "test new/0 and empty?/1" do
			s = Script.new()
			assert Script.empty?(s)

			s = Script.push_op(s, :op_true)
			assert !(Script.empty?(s))
		end

		test "test is_true?/1" do
			s = Script.new()
			s = Script.push_op(s, :op_true)
			assert Script.is_true?(s)

			s1 = Script.new()
			s1 = Script.push_op(s1, 0x51)
			assert Script.is_true?(s1)

			s2 = Script.push_op(s1, :op_true)
			assert !(Script.is_true?(s2))
		end

		test "test script_length/1 and byte_length/1" do
			s = Script.new()
			assert Script.script_length(s) == 0
			assert Script.byte_length(s) == 0

			#TODO when you add 1 int, it converts to string, which messes up serialize
			s = Script.push_op(s, :op_true)
			assert Script.script_length(s) == 1
			assert Script.byte_length(s) == 1

			s = Script.push_data(s, <<1,1,1,1>>)
			assert Script.script_length(s) == 3
			assert Script.byte_length(s) == 6

		end

		test "test get_op_num/1 and get_op_atom/1" do
			assert {:ok, 0x00} == Script.get_op_num(:op_0)
			assert {:ok, 0x60} == Script.get_op_num(:op_16)
			assert {:ok, 0xfe} == Script.get_op_num(:op_pubkey)
			assert :error == Script.get_op_num(:op_eval)
			
			assert {:ok, :op_0} == Script.get_op_atom(0x00)
			assert {:ok, :op_pushdata1} == Script.get_op_atom(0x4c)
			assert {:ok, :op_invalidopcode} == Script.get_op_atom(0xff)
			assert {:ok, :op_nop1} == Script.get_op_atom(0xb0)

			assert 5 == Script.get_op_atom(5)
			assert 75 == Script.get_op_atom(75)
			assert :error == Script.get_op_atom(-1)
		end

		test "test pop/1" do
			s = Script.new()
			assert Script.pop(s) == nil
			
			s = Script.push_op(s, :op_true)
			{:ok, 81, s1} = Script.pop(s)
			assert Script.empty?(s1)

			s = Script.push_data(s1, <<1, 1, 1, 1, 1, 1, 1>>)
			{:ok, 7, s1} = Script.pop(s)
			{:ok, <<1, 1, 1, 1, 1, 1, 1>>, s2} = Script.pop(s1) 
			assert Script.pop(s2) == nil
		end
	end

	describe "test push_op/2" do
		test "test pushing and popping ops by atom" do
			s = Script.new()
			s = 
				s
				|> Script.push_op(:op_true)
				|> Script.push_op(:op_false)
				|> Script.push_op(:op_checksig)

			assert Script.script_length(s) == 3
			assert Script.byte_length(s) == 3

			{:ok, o1, s1} = Script.pop(s)
			{:ok, o2, s2} = Script.pop(s1)
			{:ok, o3, _s3} = Script.pop(s2)

			# checksig
			assert o1 == 0xac 
			# false
			assert o2 == 0x00
			# true
			assert o3 == 0x51
		end

		test "test pushing and popping ops by integer" do
			s = Script.new()
			s = 
				s
				|> Script.push_op(0x51) # true
				|> Script.push_op(0x00) # false
				|> Script.push_op(0xac) # checksig

			assert Script.script_length(s) == 3
			assert Script.byte_length(s) == 3

			{:ok, o1, s1} = Script.pop(s)
			{:ok, o2, s2} = Script.pop(s1)
			{:ok, o3, _s3} = Script.pop(s2)

			assert o1 == 0xac 
			assert o2 == 0x00
			assert o3 == 0x51
		end
	end

	describe "push_data/2" do
		test "push public key" do
			s = Script.new()
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			bin = Base.decode16!(hex, case: :lower)
			s = Script.push_data(s, bin)
			{:ok, len, s2} = Script.pop(s)
			{:ok, pk, _s3} = Script.pop(s2)

			assert len == 33
			assert pk == bin
		end

		test "push pubkey hash" do
			s = Script.new()
			hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
			bin = Base.decode16!(hex, case: :lower)
			Script.push_data(s, bin)
		end

		test "push data 1" do
			s = Script.new()
			hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			bin = Utils.hex_to_bin(hex)
			s = Script.push_data(s, bin)

			{:ok, op2, s1} = Script.pop(s)
			{:ok, bin2, _s2} = Script.pop(s1)

			assert op2 == 76
			assert bin2 == bin
		end

		test "push data 2" do
			s = Script.new()
			hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			bin = Utils.hex_to_bin(hex)
			s = Script.push_data(s, bin)

			{:ok, op2, s1} = Script.pop(s)
			{:ok, bin2, _s2} = Script.pop(s1)

			assert op2 == 77
			assert bin2 == bin
		end


	end

	describe "test specific script creation and identification" do 

		test "test parse p2pk from uncompressed key" do
			s = Script.new()
			# from tx df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a
			hex = "04184f32b212815c6e522e66686324030ff7e5bf08efb21f8b00614fb7690e19131dd31304c54f37baa40db231c918106bb9fd43373e37ae31a0befc6ecaefb867"
			bin = Base.decode16!(hex, case: :lower)
			s1 = Script.push_op(s, :op_checksig)
			s1 = Script.push_data(s1, bin)

			assert Script.is_p2pk(s1)

			s2 = Script.create_p2pk(bin)
			assert s2 == s1

			# from tx da69323ec33972675d9594b6569983bfc2257bced36d8df541a2aadfe31db016
			hex = "035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344"
			bin = Base.decode16!(hex, case: :lower)
			s3 = Script.push_op(s, :op_checksig)
			s3 = Script.push_data(s3, bin)

			assert Script.is_p2pk(s3)

			s4 = Script.create_p2pk(bin)
			assert s4 == s3
		end

		test "test is_p2sh and create_p2sh" do
			s = Script.new()
			hex = "d1914384b57de2944ce1b6a90adf2f7b72cfe61e"
			bin = Base.decode16!(hex, case: :lower)
			s = Script.push_op(s, 0x87)
			s = Script.push_data(s, bin)
			s = Script.push_op(s, 0xa9)

			s2 = Script.create_p2sh(bin)

			assert Script.is_p2sh(s)
			assert s2 == s
		end

		test "test is_p2pkh and create_p2pkh" do
			s = Script.new()
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			bin = Base.decode16!(hex, case: :lower)
			h160 = Utils.hash160(bin)
			s = Script.push_op(s, :op_checksig)
			s = Script.push_op(s, :op_equalverify)
			s = Script.push_data(s, h160)
			s = Script.push_op(s, :op_hash160)
			s = Script.push_op(s, :op_dup)

			s2 = Script.create_p2pkh(h160)

			assert Script.is_p2pkh(s)
			assert s2 == s
		end

		test "test is_p2wpkh and create_p2wpkh" do
			s = Script.new()
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			bin = Base.decode16!(hex, case: :lower)
			h160 = Utils.hash160(bin)

			s = Script.push_data(s, h160)
			s = Script.push_op(s, 0x00)
			
			s2 = Script.create_p2wpkh(h160)

			assert Script.is_p2wpkh(s)
			assert s2 == s
		end

		test "test create_p2sh_p2wpkh" do
			s = Script.new()
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			bin = Base.decode16!(hex, case: :lower)
			h160 = Utils.hash160(bin)

			p2wpkh = Script.push_data(s, h160)
			p2wpkh = Script.push_op(p2wpkh, 0x00)
			sbin = Script.serialize_script(p2wpkh)
			sh = Utils.hash160(sbin)

			p2sh = Script.push_op(s, 0x87)
			p2sh = Script.push_data(p2sh, sh)
			p2sh = Script.push_op(p2sh, 0xa9)
			
			s2 = Script.create_p2sh_p2wpkh(h160)

			assert Script.is_p2sh(p2sh)
			assert s2 == p2sh
		end

		test "test create scripts from pubkey" do
			hex = "033b15e1b8c51bb947a134d17addc3eb6abbda551ad02137699636f907ad7e0f1a"
			h160 = hex |> Base.decode16!(case: :lower) |> Utils.hash160()
			pubkey = Point.parse_public_key(hex)

			p2pkh = Script.public_key_to_p2pkh(pubkey)
			assert Script.is_p2pkh(p2pkh)

			
			# check correct p2pkh format and pkh
			{:ok, op_dup, rest} = Script.pop(p2pkh)
			{:ok, op_h160, rest} = Script.pop(rest)
			{:ok, len, rest} = Script.pop(rest)
			{:ok, pkh, _rest} = Script.pop(rest)
			assert op_dup == 0x76
			assert op_h160 == 0xa9
			assert len == 20
			assert pkh == h160

			p2wpkh = Script.public_key_to_p2wpkh(pubkey)
			assert Script.is_p2wpkh(p2wpkh)
			# check pkh is correct
			{:ok, witver, rest} = Script.pop(p2wpkh)
			{:ok, len, rest} = Script.pop(rest)
			{:ok, pkh, rest} = Script.pop(rest)
			assert witver == 0
			assert len == 20
			assert pkh == h160
			assert Script.empty?(rest)


			p2sh_p2wpkh = Script.public_key_to_p2sh_p2wpkh(pubkey)
			assert Script.is_p2sh(p2sh_p2wpkh)

		end

	end

	describe "test parsing scripts" do

		
		test "test parse p2pk from uncompressed key" do
			# from tx df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a
			s_hex = "4104184f32b212815c6e522e66686324030ff7e5bf08efb21f8b00614fb7690e19131dd31304c54f37baa40db231c918106bb9fd43373e37ae31a0befc6ecaefb867ac"
			s = Script.parse_script(s_hex)

			assert Script.is_p2pk(s)

			# from tx da69323ec33972675d9594b6569983bfc2257bced36d8df541a2aadfe31db016
			s_hex = "21035ce3ee697cd5148e12ab7bb45c1ef4dd5ee2bf4867d9d35135e214e073211344ac"
			s = Script.parse_script(s_hex)

			assert Script.is_p2pk(s)
		end

		test "test parse p2pkh" do
			s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"
			s = Script.parse_script(s_hex)

			assert Script.is_p2pkh(s)

			# from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
			s_hex = "76a914c689464b843e9782e54c662f544e452940357a9888ac"
			s = Script.parse_script(s_hex)

			assert Script.is_p2pkh(s)
		end

		test "test parse p2sh" do
			s_hex = "a914cbb5d42faa8e9267f3a4ab9eabde9ebc9016ef8787"
			s = Script.parse_script(s_hex)

			assert Script.is_p2sh(s)
		end

		# from tx fd910133a2febe8e0edbd25c908f0a8339afda29ff820a1f845e8dd2dccc5658
		test "test parse p2wpkh" do
			s_hex = "0014a38e224fc2ead8f32b13e3cef6bbf3520f16378c"
			s = Script.parse_script(s_hex)

			assert Script.is_p2wpkh(s)
		end

		# from tx d3bde81de54f8ace1cf98bab6b06772f752979e3d4e7866691fcb2965d9c766c
		test "test parse p2wsh" do
			s_hex = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
			s = Script.parse_script(s_hex)

			assert Script.is_p2wsh(s)
		end

		test "test parse short script" do
			assert Script.parse_script("") == Script.new()
			assert Script.parse_script("00") == %Script{items: [0]}
			assert Script.parse_script("51") == %Script{items: [0x51]}
			assert Script.parse_script("5151") == %Script{items: [0x51,0x51]}
		end

	end

	describe "test parse invalid scripts" do
		scripts = [
			"4caa12",
			"004ca112",
			"4c6ac5802547372094c580258025473720941cee958bca07652beaaaa7e6419bc91cee958b802720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9",
			"1",
			"21",
			"31",
			"4c"
		]
		for hex <- scripts do
			{res, _msg} = Script.parse_script(hex)
			assert res == :error
		end
	end

	describe "test display_script/1" do
		test "test display_script/1 with p2pkh" do
			text = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 c58025473720941cee958bca07652be7e6419bc9 OP_EQUALVERIFY OP_CHECKSIG"
			s_hex = "76a914c58025473720941cee958bca07652be7e6419bc988ac"
			s = Script.parse_script(s_hex)

			assert Script.display_script(s) == text
		end

		test "display_script/1 with random script" do
			text = "OP_0 OP_PUSHDATA1 OP_16 OP_5 OP_RETURN OP_ROLL OP_CHECKSIG OP_NOP1 0102030405"
			s = %Script{items: [0x00, 0x4c, 0x60, 0x55, 0x6a, 0x7a, 0xac, 0xb0, <<1, 2, 3, 4, 5>>]}

			assert Script.display_script(s) == text
		end

		test "push data 1" do
			text = "OP_PUSHDATA1 c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			s = Script.new()
			hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			bin = Utils.hex_to_bin(hex)
			s = Script.push_data(s, bin)

			assert Script.display_script(s) == text
		end

		test "push data 2" do
			text = "OP_PUSHDATA2 c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			s = Script.new()
			hex = "c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91ceec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7ec5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be7e6419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc96419bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9bc91cee958bc58025473720941cee958bca07652be7e6419bc9ca07652c5802547372094c58025478025473720941cee958bca07652be7e6419bc91cee958b8025473720941cee958bca07652be7e6419bc91cee958b3720941cee958bca07652be9bc9958bc58025473720941cee958bca07652be7e6419bc9ca07652be7e6419bc9"
			bin = Utils.hex_to_bin(hex)
			s = Script.push_data(s, bin)

			assert Script.display_script(s) == text
		end

	end

end