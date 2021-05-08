defmodule Bitcoinex.Script do
	@moduledoc """
		a module for manipulating Bitcoin Scripts
	"""

	import Bitcoinex.Opcode

	alias Bitcoinex.Secp256k1.Point

	alias Bitcoinex.Utils

	@type script_type :: :p2pk | :p2pkh | :p2sh | :p2wpkh | :p2wsh | :p2tr | :non_standard

	@type t :: %__MODULE__{
		items: list
	}

	@enforce_keys [
		:items
	]
	defstruct [:items]

	defp invalid_opcode_error(msg), do: {:error, "invalid opcode: #{msg}"}

	@spec new() :: t()
	def new, do: %__MODULE__{items: []}

	@spec is_true?(t()) :: bool
	def is_true?(%__MODULE__{items: [0x51]}), do: true
	def is_true?(%__MODULE__{items: [:op_true]}), do: true
	def is_true?(_), do: false


	@spec empty?(t()) :: bool
	def empty?(%__MODULE__{items: []}), do: true
	def empty?(_), do: false

	@spec script_length(t()) :: non_neg_integer()
	def script_length(%__MODULE__{items: items}), do: length(items)

	@spec byte_length(t()) :: non_neg_integer()
	def byte_length(script) do
		script
		|> serialize_script()
		|> byte_size()
	end

	@spec get_op_num(atom) :: non_neg_integer()
	def get_op_num(op), do: Map.fetch(opcode_atoms(), op)

	@spec get_op_atom(non_neg_integer()) :: atom
	def get_op_atom(i), do: if i > 0 and i < 0x4c, do: i, else: Map.fetch(opcode_nums(), i) 

	@spec pop(t()) :: nil | {:ok, non_neg_integer() | binary, t()}
	def pop(%__MODULE__{items: []}), do: nil
	def pop(%__MODULE__{items: [item | stack]}), do: {:ok, item, %__MODULE__{items: stack}}

	@spec push_op(atom | non_neg_integer(), t()) :: t()

	def push_op(%__MODULE__{items: stack}, item) do
		# item is opcode num
		if is_integer(item) and item >= 0 and item < 0xff do
			%__MODULE__{items: [item | stack]}
		else
			# item is atom
			case get_op_num(item) do
				nil -> invalid_opcode_error(item)
				{:ok, op} -> %__MODULE__{items: [op | stack]}	
			end
		end
	end

	# used to push data lengths and raw binary
	defp push_raw_data(%__MODULE__{items: stack}, data) do
		%__MODULE__{items: [data | stack]}
	end

	@spec push_data(binary, t()) :: t()
	def push_data(script, data) do
		datalen = byte_size(data)
		script = push_raw_data(script, data)
		cond do
			datalen < 0x4c ->
				push_op(script, datalen)
			datalen <= 0xff ->
				push_op(script, :op_pushdata1)
			datalen <= 0x0208 ->
				push_op(script, :op_pushdata2)
			true ->
				{:error, "invalid data length, must be 0..0x0208, got #{datalen}"}
		end
	end

	# SERIALIZE & PARSE 
	defp serializer(%__MODULE__{items: []}, acc), do: acc
	defp serializer(%__MODULE__{items: [item | script]}, acc) when is_integer(item) do
		# prevents UTF-8 ints from becoming strings
		serializer(%__MODULE__{items: script}, acc <> Utils.int_to_little(item, 1))
	end
	# For data pushes
	defp serializer(%__MODULE__{items: [item | script]}, acc) when is_binary(item) do
		len = byte_size(item)
		cond do
			len < 0x4c -> # CHECK IF PUSHBYTES75 is valid
				serializer(%__MODULE__{items: script}, acc <> item)
			len <= 0xff -> 
				len = len |> Utils.int_to_little(1)
				serializer(%__MODULE__{items: script}, acc <> len <> item)
			# PUSHDATA limited to 520 bytes, so no PUSHDATA4 is a valid script.
			# Should we allow this?
			len <= 0x0208 ->
				len = Utils.int_to_little(len, 2)
				serializer(%__MODULE__{items: script}, acc <> len <> item)
			# len <= 0xffffffff ->
			# 	len = Utils.int_to_little(len, 4)
			# 	serializer(%__MODULE__{items: script}, acc <> len <> item)
			true -> {:error, "data is too long"}
		end
	end

	@spec serialize_script(t()) :: binary
	def serialize_script(script = %__MODULE__{}) do
		# avoid binary being interpreted as utf8 strings
		# serialize_script(%Script{items: [0x81]}) will still display "Q" but 
		# it functions as binary 0x51. Use to_hex for displaying scripts.
		<<0, script::binary>> = serializer(script, <<0>>)
		script
	end

	def to_hex(script) do
		 script
		 |> serialize_script() 
		 |> Base.encode16(case: :lower)
	end

	def parse_script(script_str) when is_binary(script_str) do
		try do
			case Utils.hex_to_bin(script_str) do
				{:error, _msg} -> 
						# necessary to allow parse_script to accept raw binary script
						parser(new(), script_str)
				bin ->
					parser(new(), bin)
			end
		rescue
			_ -> {:error, "invalid script. parse_script accepts hex or binary."}
		end
	end

	defp parser(script, <<>>), do: script
	defp parser(script, <<next::binary-size(1), bin::binary>>) do
		op = :binary.decode_unsigned(next)
		cond do
			# PUSHBYTES
			op > 0x00 and op < 0x4c ->
				script
				|> parser(:binary.part(bin, op, byte_size(bin) - op))
				|> push_raw_data(:binary.part(bin, 0, op))
				|> push_op(op)
			# PUSHDATA1
			op == 0x4c ->
				len = bin |> :binary.part(0, 1) |> Utils.little_to_int()
				script
				|> parser(:binary.part(bin, len, byte_size(bin) - len - 1))
				|> push_raw_data(:binary.part(bin, 1, len))
				|> push_op(op)
				
			# PUSHDATA2
			op == 0x4d ->
				len = bin |> :binary.part(0, 2) |> Utils.little_to_int()
				script
				|> parser(:binary.part(bin, len, byte_size(bin) - len - 2))
				|> push_raw_data(:binary.part(bin, 2, len))
				|> push_op(op)
				
			# PUSHDATA4
			op == 0x4e ->
				len = bin |> :binary.part(0, 4) |> Utils.little_to_int()
				script
				|> parser(:binary.part(bin, len + 4, byte_size(bin) - len - 4))
				|> push_raw_data(:binary.part(bin, 4, len))
				|> push_op(op)
				
			# OPCODE
			true -> 
				script
				|> parser(:binary.part(bin, 0, byte_size(bin)))
				|> push_op(op)
				
		end
	end

	@doc """
		raw_combine directly concatenates two scripts with no checks.
	"""
	@spec raw_combine(t(), t()) :: t()
	def raw_combine(%__MODULE__{items: s1}, %__MODULE__{items: s2}), do: %__MODULE__{items: s1 ++ s2}

	@doc """
		display_script returns a human readable string of the script, with
		op_codes shown by name rather than number. 
	"""
	@spec display_script(t()) :: String.t()
	def display_script(script) do
		" " <> scriptxt = display_script(script, "")
		scriptxt
	end

	defp display_script(%__MODULE__{items: []}, acc), do: acc
	defp display_script(%__MODULE__{items: [item | stack]}, acc) when is_integer(item) do
		if item > 0 and item < 0x4c do
			display_script(%__MODULE__{items: stack}, acc <> " OP_PUSHBYTES_#{item}")
		else
			{:ok, op_atom} = get_op_atom(item)
			upper_op = op_atom |> to_string() |> String.upcase()
			display_script(%__MODULE__{items: stack}, acc <> " " <> upper_op ) 
		end
	end
	defp display_script(%__MODULE__{items: [item | stack]}, acc) when is_binary(item) do
		display_script(%__MODULE__{items: stack}, acc <> " " <> Base.encode16(item, case: :lower) ) 
	end

	# SCRIPT TYPE DETERMINERS

	@doc """
		is_p2pk returns whether a given script is of the p2pk format:
		<33-byte or 65-byte pubkey> OP_CHECKSIG
	"""
	@spec is_p2pk(t()) :: boolean
	def is_p2pk(script) do
		try do
			{:ok, len, script} = pop(script)
			{:ok, pubkey, script} = pop(script)
			{:ok, 0xac, script} = pop(script)
				
			len in [33,65] and byte_size(pubkey) in [33,65] and empty?(script)
		rescue 
			_ in MatchError -> false
		end
	end

	@doc """
		is_p2pkh returns whether a given script is of the p2pkh format:
		OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
	"""
	@spec is_p2pkh(t()) :: boolean
	def is_p2pkh(script) do
		try do
			{:ok, 0x76, script} = pop(script)
			{:ok, 0xa9, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			{:ok, 0x88, script} = pop(script)
			{:ok, 0xac, script} = pop(script)
			empty?(script)
		rescue 
			_ in MatchError -> false
		end
	end

	@doc """
		is_p2sh returns whether a given script is of the p2sh format:
		OP_HASH160 OP_PUSHBYTES_20 <20-byte hash> OP_EQUAL
	"""
	@spec is_p2sh(t()) :: boolean
	def is_p2sh(script) do
		try do
			{:ok, 0xa9, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			{:ok, 0x87, script} = pop(script)
			empty?(script)
		rescue 
			_ in MatchError -> false
		end
	end

	@doc """
		is_p2wpkh returns whether a given script is of the p2wpkh format:
		OP_0 OP_PUSHBYTES_20 <20-byte hash>
	"""
	@spec is_p2wpkh(t()) :: boolean
	def is_p2wpkh(script) do
		try do
			{:ok, 0x00, script} = pop(script)
			{:ok, 0x14, script} = pop(script)
			{:ok, <<_::binary-size(20)>>, script} = pop(script)
			empty?(script)
		rescue 
			_ in MatchError -> false
		end
		
	end

	@doc """
		is_p2wsh returns whether a given script is of the p2wsh format:
		OP_0 OP_PUSHBYTES_32 <32-byte hash>
	"""
	@spec is_p2wsh(t()) :: boolean
	def is_p2wsh(script) do
		try do
			{:ok, 0x00, script} = pop(script)
			{:ok, 0x20, script} = pop(script)
			{:ok, <<_::binary-size(32)>>, script} = pop(script)
			empty?(script)
		rescue 
			_ in MatchError -> false
		end
	end

	@doc """
		is_p2tr returns whether a given script is of the p2tr format:
		OP_1 OP_PUSHBYTES_32 <32-byte hash>
	"""
	@spec is_p2tr(t()) :: boolean
	def is_p2tr(script) do
		try do
			# from bip340 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
			{:ok, 0x01, script} = pop(script)
			{:ok, 0x20, script} = pop(script)
			{:ok, <<_::binary-size(32)>>, script} = pop(script)
			empty?(script)
		rescue 
			_ in MatchError -> false
		end
	end

	@doc """
		get_script_type determines the type of a script based on its elements
		returns :non_standard if no type matches
	"""
	@spec get_script_type(t()) :: script_type
	def get_script_type(script = %__MODULE__{}) do
		cond do

			is_p2pkh(script) -> :p2pkh
			is_p2wpkh(script) -> :p2wpkh
			is_p2sh(script) -> :p2sh
			is_p2pk(script) -> :p2pk
			is_p2wsh(script) -> :p2wsh
			is_p2tr(script) -> :p2tr
			true -> :non_standard
		end
	end

	# CREATE COMMON SCRIPTS

	@doc """
		create_p2pk creates a p2pk script using the passed public key
	"""
	@spec create_p2pkh(binary) :: t()
	def create_p2pk(pk) when is_binary(pk) and byte_size(pk) in [33,65] do
		new()
		|> push_op(0xac)
		|> push_data(pk)
	end
	def create_p2pk(_), do: {:error, "pubkey must be 33 or 65 bytes compressed or uncompressed SEC"}

	@doc """
		create_p2pkh creates a p2pkh script using the passed 20-byte public key hash
	"""
	@spec create_p2pkh(binary) :: t()
	def create_p2pkh(<<pkh::binary-size(20)>>) do
		new()
		|> push_op(0xac)
		|> push_op(0x88)
		|> push_data(pkh)
		|> push_op(0xa9)
		|> push_op(0x76)
	end
	def create_p2pkh(_), do: {:error, "pubkey hash must be a 20-byte hash"}

	@doc """
		create_p2sh creates a p2sh script using the passed 20-byte public key hash
	"""
	@spec create_p2sh(binary) :: t()
	def create_p2sh(<<sh::binary-size(20)>>) do
		new()
		|> push_op(0x87)
		|> push_data(sh)
		|> push_op(0xa9)
	end
	def create_p2sh(_), do: {:error, "script hash must be a 20-byte hash"}

	@doc """
		create_witness_script creates any witness script from a witness version
		and witness program. It performs no validity checks. 
	"""
	@spec create_witness_script(non_neg_integer(), binary) :: t()
	def create_witness_script(witver, witness_program) do
		new()
		|> push_data(witness_program)
		|> push_op(witver)
	end

	@doc """
		create_p2wpkh creates a p2wpkh script using the passed 20-byte public key hash
	"""
	@spec create_p2wpkh(binary) :: t()
	def create_p2wpkh(<<pkh::binary-size(20)>>), do: create_witness_script(0x00, pkh)
	def create_p2wpkh(_), do: {:error, "pubkey hash must be a 20-byte hash"}

	@doc """
		create_p2wsh creates a p2wsh script using the passed 32-byte script hash
	"""
	@spec create_p2wsh(binary) :: t()
	def create_p2wsh(<<sh::binary-size(32)>>), do: create_witness_script(0x00, sh)
	def create_p2wsh(_), do: {:error, "script hash must be a 32-byte hash"}

	@doc """
		create_p2tr creates a p2tr script using the passed 32-byte public key
	"""
	@spec create_p2tr(binary) :: t()
	def create_p2tr(<<pk::binary-size(32)>>), do: create_witness_script(0x01, pk)
	def create_p2tr(_), do: {:error, "public key must be 32-bytes"}

	@doc """
		create_p2sh_p2wpkh creates a p2wsh script using the passed 20-byte public key hash
	"""
	@spec create_p2sh_p2wpkh(binary) :: t()
	def create_p2sh_p2wpkh(<<pkh::binary-size(20)>>) do
		pkh
		|> create_p2wpkh()
		|> serialize_script()
		|> Utils.hash160()
		|> create_p2sh()
	end
	def create_p2sh_p2wpkh(_), do: {:error, "public key hash must be 20-bytes"}

	# CREATE SCRIPTS FROM PUBKEYS

	def public_key_hash(p = %Point{}) do
		p
		|> Point.sec()
		|> Utils.hash160()
	end

	@doc """
		public_key_to_p2pkh creates a p2pkh script from a public key. 
		All public keys are compressed.
	"""
	@spec public_key_to_p2pkh(Point.t()) :: t()
	def public_key_to_p2pkh(p = %Point{}) do
		p
		|> public_key_hash()
		|> create_p2pkh()
	end

	@doc """
		public_key_to_p2wpkh creates a p2wpkh script from a public key. 
		All public keys are compressed.
	"""
	@spec public_key_to_p2wpkh(Point.t()) :: t()
	def public_key_to_p2wpkh(p = %Point{}) do
		p
		|> public_key_hash()
		|> create_p2wpkh()
	end

	@doc """
		public_key_to_p2sh_p2wpkh creates a p2sh-p2wpkh script from a public key. 
		All public keys are compressed.
	"""
	@spec public_key_to_p2sh_p2wpkh(Point.t()) :: t()
	def public_key_to_p2sh_p2wpkh(p = %Point{}) do
		p
		|> public_key_hash()
		|> create_p2sh_p2wpkh()
	end

	# ADDRESS CREATION & DECODING



	# @spec to_address(t(), Bitcoinex.Network.network_name())
	# def to_address(script = %__MODULE__{}, network) do
	# 	cond do
	# 		is_p2pkh(script) -> 


	# 	end
	# end

	# def to_address(script = %__MODULE__{}, network) do
	# 	{:ok, head, script} = pop(script)
	# 	try do
	# 		case head do
	# 			# segwit 0
	# 			0x00 ->
	# 				{:ok, len, script} = pop(script)
	# 				{:ok, <<res::binary-size(len)>>, script} = pop(script)
	# 				if len == 20 do
	# 					Bech32.encode("bc1", [0, res], :bech32, )
	# 			# segwit 1 (taproot)
	# 			0x01 -> 
	# 				{:ok, 32, script} = pop(script)
	# 				{:ok, <<res::binary-size(32)>>, script} = pop(script)
	# 				res
	# 			# p2sh
	# 			0xa9 -> 
	# 				{:ok, 0x14, script} = pop(script)
	# 				{:ok, <<res::binary-size(0x14)>>, script} = pop(script)
	# 				res
	# 			# p2pkh 
	# 			0x76 -> 
	# 				{:ok, 0xa9, script} = pop(script)
	# 				{:ok, 0x14, script} = pop(script)
	# 				{:ok, <<res::binary-size(0x14)>>, script} = pop(script)
	# 				res
	# 		end
	# 	end
	# end

end
