defmodule Bitcoinex.Seed do
	@moduledoc """
		Contains functionality for BIP32 seed and extended keys.
  """
	
	
	# @soft_cap 0x80000000
	# @hard_cap 0x100000000
	# @pbkdf2_rounds 0x800
	@strengths [128, 160, 192, 224, 256]
	@wordlist_dir "lib/wordlist/"


	defstruct [
		:bits
	]

	@type t() :: %__MODULE__{
		bits: binary
	}

	@type language :: :english | :french | :italian | :chinese_simplified | :chinese_traditional | :japanese | :korean | :spanish

	defp valid_len(bits) do
		bits_len = byte_size(bits)
		entropy_len = bits_len * 8 - div(bits_len, 33)
		entropy_len in @strengths
	end

	@spec checksum(binary) :: boolean
	def calculate_checksum(bits) do
		strength = byte_size(bits)
		cs_len = div(strength, 32)
		

	end

	@spec get_wordlist(language) :: list
	defp get_wordlist(lang) do
		@wordlist_dir <> to_string(lang)
		|> Kernel.<>(".txt")
		|> File.stream!()
		|> Stream.map(&String.trim/1)
		|> Enum.to_list()
	end

	#@spec to_mnemonic(%__MODULE__.t(), language) :: list(String.t())
	def to_mnemonic(%__MODULE__{bits: bits}, lang) do
		case valid_len(bits) do
			true ->
				wordlist = get_wordlist(lang)
				{:ok, wordnums} = 
					bits
					|> :binary.bin_to_list()
					|> Bitcoinex.Bech32. #convert_bits(8, 11, false)
				Enum.map(wordnums, fn i -> elem(wordlist, i) end)
			false -> {:error, :invalid_bits}
		end
	end

	# for testing only. REMOVE
	def weak_random(strength \\ 132) do
		%__MODULE__{
			bits: :crypto.strong_rand_bytes(div(strength, 8))
		}
	end


end
