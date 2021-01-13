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

	def valid_len(bits) do
		bits_len = byte_size(bits)
		entropy_len = bits_len * 8 - div(bits_len, 33)
		entropy_len in @strengths
	end

	@spec checksum(binary) :: boolean
	def checksum(bits) do
		byte_size(bits) * 8
	end

	@spec get_wordlist(language) :: list
	def get_wordlist(lang) do
		@wordlist_dir <> to_string(lang)
		|> Kernel.<>(".txt")
		|> File.stream!()
		|> Stream.map(&String.trim/1)
		|> Enum.to_list()
	end

	


end
