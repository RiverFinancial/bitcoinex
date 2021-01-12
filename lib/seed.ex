defmodule Bitcoinex.Seed do
	@moduledoc """
	Contains functionality for BIP32 seeds.
  """
	@strengths [128, 160, 192, 224, 256]
	@languages [:english, :french, :italian, :chinese_simplified, :chinese_traditional, :japanese, :korean, :spanish]

	defstruct [
		:bits,
		:strength
	]

	def valid_len(bits) do
		bits_len = byte_size(bits)
		entropy_len = bits_len * 8 - div(bits_len, 33)
		entropy_len in @strengths
	end


	@spec checksum(binary) :: boolean
	defp checksum(bits) do
		byte_size(bits) * 8
	end


end
