defmodule Bitcoinex.Secp256k1.PrivateKey do
	@moduledoc """
  	Contains an integer used to create a Point and sign.
	"""
	alias Bitcoinex.Secp256k1.{Params, Math, Point, Signature}
	alias Bitcoinex.Base58

	@type t :: %__MODULE__{
					s: integer()
				}

	@enforce_keys [
		:s
	]
	defstruct [:s]

	@doc """
	calculate Point from private key
	"""
	#@spec serialize_private_key(t()) :: %Point
	def to_point(%__MODULE__{s: s}) do
		g = %Point{x: Params.curve().g_x, y: Params.curve().g_y, z: 0}
		Math.multiply(g, s)
	end

	@doc """
  serialize_private_key serializes a private key into hex
	"""
  @spec serialize_private_key(t()) :: String.t()
	def serialize_private_key(%__MODULE__{s: s}) do
		Base.encode16(Point.pad(:binary.encode_unsigned(s)), case: :lower)
	end

	@doc """
	wif returns the base58check encoded private key as a string
	assumes all keys are compressed
	"""
	@spec wif!(t(), Bitcoinex.Network.network_name()) :: String.t()
	def wif!(%__MODULE__{s: s}, network_name) do
		:binary.encode_unsigned(s)
		|> Point.pad()
		|> wif_prefix(network_name)
		|> compressed_suffix()
		|> Base58.encode()
	end

	@doc """
	returns the base58check encoded private key as a string
	assumes all keys are compressed
	"""
	#@spec parse_wif(string) :: %__MODULE__
	def parse_wif(wif_str) do
		{state, bin} = Base58.decode(wif_str)
		case state do
			:error -> {:error, bin}
			:ok -> parse_wif_bin(bin)
		end
	end
	# parse compressed
	def parse_wif_bin(<<prefix::binary-size(1), wif::binary-size(32), 0x01>>) do
		{state, network_name} = wif_prefix(prefix)
		if state == :error do
			{:error, network_name}
		else
			secret = :binary.decode_unsigned(wif)
			{:ok, %__MODULE__{s: secret}, network_name, true}
		end
	end
	# parse uncompressed
	def parse_wif_bin(<<prefix::binary-size(1), wif::binary-size(32)>>) do
		{state, network_name} = wif_prefix(prefix)
		if state == :error do
			{:error, network_name}
		else
			secret = :binary.decode_unsigned(wif)
			{:ok, %__MODULE__{s: secret}, network_name, false}
		end
	end


	defp compressed_suffix(binary), do: binary <> <<0x01>>
	#encoding
	defp wif_prefix(binary, :mainnet), do: <<0x80>> <> binary
	defp wif_prefix(binary, :testnet), do: <<0xef>> <> binary
	# what is the best way to throw an error if an invalid network name is passed?
	#defp wif_prefix(binary, _), do: {:error, "networks must be in [:mainnet, :testnet]"}
	#decoding
	defp wif_prefix(<<0x80>>), do: {:ok, :mainnet}
	defp wif_prefix(<<0xef>>), do: {:ok, :testnet}
	defp wif_prefix(_), do: {:error, "unrecognized network prefix for WIF"}


	@doc """
	deterministic_k deterministicallly generates a k value from a sighash z and privkey 
	"""
	@spec deterministic_k(integer, integer) :: integer
	def deterministic_k(%__MODULE__{s: s}, raw_z) do
		k = :binary.list_to_bin(List.duplicate(<<0x00>>, 32))
		v = :binary.list_to_bin(List.duplicate(<<0x01>>, 32))
		n = Params.curve().n
		z = lower_z(raw_z, n)
		sighash = Point.pad(:binary.encode_unsigned(z))
		secret = Point.pad(:binary.encode_unsigned(s))
		k = :crypto.hmac(:sha256, k, v <> <<0x00>> <> secret <> sighash)
		v = :crypto.hmac(:sha256, k, v)
		k = :crypto.hmac(:sha256, k, v <> <<0x01>> <> secret <> sighash)
		v = :crypto.hmac(:sha256, k, v)
		final_k = find_candidate(k,v,n)
		%__MODULE__{s: final_k}
	end

	defp find_candidate(k, v, n) do
		v = :crypto.hmac(:sha256, k, v)
		candidate = :binary.decode_unsigned(v)
		unless candidate >= 1 and candidate < n do
			k = :crypto.hmac(:sha256, k, v <> <<0x00>>)
			v = :crypto.hmac(:sha256, k, v)
			find_candidate(k, v, n)
		end
		candidate
	end

	defp lower_z(z, n) do
		if z > n, do: z - n, else: z
	end

	#@spec sign(t(), integer) :: %Signature
	def sign(privkey, z) do
		k = deterministic_k(privkey, z)
		n = Params.curve().n
		sig_r = to_point(k).x
		inv_k = Math.inv(k.s, n)
		sig_s = Math.modulo((z + sig_r * privkey.s ) * inv_k, n)
		if sig_s > n/2 do
			%Signature{r: sig_r, s: n - sig_s}
		else
			%Signature{r: sig_r, s: sig_s}
		end
	end

end