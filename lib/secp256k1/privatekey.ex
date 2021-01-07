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
	@spec wif(t(), Bitcoinex.Network.network_name()) :: String.t()
	def wif(%__MODULE__{s: s}, network_name) do
		:binary.encode_unsigned(s)
		|> Point.pad()
		|> wif_prefix(network_name)
		|> compressed_suffix()
		|> Base58.encode()
	end

	defp wif_prefix(binary, :mainnet) do
		<<0x80>> <> binary
	end

	defp wif_prefix(binary, :testnet) do
		<<0xef>> <> binary
	end

	defp compressed_suffix(binary) do
		binary <> <<0x01>>
	end

	@doc """
	deterministic_k deterministicallly generates a k value from a sighash z and privkey 
	"""
	@spec deterministic_k(integer, integer) :: integer
	def deterministic_k(%__MODULE__{s: s}, z) do
		k = :binary.list_to_bin(List.duplicate(<<0x00>>, 32))
		v = :binary.list_to_bin(List.duplicate(<<0x01>>, 32))
		n = Params.curve().n
		unless z <= n do
			z = z - n
		end
		# if z > n, do: z = z - n
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

	def test_K(privkey, z) do
		deterministic_k(privkey, z)
	end

	#@spec sign(t(), integer) :: %Signature
	def sign(privkey, z) do
		k = deterministic_k(privkey, z)
		n = Params.curve().n
		sig_r = to_point(k).x
		inv_k = Math.inv(k.s, n)
		#IO.puts(inv_k)
		IO.puts((z + sig_r * privkey.s ))
		IO.puts(Math.modulo(inv_k, n))
		sig_s = Math.modulo((z + sig_r * privkey.s ) * inv_k, n)
		IO.puts(sig_s)
		if sig_s > n/2 do
			%Signature{r: sig_r, s: n - sig_s}
		else
			%Signature{r: sig_r, s: sig_s}
		end
	end

end