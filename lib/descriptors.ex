defmodule Bitcoinex.Descriptors do

	alias Bitcoinex.{ExtendedKey, ExtendedKey.DerivationPath Secp256k1.PrivateKey, Secp256k1.Point, Script}

	defstruct Bitcoinex.Descriptors.DKey do

		@type key_type :: ExtendedKey.t() | PrivateKey.t() | Point.t()

		@type t :: %__MODULE__{
			fingerprint: binary
			derivation_path: DerivationPath.t()
			key: key_type
		}

		@enforce_keys [
			:key
		]

		defstruct [
			# default both to empty for easier serialization
			fingerprint: <<>>,
			derivation_path: %DerivationPath{child_nums: []},
			:key
		]

		def serialize_dkey(desc = %__MODULE__{key: %Point{}}) do
			desc.key
			|> Point.sec()
			|> Base.encode16!(case: :lower)
		end
		def serialize_dkey(desc = %__MODULE__{key: %PrivateKey{}}) do
			PrivateKey.wif!(desc.key)
		end
		def serialize_dkey(desc = %__MODULE__{key: %ExtendedKey{}}) do
			fp = Base.encode16(desc.fingerprint)
			{:ok, deriv_path} = DerivationPath.to_string(desc.derivation_path)
		end

		def parse_dkey() do
			cond do
				# if pubkey
				# if privkey 
				# if fingerprint
				# if xkey
			end
		end



	end

	defstruct Bitcoinex.Descriptors do

		@type descriptor_type :: :p2pkh | :p2sh | :p2wpkh | :p2wsh | :p2pk | :combo | :multi | :sortedmulti | :addr | :raw
		@descriptor_types ~w(p2pkh p2sh p2wpkh p2wsh p2pk combo multi sortedmulti addr raw)a

		@type t :: %__MODULE__{
			script_type: descriptor_type,
			m: non_neg_integer() | nil,
			data: t() | DKey.t() | Script.t() | list | binary
		}

		@enforce_keys [
			:script_type,
			:data
		]

		defstruct [
			:script_type,
			:m,
			:data
		]

	end

end



"""
types of descriptors: 

:p2pkh (%DKEY)
:p2sh (%DESCRIPTOR)
:p2wpkh (%DKEY)
:p2wsh (%DESCRIPTOR)
:p2pk (%DKEY)
:combo (%DKEY)
:multi (m, [%DKEY * n])
:sortedmulti (m, [%DKEY * n])
:addr (%SCRIPT)
:raw (%SCRIPT)


"""