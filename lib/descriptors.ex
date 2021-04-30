defmodule Bitcoinex.Descriptors do

	alias Bitcoinex.{ExtendedKey, Secp256k1.PrivateKey, Secp256k1.Point}
	
	defstruct Bitcoinex.Descriptors.DScript do

		@type dscript_type :: :p2pkh | :p2sh | :p2wpkh | :p2wsh | :p2pk | :combo | :multi | :sortedmulti | :addr | :raw
		@dscript_types ~w(p2pkh p2sh p2wpkh p2wsh p2pk combo multi sortedmulti addr raw)a

		@type t :: %__MODULE__{
			script_type: dscript_type,
			data: t() | DKey.t() | list | binary
		}

		@enforce_keys [
			:script_type,
			:data
		]

	end

	defstruct Bitcoinex.Descriptors.DKey do

		@type key_type :: ExtendedKey.t() | PrivateKey.t() | Point.t()

		@type t :: %__MODULE__{
			fingerprint: binary | nil
			derivation_path: ExtendedKey.DerivationPath.t() | nil
			key: key_type
		}

		@enforce_keys [
			:key
		]

	end

	defstruct Bitcoinex.Descriptors.DAddress do

		@type t :: %__MODULE__{
			:addr
		}

		@enforce_keys [
			:addr
		]

	end

end