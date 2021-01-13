defmodule Bitcoinex.ExtendedKey do
  @moduledoc """
  	Contains an an extended key as documented in BIP 32.
	"""
    
    @type t :: %__MODULE__{
        prefix: binary,
        depth: binary,
				parent: binary,
        child_num: binary,
        chaincode: binary,
        key: binary,
        checksum: binary,
    }

    @enforce_keys [
        :prefix,
        :depth,
				:parent,
        :child_num,
        :chaincode,
        :key,
        :checksum
    ]

    defstruct [
        :prefix,
        :depth,
				:parent,
        :child_num,
        :chaincode,
        :key,
        :checksum
    ]

		def parse_extended_key(
			<<prefix::binary-size(4),
				depth::binary-size(1),
				parent::binary-size(4),
				child_num::binary-size(4),
				chaincode::binary-size(32),
				key::binary-size(33),
				chekcsum::binary-size(4)>>
		) do
			%__MODULE__{
				prefix: prefix,
        depth: depth,
				parent: parent,
        child_num: child_num,
        chaincode: chaincode,
        key: key,
        checksum: checksum,
			}
		end
end