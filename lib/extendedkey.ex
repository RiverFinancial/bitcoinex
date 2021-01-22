defmodule Bitcoinex.ExtendedKey do
  @moduledoc """
  	Contains an an extended key as documented in BIP 32.
  """
    alias Bitcoinex.Secp256k1.{Point, PrivateKey}
    
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

    @xpub_pfx <<0x04,0x88,0xb2,0x1e>> #XPUB
    @xprv_pfx <<0x04,0x88,0xad,0xe4>> #XPRV
    @tpub_pfx <<0x04,0x35,0x87,0xcf>> #TPUB
    @tprv_pfx <<0x04,0x35,0x83,0x94>> #TPRV
    @ypub_pfx <<0x04,0x9d,0x7c,0xb2>> #YPUB
    @yprv_pfx <<0x04,0x9d,0x78,0x78>> #YPRV
    @upub_pfx <<0x04,0x4a,0x52,0x62>> #UPUB
    @uprv_pfx <<0x04,0x4a,0x4e,0x28>> #UPRV
    @zpub_pfx <<0x04,0xb2,0x47,0x46>> #ZPUB
    @zprv_pfx <<0x04,0xb2,0x43,0x0c>> #ZPRV
    @vpub_pfx <<0x04,0x5f,0x1c,0xf6>> #VPUB
    @vprv_pfx <<0x04,0x5f,0x18,0xbc>> #VPRV

    defp all_prefixes do
      [
        @xpub_pfx,
        @xprv_pfx,
        @tpub_pfx,
        @tprv_pfx,
        @ypub_pfx,
        @yprv_pfx,
        @upub_pfx,
        @uprv_pfx,
        @zpub_pfx,
        @zprv_pfx,
        @vpub_pfx,
        @vprv_pfx
      ]
    end

    defp bip44 do
      [
        @xpub_pfx,
        @xprv_pfx,
        @tpub_pfx,
        @tprv_pfx
      ]
    end

    defp bip49 do
      [
        @ypub_pfx,
        @yprv_pfx,
        @upub_pfx,
        @uprv_pfx
      ]
    end

    defp bip84 do
      [
        @zpub_pfx,
        @zprv_pfx,
        @vpub_pfx,
        @vprv_pfx
      ]
    end

    defp prv_prefixes do
      [
        @xprv_pfx,
        @tprv_pfx,
        @yprv_pfx,
        @uprv_pfx,
        @zprv_pfx,
        @vprv_pfx
      ]
    end

    defp mainnet_prefixes do
      [
        @xpub_pfx,
        @xprv_pfx,
        @ypub_pfx,
        @yprv_pfx,
        @zpub_pfx,
        @zprv_pfx
      ]
    end

    defp network_from_prefix(prefix) do
      if prefix in mainnet_prefixes() do
        :mainnet
      else
        :testnet
      end
    end

    defp script_type_from_prefix(prefix) do
      cond do
        prefix in bip44 -> :p2pkh
        prefix in bip49 -> :p2sh_p2wpkh # p2sh or p2sh_p2wpkh? 
        prefix in bip84 -> :p2wpkh
      end
    end

    @spec parse_extended_key(binary | String.t()) :: t()
		def parse_extended_key(
			<<prefix::binary-size(4),
				depth::binary-size(1),
				parent::binary-size(4),
				child_num::binary-size(4),
				chaincode::binary-size(32),
				key::binary-size(33),
				chekcsum::binary-size(4)>>
    ) do
      if prefix not in all_prefixes() do
        {:error, "invalid prefix"}
      else 
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

    def parse_extended_key(xkey) do
      xkey 
      |> Base.encode16(case: :lower)
      |> parse_extended_key()
    end
    
    @spec serialize_extended_key(t()) :: binary
    def serialize_extended_key(xkey) do
      xkey.prefix <> xkey.depth <> xkey.parent <> xkey.child_num <> xkey.chaincode <> xkey.key
    end

    @spec display(t()) :: String.t()
    def display(xkey) do
      xkey
      |> serialize_extended_key()
      |> Base58.encode()
    end

    @spec to_private_key(t()) :: PrivateKey.t()
    def to_private_key(xprv) do
      if xprv.prefix not in prv_prefixes() do
        {:error, "key is not a private key."}
      else
        secret = :binary.decode_unsigned(xprv.key, :big)
        PrivateKey{d: secret}
      end
    end

    @spec to_public_key(t()) :: Point.t()
    def to_public_key(xprv) do
      if xprv.prefix in prv_prefixes() do
        xprv
        |> to_private_key()
        |> PrivateKey.to_point()
      else
        xprv.key
        |> Point.parse_public_key()
      end
    end

    @spec derive_child_key(t(), non_neg_integer) :: t()
    def derive_child_key(xkey, idx) do

    end

end