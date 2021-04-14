defmodule Bitcoinex.ExtendedKey do
  @moduledoc """
  	Contains an an extended key as documented in BIP 32.
  """
  alias Bitcoinex.Secp256k1.{Params, Point, PrivateKey, Math}
  alias Bitcoinex.Base58

  defmodule DerivationPath do
    @moduledoc """
    Contains a list of integers representing a bip32 derivation path
    """

    @type t :: %__MODULE__{
            p: list
          }

    @enforce_keys [
      :p
    ]
    defstruct [:p]

    @softcap Math.pow(2, 31)
    @hardcap @softcap * @softcap

    @spec path_to_string(t()) :: String.t()
    def path_to_string(%__MODULE__{p: path}), do: tpath_to_string(path, "")

    defp tpath_to_string([], path_acc), do: path_acc
    defp tpath_to_string(["m" | rest], path_acc), do: tpath_to_string(rest, "m/" <> path_acc)

    defp tpath_to_string([l | rest], path_acc) do
      cond do
        l >= @hardcap ->
          {:error, "index cannot be greater than 2^32-1"}

        l < 0 ->
          {:error, "index cannot be negative"}

        # hardened
        l >= @softcap ->
          tpath_to_string(
            rest,
            path_acc <>
              (l
               |> Math.modulo(@softcap)
               |> Integer.to_string()
               |> Kernel.<>("'/"))
          )

        # unhardened
        true ->
          tpath_to_string(rest, path_acc <> Integer.to_string(l) <> "/")
      end
    end

    @spec string_to_path(String.t()) :: t()
    def string_to_path(pathstr), do: %__MODULE__{p: tstring_to_path(String.split(pathstr, "/"))}

    defp tstring_to_path([]), do: []
    defp tstring_to_path([""]), do: []
    defp tstring_to_path(["m" | rest]), do: tstring_to_path(rest)
    defp tstring_to_path([this | rest]), do: [str_to_level(this) | tstring_to_path(rest)]

    defp str_to_level(level) do
      [num | tick] = String.split(level, ["'", "h"])
      nnum = String.to_integer(num)

      if nnum >= @softcap or nnum < 0 do
        raise(ArgumentError, message: "invalid derivation path")
      else
        harden(nnum, tick)
      end
    end

    defp harden(num, [""]), do: num + @softcap
    defp harden(num, []), do: num
    def add(%__MODULE__{p: path1}, %__MODULE__{p: path2}), do: %__MODULE__{p: path1 ++ path2}
  end

  @type t :: %__MODULE__{
          prefix: binary,
          depth: binary,
          parent: binary,
          child_num: binary,
          chaincode: binary,
          key: binary,
          checksum: binary
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

  @softcap Math.pow(2, 31)
  @hardcap @softcap * @softcap

  # Single Sig
  # xpub
  @xpub_pfx <<0x04, 0x88, 0xB2, 0x1E>>
  # xprv
  @xprv_pfx <<0x04, 0x88, 0xAD, 0xE4>>
  # tpub
  @tpub_pfx <<0x04, 0x35, 0x87, 0xCF>>
  # tprv
  @tprv_pfx <<0x04, 0x35, 0x83, 0x94>>
  # ypub
  @ypub_pfx <<0x04, 0x9D, 0x7C, 0xB2>>
  # yprv
  @yprv_pfx <<0x04, 0x9D, 0x78, 0x78>>
  # upub
  @upub_pfx <<0x04, 0x4A, 0x52, 0x62>>
  # uprv
  @uprv_pfx <<0x04, 0x4A, 0x4E, 0x28>>
  # zpub
  @zpub_pfx <<0x04, 0xB2, 0x47, 0x46>>
  # zprv
  @zprv_pfx <<0x04, 0xB2, 0x43, 0x0C>>
  # vpub
  @vpub_pfx <<0x04, 0x5F, 0x1C, 0xF6>>
  # vprv
  @vprv_pfx <<0x04, 0x5F, 0x18, 0xBC>>
  # Multisig (no BIP or derivation path)
  # @y_pub_pfx <<0x02,0x95,0xb4,0x3f>> #Ypub
  # @y_prv_pfx <<0x02,0x95,0xb0,0x05>> #Yprv
  # @z_pub_pfx <<0x02,0xaa,0x7e,0xd3>> #Zpub
  # @z_prv_pfx <<0x02,0xaa,0x7a,0x99>> #Zprv

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

  defp prv_to_pub_prefix(prv_pfx) do
    case prv_pfx do
      @xprv_pfx -> @xpub_pfx
      @tprv_pfx -> @tpub_pfx
      @yprv_pfx -> @ypub_pfx
      @uprv_pfx -> @upub_pfx
      @zprv_pfx -> @zpub_pfx
      @vprv_pfx -> @vpub_pfx
    end
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

  @spec network_from_prefix(binary) :: atom
  def network_from_prefix(prefix) do
    if prefix in mainnet_prefixes() do
      :mainnet
    else
      :testnet
    end
  end

  @spec script_type_from_prefix(binary) :: atom
  def script_type_from_prefix(prefix) do
    cond do
      prefix in bip44() -> :p2pkh
      # p2sh or p2sh_p2wpkh? 
      prefix in bip49() -> :p2sh_p2wpkh
      prefix in bip84() -> :p2wpkh
    end
  end

  @doc """
    parse_extended_key takes binary or string representation 
    of an extended key and parses it to an extended key object
  """
  @spec parse_extended_key(binary | String.t()) :: t()
  def parse_extended_key(
        <<prefix::binary-size(4), depth::binary-size(1), parent::binary-size(4),
          child_num::binary-size(4), chaincode::binary-size(32), key::binary-size(33),
          checksum::binary-size(4)>>
      ) do
    if prefix not in all_prefixes() do
      {:error, "invalid prefix"}
    else
      unless Base58.validate_checksum(prefix <> depth <> parent <> child_num <> chaincode <> key) do
        {:error, "invalid checksum"}
      else
        %__MODULE__{
          prefix: prefix,
          depth: depth,
          parent: parent,
          child_num: child_num,
          chaincode: chaincode,
          key: key,
          checksum: checksum
        }
      end
    end
  end

  # parse from string
  def parse_extended_key(xkey) do
    case Base58.decode(xkey) do
      {:error, _} ->
        {:error, "error parsing key"}

      {:ok, xkey} ->
        xkey
        |> Base58.append_checksum()
        |> parse_extended_key()
    end
  end

  @doc """
    serialize_extended_key takes an extended key
    and returns the binary
  """
  @spec serialize_extended_key(t()) :: binary
  def serialize_extended_key(xkey) do
    (xkey.prefix <> xkey.depth <> xkey.parent <> xkey.child_num <> xkey.chaincode <> xkey.key)
    |> Base58.append_checksum()
  end

  @doc """
    display returns the extended key as a string
  """
  @spec display_extended_key(t()) :: String.t()
  def display_extended_key(xkey) do
    xkey
    |> serialize_extended_key()
    |> Base58.encode_base()
  end

  @doc """
    to_extended_public_key takes an extended private key
    and returns an extended public key
  """
  @spec to_extended_public_key(t()) :: t()
  def to_extended_public_key(xprv) do
    if xprv.prefix in prv_prefixes() do
      privkey = %PrivateKey{d: :binary.decode_unsigned(xprv.key, :big)}

      pubkey =
        PrivateKey.to_point(privkey)
        |> Point.sec()

      prv_to_pub_prefix(xprv.prefix)
      |> Kernel.<>(xprv.depth)
      |> Kernel.<>(xprv.parent)
      |> Kernel.<>(xprv.child_num)
      |> Kernel.<>(xprv.chaincode)
      |> Kernel.<>(pubkey)
      |> Base58.append_checksum()
      |> parse_extended_key()
    else
      # it is an xpub already
      xprv
    end
  end

  @doc """
    to_private_key takes an extended private key
    and returns the contained private key.
  """
  @spec to_private_key(t()) :: PrivateKey.t()
  def to_private_key(xprv) do
    if xprv.prefix not in prv_prefixes() do
      {:error, "key is not a extended private key."}
    else
      secret = :binary.decode_unsigned(xprv.key, :big)
      %PrivateKey{d: secret}
    end
  end

  @doc """
    to_public_key takes an extended key xkey and 
    returns the public key.
  """
  @spec to_public_key(t()) :: Point.t()
  def to_public_key(xkey) do
    if xkey.prefix in prv_prefixes() do
      xkey
      |> to_private_key()
      |> PrivateKey.to_point()
    else
      xkey.key
      |> Point.parse_public_key()
    end
  end

  @doc """
    derive_child uses a public or private key xkey to
    derive the public or private key at index idx. 
    public key -> public child
    private key -> private child
  """
  @spec derive_child_key(t(), non_neg_integer) :: t()
  def derive_child_key(xkey, idx) do
    if xkey.prefix in prv_prefixes() do
      derive_private_child(xkey, idx)
    else
      derive_public_child(xkey, idx)
    end
  end

  @doc """
    derive_public_child uses a public or private key xkey to
    derive the public key at index idx
  """
  @spec derive_public_child(t(), non_neg_integer) :: t()
  def derive_public_child(xkey, idx) do
    if xkey.prefix in prv_prefixes() do
      xkey
      |> derive_private_child(idx)
      |> to_extended_public_key()
    else
      if idx > @softcap do
        {:error, "xpub cannot derive hardened child"}
      else
        child_depth = incr(xkey.depth)

        i =
          idx
          |> :binary.encode_unsigned()
          |> Bitcoinex.Utils.pad(4, :leading)

        fingerprint =
          xkey.key
          |> Bitcoinex.Utils.hash160()
          |> :binary.part(0, 4)

        ent = get_pub_child_entropy(xkey, idx)
        child_chaincode = :binary.part(ent, byte_size(ent), -32)

        key_secret =
          ent
          |> :binary.part(0, 32)
          |> :binary.decode_unsigned()

        if key_secret >= Params.curve().n do
          {:error, "invalid key derived. Bad luck!"}
        else
          parent_pubkey = Point.parse_public_key(xkey.key)

          pubkey =
            %PrivateKey{d: key_secret}
            |> PrivateKey.to_point()
            |> Math.add(parent_pubkey)

          # TODO How to check if pubkey is not infinity?
          (xkey.prefix <> child_depth <> fingerprint <> i <> child_chaincode <> Point.sec(pubkey))
          |> Base58.append_checksum()
          |> parse_extended_key()
        end
      end
    end
  end

  @doc """
    derive_private_child uses a private key xkey to 
    derive the private key at index idx 
  """
  @spec derive_private_child(t(), non_neg_integer) :: t()
  def derive_private_child(xkey, idx) do
    if xkey.prefix not in prv_prefixes() do
      {:error, "public key cannot derive private child"}
    else
      child_depth = incr(xkey.depth)

      i =
        idx
        |> :binary.encode_unsigned()
        |> Bitcoinex.Utils.pad(4, :leading)

      key_secret =
        xkey.key
        |> :binary.decode_unsigned()

      fingerprint =
        %PrivateKey{d: key_secret}
        |> PrivateKey.to_point()
        |> Point.sec()
        |> Bitcoinex.Utils.hash160()
        |> :binary.part(0, 4)

      ent = get_prv_child_entropy(xkey, idx)
      child_chaincode = :binary.part(ent, byte_size(ent), -32)

      child_key =
        ent
        |> :binary.part(0, 32)
        |> :binary.decode_unsigned()
        |> Kernel.+(key_secret)
        |> Bitcoinex.Secp256k1.Math.modulo(Params.curve().n)
        |> :binary.encode_unsigned()

      (xkey.prefix <> child_depth <> fingerprint <> i <> child_chaincode <> <<0>> <> child_key)
      |> Base58.append_checksum()
      |> parse_extended_key()
    end
  end

  # increment byte by 1
  defp incr(byte) do
    byte
    |> :binary.decode_unsigned()
    |> Kernel.+(1)
    |> :binary.encode_unsigned()
  end

  # BIP32 spec
  defp get_prv_child_entropy(xprv, idx) do
    if idx > @hardcap or idx < 0 do
      {:error, "idx must be [0,2**32-1]"}
    else
      i =
        idx
        |> :binary.encode_unsigned()
        |> Bitcoinex.Utils.pad(4, :leading)

      if idx >= @softcap do
        # hardened child from priv key
        :crypto.hmac(:sha512, xprv.chaincode, xprv.key <> i)
      else
        # unhardened child from privkey
        pubkey =
          %PrivateKey{d: :binary.decode_unsigned(xprv.key)}
          |> PrivateKey.to_point()
          |> Point.sec()

        :crypto.hmac(:sha512, xprv.chaincode, pubkey <> i)
      end
    end
  end

  defp get_pub_child_entropy(xpub, idx) do
    if idx > @softcap or idx < 0 do
      {:error, "idx must be [0, 2**31-1]"}
    else
      i =
        idx
        |> :binary.encode_unsigned()
        |> Bitcoinex.Utils.pad(4, :leading)

      :crypto.hmac(:sha512, xpub.chaincode, xpub.key <> i)
    end
  end

  @doc """
    derive_extended_key uses an extended xkey and a derivation 
    path to derive the extended key at that path
  """
  @spec derive_extended_key(t(), DerivationPath.t()) :: t()
  def derive_extended_key(xkey, %DerivationPath{p: path}), do: rderive_extended_key(xkey, path)

  defp rderive_extended_key(xkey, []), do: xkey

  defp rderive_extended_key(xkey, [p | rest]),
    do: derive_child_key(xkey, p) |> rderive_extended_key(rest)
end
