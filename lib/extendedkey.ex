defmodule Bitcoinex.ExtendedKey do
  @moduledoc """
  	Contains an an extended key as documented in BIP 32.
  """
  alias Bitcoinex.Secp256k1.{Params, Point, PrivateKey, Math}
  alias Bitcoinex.Base58

  use Bitwise, only_operators: true

  defmodule DerivationPath do
    @moduledoc """
    Contains a list of integers (or the :any atom) representing a bip32 derivation path.
    The :any atom represents a wildcard in the derivation path. DerivationPath structs can
    be used by ExtendedKey.derive_extended_key to derive a child key at the given path.
    """

    @min_non_hardened_child_num 0
    # 2^31 - 1
    @max_non_hardened_child_num 0x80000000 - 1
    @min_hardened_child_num 0x80000000
    # 2^32 - 1
    @max_hardened_child_num 0x100000000 - 1

    @type hardened_child_num ::
            unquote(@min_hardened_child_num)..unquote(@max_hardened_child_num)
    @type non_hardened_child_num ::
            unquote(@min_non_hardened_child_num)..unquote(@max_non_hardened_child_num)

    @type child_num :: hardened_child_num | non_hardened_child_num

    @type t :: %__MODULE__{
            child_nums: list(child_num)
          }

    @enforce_keys [
      :child_nums
    ]
    defstruct [:child_nums]

    def max_non_hardened_child_num(), do: @max_non_hardened_child_num
    def max_hardened_child_num(), do: @max_hardened_child_num

    @spec path_to_string(t()) :: String.t()
    def path_to_string(%__MODULE__{child_nums: path}), do: tpath_to_string(path, "")

    defp tpath_to_string([], path_acc), do: path_acc
    defp tpath_to_string(["m" | rest], path_acc), do: tpath_to_string(rest, "m/" <> path_acc)

    defp tpath_to_string([l | rest], path_acc) do
      cond do
        l == :any ->
          tpath_to_string(rest, path_acc <> "*/")

        l > @max_hardened_child_num ->
          {:error, "index cannot be greater than #{@max_hardened_child_num}"}

        l < @min_non_hardened_child_num ->
          {:error, "index cannot be less than #{@min_non_hardened_child_num}"}

        # hardened
        l >= @min_hardened_child_num ->
          tpath_to_string(
            rest,
            path_acc <>
              (l
               |> Math.modulo(@min_hardened_child_num)
               |> Integer.to_string()
               |> Kernel.<>("'/"))
          )

        # unhardened
        true ->
          tpath_to_string(rest, path_acc <> Integer.to_string(l) <> "/")
      end
    end

    @spec string_to_path(String.t()) :: t()
    def string_to_path(pathstr) do
      try do
        %__MODULE__{child_nums: tstring_to_path(String.split(pathstr, "/"))}
      rescue
        e in ArgumentError -> {:error, e.message}
      end
    end

    defp tstring_to_path(path_list) do
      case path_list do
        [] -> []
        [""] -> []
        ["m" | rest] -> tstring_to_path(rest)
        ["*" | rest] -> [:any | tstring_to_path(rest)]
        [i | rest] -> [str_to_level(i) | tstring_to_path(rest)]
      end
    end

    defp str_to_level(level) do
      {num, is_hardened} =
        case String.split(level, ["'", "h"]) do
          [num] ->
            {num, false}

          [num, ""] ->
            {num, true}
        end

      nnum = String.to_integer(num)

      if nnum in @min_non_hardened_child_num..@max_non_hardened_child_num do
        if is_hardened do
          nnum + @min_hardened_child_num
        else
          nnum
        end
      else
        raise(ArgumentError, message: "invalid derivation path")
      end
    end

    def add(%__MODULE__{child_nums: path1}, %__MODULE__{child_nums: path2}),
      do: %__MODULE__{child_nums: path1 ++ path2}
  end

  @type t :: %__MODULE__{
          prefix: binary,
          depth: binary,
          parent_fingerprint: binary,
          child_num: binary,
          chaincode: binary,
          key: binary
        }

  @enforce_keys [
    :prefix,
    :depth,
    :parent_fingerprint,
    :child_num,
    :chaincode,
    :key
  ]

  defstruct [
    :prefix,
    :depth,
    :parent_fingerprint,
    :child_num,
    :chaincode,
    :key
  ]

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
  # Multisig (no BIP or derivation path, from SLIP-132)
  # @y_pub_pfx <<0x02,0x95,0xb4,0x3f>> #Ypub
  # @y_prv_pfx <<0x02,0x95,0xb0,0x05>> #Yprv
  # @z_pub_pfx <<0x02,0xaa,0x7e,0xd3>> #Zpub
  # @z_prv_pfx <<0x02,0xaa,0x7a,0x99>> #Zprv
  @prv_prefixes [
    @xprv_pfx,
    @tprv_pfx,
    @yprv_pfx,
    @uprv_pfx,
    @zprv_pfx,
    @vprv_pfx
  ]

  @pub_prefixes [
    @xpub_pfx,
    @tpub_pfx,
    @ypub_pfx,
    @upub_pfx,
    @zpub_pfx,
    @vpub_pfx
  ]

  @all_prefixes @prv_prefixes ++ @pub_prefixes

  defp pfx_atom_to_bin(pfx) do
    case pfx do
      :xpub -> @xpub_pfx
      :xprv -> @xprv_pfx
      :tpub -> @tpub_pfx
      :tprv -> @tprv_pfx
      :ypub -> @ypub_pfx
      :yprv -> @yprv_pfx
      :upub -> @upub_pfx
      :uprv -> @uprv_pfx
      :zpub -> @zpub_pfx
      :zprv -> @zprv_pfx
      :vpub -> @vpub_pfx
      :vprv -> @vprv_pfx
    end
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
    if prefix in mainnet_prefixes(), do: :mainnet, else: :testnet
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

  @spec switch_prefix(t(), atom) :: t() | {:error, String.t()}
  def switch_prefix(xkey = %__MODULE__{prefix: pfx}, new_pfx) do
    new_pfx_bin = pfx_atom_to_bin(new_pfx)
    cond do
      new_pfx_bin in @prv_prefixes and pfx in @prv_prefixes ->
        %__MODULE__{xkey | prefix: new_pfx_bin}

      new_pfx_bin in @pub_prefixes and pfx in @pub_prefixes ->
        %__MODULE__{xkey | prefix: new_pfx_bin}

      true ->
        {:error, "switching between public and private prefixes will result in a useless key"}
    end
  end

  @doc """
    parse_extended_key takes binary or string representation
    of an extended key and parses it to an extended key object
  """
  @spec parse_extended_key(binary | String.t()) :: t()
  def parse_extended_key(
        <<prefix::binary-size(4), depth::binary-size(1), parent_fingerprint::binary-size(4),
          child_num::binary-size(4), chaincode::binary-size(32), key::binary-size(33),
          _checksum::binary-size(4)>> = xkey
      ) do
    cond do
      prefix not in @all_prefixes ->
        {:error, "invalid prefix"}

      # BIP 32 instructs to check that public key is valid upon import
      prefix not in @prv_prefixes and not check_point(key) ->
        {:error, "invalid public key"}

      true ->
        case Base58.validate_checksum(xkey) do
          {:error, msg} ->
            {:error, msg}

          _ ->
            %__MODULE__{
              prefix: prefix,
              depth: depth,
              parent_fingerprint: parent_fingerprint,
              child_num: child_num,
              chaincode: chaincode,
              key: key
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

  defp check_point(key) do
    key
    |> Point.parse_public_key()
    |> Bitcoinex.Secp256k1.verify_point()
  end

  @doc """
    serialize_extended_key takes an extended key
    and returns the binary
  """
  @spec serialize_extended_key(t()) :: binary
  def serialize_extended_key(xkey) do
    (xkey.prefix <>
       xkey.depth <> xkey.parent_fingerprint <> xkey.child_num <> xkey.chaincode <> xkey.key)
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
    seed_to_master_private_key transforms a bip32 seed
    into a master extended private key
  """
  @spec seed_to_master_private_key(binary, atom) :: t()
  def seed_to_master_private_key(<<seed::binary>>, pfx \\ :xprv) do
    prefix = pfx_atom_to_bin(pfx)

    if prefix in @prv_prefixes do
      <<key::binary-size(32), chaincode::binary-size(32)>> =
        :crypto.hmac(:sha512, "Bitcoin seed", seed)

      depth_fingerprint_childnum = <<0, 0, 0, 0, 0, 0, 0, 0, 0>>

      (prefix <> depth_fingerprint_childnum <> chaincode <> <<0>> <> key)
      |> Base58.append_checksum()
      |> parse_extended_key()
    else
      {:error, "invalid extended private key prefix"}
    end
  end

  @doc """
    to_extended_public_key takes an extended private key
    and returns an extended public key
  """
  @spec to_extended_public_key(t()) :: t()
  def to_extended_public_key(xprv) do
    if xprv.prefix in @prv_prefixes do
      privkey = %PrivateKey{d: :binary.decode_unsigned(xprv.key, :big)}

      pubkey =
        privkey
        |> PrivateKey.to_point()
        |> Point.sec()

      xprv.prefix
      |> prv_to_pub_prefix()
      |> Kernel.<>(xprv.depth)
      |> Kernel.<>(xprv.parent_fingerprint)
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
    if xprv.prefix in @prv_prefixes do
      secret = :binary.decode_unsigned(xprv.key, :big)
      %PrivateKey{d: secret}
    else
      {:error, "key is not a extended private key."}
    end
  end

  @doc """
    to_public_key takes an extended key xkey and
    returns the public key.
  """
  @spec to_public_key(t()) :: Point.t()
  def to_public_key(xkey) do
    if xkey.prefix in @prv_prefixes do
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
    if xkey.prefix in @prv_prefixes do
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
    cond do
      xkey.prefix in @prv_prefixes ->
        xkey
        |> derive_private_child(idx)
        |> to_extended_public_key()

      idx > DerivationPath.max_non_hardened_child_num() or idx < 0 ->
        {:error, "idx must be in 0..2**31-1"}

      true ->
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

          if Point.is_inf(pubkey) do
            {:error, "pubkey is point at infinity, bad luck!"}
          else
            (xkey.prefix <>
               child_depth <> fingerprint <> i <> child_chaincode <> Point.sec(pubkey))
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
  @spec derive_private_child(t(), non_neg_integer()) :: t()
  def derive_private_child(_, idx) when idx >>> 32 != 0, do: {:error, "idx must be in 0..2**32-1"}

  def derive_private_child(%{prefix: prefix}, _) when prefix not in @prv_prefixes,
    do: {:error, "public key cannot derive private child"}

  def derive_private_child(xkey, idx) do
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

  # increment byte by 1
  defp incr(byte) do
    byte
    |> :binary.decode_unsigned()
    |> Kernel.+(1)
    |> :binary.encode_unsigned()
  end

  # BIP32 spec
  defp get_prv_child_entropy(xprv, idx) do
    i =
      idx
      |> :binary.encode_unsigned()
      |> Bitcoinex.Utils.pad(4, :leading)

    if idx > DerivationPath.max_non_hardened_child_num() do
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

  defp get_pub_child_entropy(xpub, idx) do
    i =
      idx
      |> :binary.encode_unsigned()
      |> Bitcoinex.Utils.pad(4, :leading)

    :crypto.hmac(:sha512, xpub.chaincode, xpub.key <> i)
  end

  @doc """
    derive_extended_key uses an extended xkey and a derivation
    path to derive the extended key at that path
  """
  @spec derive_extended_key(t(), DerivationPath.t()) :: t()
  def derive_extended_key(xkey, %DerivationPath{child_nums: path}),
    do: rderive_extended_key(xkey, path)

  defp rderive_extended_key(xkey, []), do: xkey

  defp rderive_extended_key(xkey, [p | rest]) do
    case p do
      # if asterisk (:any) is in path, return the immediate parent xkey
      :any ->
        xkey

      # otherwise it is an integer, so derive child at that index.
      _ ->
        xkey
        |> derive_child_key(p)
        |> rderive_extended_key(rest)
    end
  end
end
