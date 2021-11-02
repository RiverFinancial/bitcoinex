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

    def min_hardened_child_num(), do: @min_hardened_child_num
    def max_hardened_child_num(), do: @max_hardened_child_num

    def new(), do: %__MODULE__{child_nums: []}

    @spec serialize(t(), atom) :: {:ok, String.t()} | {:ok, binary} | {:error, String.t()}
    def serialize(dp = %__MODULE__{}, :to_string), do: path_to_string(dp)
    def serialize(dp = %__MODULE__{}, :to_bin), do: to_bin(dp)

    @spec path_to_string(t()) :: {:ok, String.t()} | {:error, String.t()}
    def path_to_string(%__MODULE__{child_nums: path}), do: tto_string(path, "")

    defp tto_string([], path_acc), do: {:ok, path_acc}

    defp tto_string([l | rest], path_acc) do
      cond do
        l == :any ->
          tto_string(rest, path_acc <> "*/")

        l == :anyh ->
          tto_string(rest, path_acc <> "*'/")

        l > @max_hardened_child_num ->
          {:error, "index cannot be greater than #{@max_hardened_child_num}"}

        l < @min_non_hardened_child_num ->
          {:error, "index cannot be less than #{@min_non_hardened_child_num}"}

        # hardened
        l >= @min_hardened_child_num ->
          tto_string(
            rest,
            path_acc <>
              (l
               |> Math.modulo(@min_hardened_child_num)
               |> Integer.to_string()
               |> Kernel.<>("'/"))
          )

        # unhardened
        true ->
          tto_string(rest, path_acc <> Integer.to_string(l) <> "/")
      end
    end

    @spec to_bin(t()) :: {:ok, binary} | {:error, String.t()}
    def to_bin(%__MODULE__{child_nums: child_nums}) do
      try do
        {:ok, tto_bin(child_nums, <<>>)}
      rescue
        e in ArgumentError -> {:error, e.message}
      end
    end

    defp tto_bin([], path_acc), do: path_acc
    defp tto_bin([lvl | rest], path_acc) do
      cond do
        lvl == :any or lvl == :anyh ->
          raise(ArgumentError, message: "Derivation Path with wildcard cannot be encoded to binary.")

        lvl > @max_hardened_child_num ->
          raise(ArgumentError, message: "index cannot be greater than #{@max_hardened_child_num}")

        lvl < @min_non_hardened_child_num ->
          raise(ArgumentError, message: "index cannot be less than #{@min_non_hardened_child_num}")

        true ->
          lvlbin = 
            lvl
            |> :binary.encode_unsigned(:little) 
            |> Bitcoinex.Utils.pad(4, :trailing)
          tto_bin(rest, path_acc <> lvlbin)
      end
    end

    @spec parse(binary, atom) :: {:ok, t()} | {:error, String.t()}
    def parse(dp, :from_bin), do: from_bin(dp)
    def parse(dp, :from_string), do: path_from_string(dp)

    @spec path_from_string(String.t()) :: {:ok, t()} | {:error, String.t()}
    def path_from_string(pathstr) do
      try do
        {:ok, %__MODULE__{child_nums: 
          pathstr
            |> String.split("/")
            |> tfrom_string([])
            |> Enum.reverse()
          }
        }
      rescue
        e in ArgumentError -> {:error, e.message}
      end
    end

    defp tfrom_string(path_list, child_nums) do
      case path_list do
        [] -> child_nums
        [""] -> child_nums
        ["m" | rest] -> 
          if child_nums != [] do
            raise(ArgumentError, message: "m can only be present at the begining of a derivation path.")
          else
             tfrom_string(rest, child_nums)
          end
        ["*" | rest] -> tfrom_string(rest, [:any | child_nums])
        ["*'" | rest] -> tfrom_string(rest, [:anyh | child_nums])
        ["*h" | rest] -> tfrom_string(rest, [:anyh | child_nums])
        [i | rest] -> tfrom_string(rest, [str_to_level(i) | child_nums])
      end
    end

    @spec from_bin(binary) :: {:ok, t()} | {:error, String.t()}
    def from_bin(bin) do 
      try do 
        {:ok, %__MODULE__{child_nums: Enum.reverse(tfrom_bin(bin, []))}}
      rescue
        _e in ArgumentError -> {:error, "invalid binary encoding of derivation path"}
      end
    end
    
    defp tfrom_bin(<<>>, child_nums), do: child_nums
    defp tfrom_bin(<<level::little-unsigned-32, bin::binary>>, child_nums), do: tfrom_bin(bin, [level | child_nums])

    defp str_to_level(level) do
      {num, is_hardened} =
        case String.split(level, ["'", "h"]) do
          [num] ->
            {num, false}

          [num, ""] ->
            {num, true}
        end

      nnum = String.to_integer(num)

      #TODO benchmark and make this two comparisons
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
          key: binary,
          checksum: binary
        }

  @enforce_keys [
    :prefix,
    :depth,
    :parent_fingerprint,
    :child_num,
    :chaincode,
    :key,
    :checksum
  ]

  defstruct [
    :prefix,
    :depth,
    :parent_fingerprint,
    :child_num,
    :chaincode,
    :key,
    :checksum
  ]

  @xpub_pfx <<0x04, 0x88, 0xB2, 0x1E>>
  @xprv_pfx <<0x04, 0x88, 0xAD, 0xE4>>
  @tpub_pfx <<0x04, 0x35, 0x87, 0xCF>>
  @tprv_pfx <<0x04, 0x35, 0x83, 0x94>>

  @prv_prefixes [
    @xprv_pfx,
    @tprv_pfx
  ]

  @pub_prefixes [
    @xpub_pfx,
    @tpub_pfx
  ]

  @all_prefixes @prv_prefixes ++ @pub_prefixes

  defp pfx_atom_to_bin(pfx) do
    case pfx do
      :xpub -> @xpub_pfx
      :xprv -> @xprv_pfx
      :tpub -> @tpub_pfx
      :tprv -> @tprv_pfx
    end
  end

  defp prv_to_pub_prefix(prv_pfx) do
    case prv_pfx do
      @xprv_pfx -> @xpub_pfx
      @tprv_pfx -> @tpub_pfx
    end
  end

  defp mainnet_prefixes do
    [
      @xpub_pfx,
      @xprv_pfx
    ]
  end

  @spec network_from_prefix(binary) :: atom
  defp network_from_prefix(prefix) do
    if prefix in mainnet_prefixes(), do: :mainnet, else: :testnet
  end

  @doc """
    network_from_extended_key returns :testnet or :mainnet 
    depending on the network prefix of the key.
  """
  @spec network_from_extended_key(t()) :: atom
  def network_from_extended_key(%__MODULE__{prefix: prefix}), do: network_from_prefix(prefix)

  # GETTERS

  @spec get_prefix(t()) :: binary
  def get_prefix(%__MODULE__{prefix: prefix}), do: prefix

  @spec get_depth(t()) :: binary
  def get_depth(%__MODULE__{depth: depth}), do: depth

  @spec get_parent_fingerprint(t()) :: binary
  def get_parent_fingerprint(%__MODULE__{parent_fingerprint: pfp}), do: pfp

  @spec get_fingerprint(t()) :: binary
  def get_fingerprint(xkey = %__MODULE__{}) do
    if xkey.prefix in @prv_prefixes do
      {:ok, prvkey} =
        xkey.key
        |> :binary.decode_unsigned()
        |> PrivateKey.new()

      prvkey
      |> PrivateKey.to_point()
      |> Point.sec()
      |> Bitcoinex.Utils.hash160()
      |> :binary.part(0, 4)
    else
      xkey.key
      |> Bitcoinex.Utils.hash160()
      |> :binary.part(0, 4)
    end
  end

  @spec get_child_num(t()) :: binary
  def get_child_num(%__MODULE__{child_num: child_num}), do: child_num

  # PARSE & SERIALIZE 

  @doc """
    parse takes binary or string representation 
    of an extended key and parses it to an extended key object
  """
  @spec parse(binary) :: {:ok, t()} | {:error, String.t()}
  def parse(
        xkey =
          <<prefix::binary-size(4), depth::binary-size(1), parent_fingerprint::binary-size(4),
            child_num::binary-size(4), chaincode::binary-size(32), key::binary-size(33),
            checksum::binary-size(4)>>
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
            {:ok,
             %__MODULE__{
               prefix: prefix,
               depth: depth,
               parent_fingerprint: parent_fingerprint,
               child_num: child_num,
               chaincode: chaincode,
               key: key,
               checksum: checksum
             }}
        end
    end
  end

  # parse from string
  def parse(xkey) do
    case Base58.decode(xkey) do
      {:error, _} ->
        {:error, "error parsing key"}

      {:ok, xkey} ->
        xkey
        |> Base58.append_checksum()
        |> parse()
    end
  end

  # verify if point is valid on secp256k1
  defp check_point(key) do
    {:ok, pubkey} = Point.parse_public_key(key)
    Bitcoinex.Secp256k1.verify_point(pubkey)
  end

  @doc """
    serialize takes an extended key
    and returns the binary
  """
  @spec serialize(t()) :: binary
  def serialize(xkey) do
    (xkey.prefix <>
       xkey.depth <> xkey.parent_fingerprint <> xkey.child_num <> xkey.chaincode <> xkey.key)
    |> Base58.append_checksum()
  end

  @doc """
    display returns the extended key as a string
  """
  @spec display(t()) :: String.t()
  def display(xkey) do
    xkey
    |> serialize()
    |> Base58.encode_base()
  end

  @doc """
    seed_to_master_private_key transforms a bip32 seed 
    into a master extended private key
  """
  @spec seed_to_master_private_key(binary, atom) :: {:ok, t()} | {:error, String.t()}
  def seed_to_master_private_key(<<seed::binary>>, pfx \\ :xprv) do
    prefix = pfx_atom_to_bin(pfx)

    if prefix in @prv_prefixes do
      <<key::binary-size(32), chaincode::binary-size(32)>> =
        :crypto.hmac(:sha512, "Bitcoin seed", seed)

      depth_fingerprint_childnum = <<0, 0, 0, 0, 0, 0, 0, 0, 0>>

      (prefix <> depth_fingerprint_childnum <> chaincode <> <<0>> <> key)
      |> Base58.append_checksum()
      |> parse()
    else
      {:error, "invalid extended private key prefix"}
    end
  end

  @doc """
    to_extended_public_key takes an extended private key
    and returns an extended public key
  """
  @spec to_extended_public_key(t()) :: {:ok, t()} | {:error, String.t()}
  def to_extended_public_key(xprv) do
    if xprv.prefix in @prv_prefixes do
      try do
        {:ok, privkey} = PrivateKey.new(:binary.decode_unsigned(xprv.key, :big))

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
        |> parse()
      rescue
        _ in MatchError -> {:error, "invalid private key"}
      end
    else
      # it is an xpub already
      xprv
    end
  end

  @doc """
    to_private_key takes an extended private key
    and returns the contained private key.
  """
  @spec to_private_key(t()) :: {:ok, PrivateKey.t()} | {:error, String.t()}
  def to_private_key(xprv) do
    if xprv.prefix in @prv_prefixes do
      secret = :binary.decode_unsigned(xprv.key, :big)
      PrivateKey.new(secret)
    else
      {:error, "key is not a extended private key."}
    end
  end

  @doc """
    to_public_key takes an extended key xkey and 
    returns the public key.
  """
  @spec to_public_key(t()) :: {:ok, Point.t()} | {:error, String.t()}
  def to_public_key(xkey) do
    if xkey.prefix in @prv_prefixes do
      case to_private_key(xkey) do
        {:ok, prvkey} -> {:ok, PrivateKey.to_point(prvkey)}
        x -> x
      end
    else
      Point.parse_public_key(xkey.key)
    end
  end

  @doc """
    derive_child uses a public or private key xkey to
    derive the public or private key at index idx. 
    public key -> public child
    private key -> private child
  """
  @spec derive_child_key(t(), non_neg_integer) :: {:ok, t()} | {:error, String.t()}
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
  @spec derive_public_child(t(), non_neg_integer) :: {:ok, t()} | {:error, String.t()}
  def derive_public_child(xkey, idx) do
    cond do
      xkey.prefix in @prv_prefixes ->
        {:ok, child_xprv} = derive_private_child(xkey, idx)
        to_extended_public_key(child_xprv)

      idx >= DerivationPath.min_hardened_child_num() or idx < 0 ->
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
          {:ok, parent_pubkey} = Point.parse_public_key(xkey.key)
          {:ok, prvkey} = PrivateKey.new(key_secret)

          pubkey =
            prvkey
            |> PrivateKey.to_point()
            |> Math.add(parent_pubkey)

          if Point.is_inf(pubkey) do
            {:error, "pubkey is point at infinity, bad luck!"}
          else
            (xkey.prefix <>
               child_depth <> fingerprint <> i <> child_chaincode <> Point.sec(pubkey))
            |> Base58.append_checksum()
            |> parse()
          end
        end
    end
  end

  @doc """
    derive_private_child uses a private key xkey to 
    derive the private key at index idx 
  """
  @spec derive_private_child(t(), non_neg_integer()) :: {:ok, t()} | {:error, String.t()}
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

    try do
      {:ok, prvkey} = PrivateKey.new(key_secret)

      fingerprint =
        prvkey
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
      |> parse()
    rescue
      _ in MatchError -> {:error, "invalid private key in extended private key"}
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
    i =
      idx
      |> :binary.encode_unsigned()
      |> Bitcoinex.Utils.pad(4, :leading)

    if idx >= DerivationPath.min_hardened_child_num() do
      # hardened child from priv key
      :crypto.hmac(:sha512, xprv.chaincode, xprv.key <> i)
    else
      # unhardened child from privkey
      {:ok, prvkey} = PrivateKey.new(:binary.decode_unsigned(xprv.key))

      pubkey =
        prvkey
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
  @spec derive_extended_key(t() | binary, DerivationPath.t()) :: {:ok, t()} | {:error, String.t()}
  def derive_extended_key(xkey = %__MODULE__{}, %DerivationPath{child_nums: path}),
    do: rderive_extended_key(xkey, path)

  def derive_extended_key(seed, %DerivationPath{child_nums: path}) do
    {:ok, xkey} = seed_to_master_private_key(seed)
    rderive_extended_key(xkey, path)
  end

  defp rderive_extended_key(xkey = %__MODULE__{}, []), do: {:ok, xkey}

  defp rderive_extended_key(xkey = %__MODULE__{}, [p | rest]) do
    try do
      case p do
        # if asterisk (:any) is in path, return the immediate parent xkey
        :any ->
          {:ok, xkey}

        # otherwise it is an integer, so derive child at that index.
        _ ->
          case derive_child_key(xkey, p) do
            {:ok, child_key} -> rderive_extended_key(child_key, rest)
            {:error, msg} -> {:error, msg}
          end
      end
    rescue
      e in ArgumentError -> {:error, e.message}
    end
  end
end
