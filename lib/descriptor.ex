defmodule Bitcoinex.Descriptor do
  @moduledoc """
  Module for using Descriptors

  types of descriptors:

  :pkh (%DKEY)
  :sh (%DESCRIPTOR) # recursive
  :wpkh (%DKEY)
  :wsh (%DESCRIPTOR) # recursive
  :pk (%DKEY)
  :combo (%DKEY)
  :multi (m, [%DKEY...])
  :sortedmulti (m, [%DKEY...])
  :addr (str)
  :raw (str)
  """
  alias Bitcoinex.{
    Script,
    ExtendedKey,
    Network,
    ExtendedKey.DerivationPath,
    Secp256k1.PrivateKey,
    Secp256k1.Point
  }

  # TODO can't create DKey straight from WIF
  defmodule DKey do
    # WIF encoding requires network info
    @type key_type ::
            ExtendedKey.t() | {PrivateKey.t(), Network.network_name()} | Point.t()

    @type t :: %__MODULE__{
            key: key_type,
            parent_fingerprint: binary,
            ancestor_path: DerivationPath.t(),
            descendant_path: DerivationPath.t()
          }

    @enforce_keys [
      :key
    ]

    defstruct [
      # default both to empty for easier serialization
      :key,
      parent_fingerprint: <<>>,
      ancestor_path: DerivationPath.new(),
      descendant_path: DerivationPath.new()
    ]

    def get_type(%__MODULE__{key: %ExtendedKey{}}), do: :extended_key
    def get_type(%__MODULE__{key: %Point{}}), do: :public_key
    def get_type(%__MODULE__{key: {%PrivateKey{}, _}}), do: :private_key
    def get_type(_), do: :invalid_key

    def is_valid?(dkey) do
      case get_type(dkey) do
        # TODO: maybe expand later
        :extended_key -> true
        :public_key -> true
        :private_key -> true
        :invalid_key -> false
      end
    end

    # used by descriptor module to make all keys into dkeys.
    # if dkey is passed, returns identity
    def from_key(dkey = %__MODULE__{}), do: dkey
    def from_key(pk = %Point{}), do: %__MODULE__{key: pk}
    def from_key(xkey = %ExtendedKey{}), do: %__MODULE__{key: xkey}
    def from_key(_), do: {:error, "invalid key"}

    def from_key(sk = %PrivateKey{}, network), do: from_private_key(sk, network)

    def from_key(xkey = %ExtendedKey{}, pathdata) do
      defaults = %{
        parent_fingerprint: <<>>,
        anc_path: DerivationPath.new(),
        desc_path: DerivationPath.new()
      }

      data = Map.merge(defaults, pathdata)
      from_extended_key(xkey, data.parent_fingerprint, data.anc_path, data.desc_path)
    end

    def from_key(_, _), do: {:error, "invalid key"}

    @spec from_private_key(PrivateKey.t(), Network.network_name()) :: t()
    def from_private_key(sk = %PrivateKey{}, network) do
      # ensure valid network is passed
      _ = Network.get_network(network)
      %__MODULE__{key: {sk, network}}
    end

    def from_extended_key(
          xkey = %ExtendedKey{},
          parent_fingerprint,
          anc_path = %DerivationPath{},
          desc_path = %DerivationPath{}
        ) do
      %__MODULE__{
        key: xkey,
        parent_fingerprint: parent_fingerprint,
        ancestor_path: anc_path,
        descendant_path: desc_path
      }
    end

    def serialize(desc = %__MODULE__{key: key}) do
      fp = Base.encode16(desc.parent_fingerprint, case: :lower)
      {:ok, anc_path} = DerivationPath.to_string(desc.ancestor_path)
      {:ok, desc_path} = DerivationPath.to_string(desc.descendant_path)

      serialized_key = serialize_key(key)

      case fp <> handle_slashes(anc_path) do
        "" ->
          serialized_key <> handle_slashes(desc_path)

        origin ->
          "[" <> origin <> "]" <> serialized_key <> handle_slashes(desc_path)
      end
    end

    defp serialize_key(key = %ExtendedKey{}), do: ExtendedKey.to_string(key)
    defp serialize_key({sk = %PrivateKey{}, network}), do: PrivateKey.wif!(sk, network)
    defp serialize_key(key = %Point{}), do: Point.sec(key) |> Base.encode16(case: :lower)

    defp handle_slashes(""), do: ""

    defp handle_slashes(deriv_str) do
      case String.split_at(deriv_str, -1) do
        {deriv, "/"} -> "/" <> deriv
        _ -> "/" <> deriv_str
      end
    end

    def parse(hex_data) do
      try do
        {:ok, parser(hex_data)}
      rescue
        _ -> {:error, "failed to parse descriptor key"}
      end
    end

    def parser(hex_data) do
      if String.first(hex_data) == "[" do
        {:ok, fp, anc_path, remaining} = parse_ancestor_data(hex_data)
        {:ok, key, desc_path} = parse_key_data(remaining)

        %__MODULE__{
          key: key,
          parent_fingerprint: fp,
          ancestor_path: anc_path,
          descendant_path: desc_path
        }
      else
        {:ok, key, desc_path} = parse_key_data(hex_data)

        %__MODULE__{key: key, descendant_path: desc_path}
      end
    end

    defp parse_ancestor_data("[" <> hex_data) do
      [anc_data, remaining] = String.split(hex_data, "]", parts: 2)
      [fp | tail] = String.split(anc_data, "/", parts: 2)

      <<fingerprint::binary-size(4)>> =
        fp
        |> String.downcase()
        |> Base.decode16!(case: :lower)

      # ancestor path is optional
      case tail do
        [deriv] ->
          {:ok, anc_path} = DerivationPath.from_string(deriv)
          {:ok, fingerprint, anc_path, remaining}

        [] ->
          {:ok, fingerprint, DerivationPath.new(), remaining}
      end
    end

    defp parse_ancestor_data(_), do: raise(ArgumentError)

    defp parse_key_data(hex_data) do
      case String.first(hex_data) do
        # extended key
        "x" ->
          case String.split(hex_data, "/", parts: 2) do
            [xkey] ->
              {:ok, xkey} = ExtendedKey.parse_extended_key(xkey)
              {:ok, xkey, DerivationPath.new()}

            [xkey, desc_str] ->
              {:ok, xkey} = ExtendedKey.parse_extended_key(xkey)
              {:ok, desc_path} = DerivationPath.from_string(desc_str)
              {:ok, xkey, desc_path}
          end

        # public key
        "0" ->
          # since uncompressed pubkeys are not allowed for sh and wpkh,
          # we disallow them universally
          if String.length(hex_data) != 66 do
            {:error, "public key must be compressed (33bytes)"}
          else
            {:ok, pk} = Point.parse_public_key(hex_data)
            {:ok, pk, DerivationPath.new()}
          end

        # private key
        _ ->
          # WARNING: only accepts compressed private keys
          {:ok, sk, network, true} = PrivateKey.parse_wif(hex_data)
          {:ok, {sk, network}, DerivationPath.new()}
      end
    end
  end

  @type descriptor_type ::
          :pk | :pkh | :sh | :wpkh | :wsh | :combo | :multi | :sortedmulti | :addr | :raw
  @descriptor_types ~w(pk pkh sh wpkh wsh combo multi sortedmulti addr raw)a
  @top_level_only [:sh, :combo, :addr, :raw]

  @type t :: %__MODULE__{
          script_type: descriptor_type,
          data: t() | DKey.t() | Script.t() | {non_neg_integer(), list(DKeys.t())} | binary
        }
  @enforce_keys [
    :script_type,
    :data
  ]
  defstruct [
    :script_type,
    :data
  ]

  def parse_descriptor(desc) do
    try do
      parser(desc)
    rescue
      _ -> {:error, "invalid descriptor"}
    end
  end

  def parser(desc) do
    case split_descriptor(desc) do
      # sh & wsh can be recursive
      {:ok, :sh, rest} ->
        {:ok, inner} = parser(rest)
        create_p2sh(inner)

      {:ok, :wsh, rest} ->
        {:ok, inner} = parser(rest)
        create_p2wsh(inner)

      {:ok, :multi, rest} ->
        {:ok, inner} = parse_multi(rest)
        create_multi(inner)

      {:ok, :sortedmulti, rest} ->
        {:ok, inner} = parse_multi(rest)
        create_sortedmulti(inner)

      {:ok, :raw, rest} ->
        create_raw(rest)

      {:ok, :addr, rest} ->
        create_addr(rest)

      {:ok, script_type, rest} ->
        {:ok, dkey} = DKey.parse(rest)
        create_descriptor(script_type, dkey)

      {:error, _msg} ->
        raise ArgumentError
    end
  end

  def split_descriptor(desc) do
    [s_type, rest] = String.split(desc, "(", parts: 2)

    case String.split_at(rest, -1) do
      {rest, ")"} ->
        if String.to_atom(s_type) in @descriptor_types do
          {:ok, String.to_atom(s_type), rest}
        else
          {:error, "invalid descriptor"}
        end

      _ ->
        {:error, "invalid descriptor"}
    end
  end

  defp parse_multi(multi_str) do
    [m | keys] = String.split(multi_str, ",")
    dkeys = parse_dkeys(keys)
    {:ok, {String.to_integer(m), dkeys}}
  end

  defp parse_dkeys([]), do: []

  defp parse_dkeys([dstr | rest]) do
    case DKey.parse(dstr) do
      {:ok, dkey} -> [dkey | parse_dkeys(rest)]
      {:error, "invalid key"} -> raise ArgumentError
    end
  end

  @spec serialize_descriptor(t()) :: String.t()
  def serialize_descriptor(%__MODULE__{script_type: st, data: data}) do
    cond do
      st in [:sh, :wsh] -> serialize_recursive(st, data)
      st in [:multi, :sortedmulti] -> serialize_multi(st, data)
      st in [:pk, :pkh, :wpkh, :combo] -> serialize_key_descriptor(st, data)
      st in [:addr, :raw] -> serialize_simple(st, data)
    end
  end

  defp serialize_recursive(script_type, data) do
    to_string(script_type) <> "(" <> serialize_descriptor(data) <> ")"
  end

  defp serialize_key_descriptor(script_type, dkey) do
    to_string(script_type) <> "(" <> DKey.serialize(dkey) <> ")"
  end

  defp serialize_multi(script_type, {m, dkeys}) do
    to_string(script_type) <> "(#{m}," <> serialize_dkeys(dkeys) <> ")"
  end

  defp serialize_dkeys(dkeys) do
    dkeys
    |> Enum.map(&DKey.serialize/1)
    |> Enum.join(",")
  end

  defp serialize_simple(script_type, data) do
    to_string(script_type) <> "(#{data})"
  end

  def get_script_type(descriptor) do
    case descriptor.script_type do
      :pk ->
        :p2pk

      :pkh ->
        :p2pkh

      :sh ->
        :p2sh

      :wpkh ->
        :p2wpkh

      :wsh ->
        :p2wsh

      :combo ->
        :non_standard

      :multi ->
        :multi

      :sortedmulti ->
        :multi
        # TODO
        # :addr ->
        # return exact address script type
        # :raw ->
        # return exact script type
    end
  end

  def create_descriptor(dtype, dkey) do
    case dtype do
      :sh -> create_p2sh(dkey)
      :wsh -> create_p2wsh(dkey)
      :pk -> create_p2pk(dkey)
      :pkh -> create_p2pkh(dkey)
      :wpkh -> create_p2wpkh(dkey)
      :combo -> create_combo(dkey)
      :multi -> create_multi(dkey)
      :sortedmulti -> create_sortedmulti(dkey)
      :addr -> create_addr(dkey)
      :raw -> create_raw(dkey)
    end
  end

  # Allow users to easily set an xpub, origin and desc info. this is a weird way

  @spec create_p2pk(DKey.key_type()) :: {:ok, t()} | {:error, String.t()}
  def create_p2pk(key) do
    try do
      {:ok, %__MODULE__{script_type: :pk, data: DKey.from_key(key)}}
    rescue
      _ -> {:error, "invalid key"}
    end
  end

  @spec create_p2pkh(DKey.key_type()) :: {:ok, t()} | {:error, String.t()}
  def create_p2pkh(key) do
    try do
      {:ok, %__MODULE__{script_type: :pkh, data: DKey.from_key(key)}}
    rescue
      _ -> {:error, "invalid key"}
    end
  end

  @spec create_p2sh(t()) :: {:ok, t()} | {:error, String.t()}
  def create_p2sh(descriptor = %__MODULE__{script_type: st}) when st not in @top_level_only do
    {:ok, %__MODULE__{script_type: :sh, data: descriptor}}
  end

  def create_p2sh(_), do: {:error, "p2sh descriptors can only contain descriptors."}

  @spec create_p2wsh(t()) :: {:ok, t()} | {:error, String.t()}
  def create_p2wsh(descriptor = %__MODULE__{script_type: st})
      when st not in [:wsh | [:wpkh | @top_level_only]] do
    try do
      {:ok, %__MODULE__{script_type: :wsh, data: descriptor}}
    rescue
      _ -> {:error, "invalid script"}
    end
  end

  @spec create_p2wpkh(DKey.key_type()) :: {:ok, t()} | {:error, String.t()}
  def create_p2wpkh(key) do
    try do
      {:ok, %__MODULE__{script_type: :wpkh, data: DKey.from_key(key)}}
    rescue
      _ -> {:error, "invalid key"}
    end
  end

  @spec create_combo(DKey.key_type()) :: {:ok, t()} | {:error, String.t()}
  def create_combo(key) do
    try do
      {:ok, %__MODULE__{script_type: :combo, data: DKey.from_key(key)}}
    rescue
      _ -> {:error, "invalid key"}
    end
  end

  @spec create_multi({non_neg_integer(), list(DKey.key_type())}) ::
          {:ok, t()} | {:error, String.t()}
  def create_multi({m, keys}) do
    try do
      {:ok, %__MODULE__{script_type: :multi, data: {m, Enum.map(keys, &DKey.from_key/1)}}}
    rescue
      _ -> {:error, "invalid keys present. All keys must be DKey type"}
    end
  end

  @spec create_sortedmulti({non_neg_integer(), list(DKey.key_type())}) ::
          {:ok, t()} | {:error, String.t()}
  def create_sortedmulti({m, keys}) do
    try do
      {:ok, %__MODULE__{script_type: :sortedmulti, data: {m, Enum.map(keys, &DKey.from_key/1)}}}
    rescue
      _ -> {:error, "invalid keys present. All keys must be DKey type"}
    end
  end

  @spec create_addr(String.t()) :: {:ok, t()} | {:error, String.t()}
  def create_addr(addr_str) do
    # TODO switch this to `Address.is_valid?(:testnet) || Address.is_valid?(:mainnet) || Address.is_valid?(:regtest)
    case Script.from_address(addr_str) do
      # check address is valid agnostic of network
      {:ok, _script, _network} -> {:ok, %__MODULE__{script_type: :addr, data: addr_str}}
      {:error, _msg} -> {:error, "invalid address"}
    end
  end

  @spec create_raw(String.t()) :: {:ok, t()} | {:error, String.t()}
  def create_raw(hex_str) do
    case Script.parse_script(hex_str) do
      # check script is well-formed.
      {:ok, script} -> {:ok, %__MODULE__{script_type: :raw, data: script}}
      {:error, _msg} -> {:error, "invalid script"}
    end
  end
end
