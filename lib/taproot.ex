defmodule Bitcoinex.Taproot do
  alias Bitcoinex.Utils

  alias Bitcoinex.{Secp256k1, Script}
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}

  @n Params.curve().n

  @bip342_leaf_version 0xC0

  @spec bip342_leaf_version :: 192
  def bip342_leaf_version(), do: @bip342_leaf_version

  @type tapnode :: {tapnode, tapnode} | TapLeaf.t() | nil

  @spec tweak_privkey(PrivateKey.t(), binary) :: PrivateKey.t() | {:error, String.t()}
  def tweak_privkey(sk0 = %PrivateKey{}, h) do
    sk = Secp256k1.force_even_y(sk0)

    case PrivateKey.to_point(sk) do
      {:error, msg} ->
        {:error, msg}

      pk ->
        t = calculate_taptweak(pk, h)

        if t > @n do
          {:error, "invalid tweaked key"}
        else
          %PrivateKey{d: Math.modulo(sk.d + t, @n)}
        end
    end
  end

  @spec tweak_pubkey(Point.t(), binary) :: Point.t() | {:error, String.t()}
  def tweak_pubkey(pk = %Point{}, h) do
    t = calculate_taptweak(pk, h)

    if t > @n do
      {:error, "invalid tweaked key"}
    else
      t_point = PrivateKey.to_point(t)
      Math.add(pk, t_point)
    end
  end

  @spec calculate_taptweak(Point.t(), binary) :: non_neg_integer
  def calculate_taptweak(pk = %Point{}, h) do
    pk
    |> Point.x_bytes()
    |> Kernel.<>(h)
    |> tagged_hash_taptweak()
    |> :binary.decode_unsigned()
  end

  @spec tagged_hash_tapbranch(binary) :: <<_::256>>
  def tagged_hash_tapbranch(br), do: Utils.tagged_hash("TapBranch", br)

  @spec tagged_hash_taptweak(binary) :: <<_::256>>
  def tagged_hash_taptweak(root), do: Utils.tagged_hash("TapTweak", root)

  @spec tagged_hash_tapleaf(binary) :: <<_::256>>
  def tagged_hash_tapleaf(leaf), do: Utils.tagged_hash("TapLeaf", leaf)

  @spec tagged_hash_tapsighash(binary) :: <<_::256>>
  def tagged_hash_tapsighash(sigmsg), do: Utils.tagged_hash("TapSighash", sigmsg)

  defmodule TapLeaf do
    @moduledoc """
      TapLeaf represents a leaf of a Taproot Merkle tree. A leaf
      contains a version and a Script.
    """
    alias Bitcoinex.Script
    alias Bitcoinex.Taproot

    @type t :: %__MODULE__{
            version: non_neg_integer(),
            script: Script.t()
          }
    @enforce_keys [
      :version,
      :script
    ]
    defstruct [
      :version,
      :script
    ]

    @doc """
      new constructs a TapLeaf from a leaf_version and Script.
      The script is stored as binary with the compact size prepended to it.
    """
    @spec new(non_neg_integer(), Script.t()) :: t()
    def new(leaf_version, script = %Script{}) do
      %__MODULE__{version: leaf_version, script: script}
    end

    @spec from_string(non_neg_integer(), String.t()) :: t()
    def from_string(leaf_version, script_hex) do
      {:ok, script} = Script.parse_script(script_hex)
      new(leaf_version, script)
    end

    @doc """
      serialize returns a binary concatenation of the leaf_version and Script. TapLeaf structs
      store the Script in binary and alredy prepended with the compact size, so that is not added here.
    """
    @spec serialize(t()) :: binary
    def serialize(%__MODULE__{version: v, script: s}),
      do: :binary.encode_unsigned(v) <> Script.serialize_with_compact_size(s)

    @doc """
      hash returns the Hash_TapLeaf of the serialized TapLeaf
    """
    @spec hash(t()) :: <<_::256>>
    def hash(tapleaf = %__MODULE__{}), do: serialize(tapleaf) |> Taproot.tagged_hash_tapleaf()
  end

  @typedoc """
    script_tree represents a Taproot Script Merkle Tree. Leaves are represented by TapLeaf structs
    while branches are {script_tree, script_tree}. Since we sort based on hash at each level,
    left vs right branches are irrelevant. An empty tree is represented by nil.
  """
  @type script_tree :: TapLeaf.t() | {script_tree(), script_tree()} | nil

  @doc """
    merkelize_script_tree takes a script_tree (either nil, a TapLeaf, or a tuple of two script_trees)
    and constructs the root node. It returns {root_node, hash}. The hash is nil if the script_tree is empty.
    defined in BIP341 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
  """
  @spec merkelize_script_tree(script_tree()) :: {list({TapLeaf.t(), binary}), binary}
  def merkelize_script_tree(nil), do: {nil, <<>>}

  def merkelize_script_tree(leaf = %TapLeaf{}) do
    hash = TapLeaf.hash(leaf)

    {[{leaf, <<>>}], hash}
  end

  def merkelize_script_tree({left, right}) do
    {{l_branches, l_hash}, {r_branches, r_hash}} =
      {merkelize_script_tree(left), merkelize_script_tree(right)}

    # cross-mix the right hash with left branch and left hash with right branch
    new_left = merkelize_branches(l_branches, r_hash)
    new_right = merkelize_branches(r_branches, l_hash)

    node = new_left ++ new_right

    # combine the branches to form root node.
    {l_hash, r_hash} = Utils.lexicographical_sort(l_hash, r_hash)
    hash = tagged_hash_tapbranch(l_hash <> r_hash)
    {node, hash}
  end

  defp merkelize_branches([], _), do: []

  defp merkelize_branches([{leaf, c} | tail], hash) do
    [{leaf, c <> hash} | merkelize_branches(tail, hash)]
  end

  @spec build_control_block(Point.t(), script_tree(), non_neg_integer()) :: binary
  def build_control_block(p = %Point{}, script_tree, script_index) do
    {tree, hash} = merkelize_script_tree(script_tree)
    {tapleaf, merkle_path} = Enum.at(tree, script_index)
    q = tweak_pubkey(p, hash)
    q_parity = if Point.has_even_y(q), do: 0, else: 1

    <<q_parity + tapleaf.version>> <> Point.x_bytes(p) <> merkle_path
  end

  # Should this take a Script or binary script
  @spec merkelize_control_block(<<_::256>>, binary) :: any
  def merkelize_control_block(<<k0::binary-size(32)>>, path) do
    # Consume each 32-byte chunk of the rest of the control path, which are hashes of the merkle tree
    path
    |> :binary.bin_to_list()
    |> Enum.chunk_every(32)
    |> Enum.reduce(k0, fn e, k -> merkelize_path(e, k) end)
  end

  defp merkelize_path(<<e::binary-size(32)>>, <<k::binary-size(32)>>) do
    {l, r} = Utils.lexicographical_sort(e, k)
    {:cont, tagged_hash_tapbranch(l <> r)}
  end

  @doc """
    validate_taproot_scriptpath_spend DOES NOT validate the actual script according to BIP342.
    It only validates the BIP341 rules around how a scriptPath spend works.
    See: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
  """
  @spec validate_taproot_scriptpath_spend(Point.t(), binary, binary) ::
          bool | {:error, String.t()}
  def validate_taproot_scriptpath_spend(
        q_point = %Point{},
        script,
        <<c::binary-size(1)>> <> <<p::binary-size(32)>> <> path
      ) do
    leaf_version = extract_leaf_version(c)

    k0 =
      tagged_hash_tapleaf(
        leaf_version <> Utils.serialize_compact_size_unsigned_int(byte_size(script)) <> script
      )

    k = merkelize_control_block(k0, path)
    # t is tweak
    t = tagged_hash_taptweak(p <> k) |> :binary.decode_unsigned()

    case {PrivateKey.to_point(t), Point.lift_x(p)} do
      {{:error, _}, _} ->
        {:error, "control block yielded invalid tweak"}

      {_, {:error, _}} ->
        {:error, "failed to parse point Q"}

      {tk, {:ok, pk}} ->
        validate_q(q_point, Math.add(pk, tk), c)
        # TODO evaluate actual script?
    end
  end

  defp validate_q(given_q = %Point{}, calculated_q = %Point{}, <<c::binary-size(1)>>) do
    q_parity = extract_q_parity(c)

    cond do
      q_parity != Point.has_even_y(given_q) ->
        {:error, "incorrect Q parity"}

      given_q.x != calculated_q.x ->
        {:error, "Q points do not match"}

      true ->
        true
    end
  end

  @spec extract_leaf_version(<<_::8>>) :: binary
  defp extract_leaf_version(<<c::binary-size(1)>>) do
    c
    |> :binary.decode_unsigned()
    |> Bitwise.band(0xFE)
    |> :binary.encode_unsigned()
  end

  @spec extract_q_parity(<<_::8>>) :: bool
  defp extract_q_parity(<<c::binary-size(1)>>) do
    q_mod2 =
      c
      |> :binary.decode_unsigned()
      |> Bitwise.band(1)

    q_mod2 == 0
  end
end
