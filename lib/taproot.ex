defmodule Bitcoinex.Taproot do
  alias Bitcoinex.Utils

  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Math, Params, Point, PrivateKey}

  @n Params.curve().n

  # @bip342_leaf_version 0xc0

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

  @spec tagged_hash_tapbranch(binary) :: binary
  def tagged_hash_tapbranch(br), do: Utils.tagged_hash("TapBranch", br)

  @spec tagged_hash_taptweak(binary) :: binary
  def tagged_hash_taptweak(root), do: Utils.tagged_hash("TapTweak", root)

  @spec tagged_hash_tapleaf(binary) :: binary
  def tagged_hash_tapleaf(leaf), do: Utils.tagged_hash("TapLeaf", leaf)

  defmodule TapLeaf do
    alias Bitcoinex.Script
    alias Bitcoinex.Taproot

    @type t :: %__MODULE__{
            version: non_neg_integer(),
            script: binary
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
      from_script constructs a TapLeaf from a leaf_version and Script.
      The script is stored as binary with the compact size prepended to it.
    """
    @spec from_script(non_neg_integer(), Script.t()) :: t()
    def from_script(leaf_version, script = %Script{}) do
      s = Script.serialize_with_compact_size(script)
      %__MODULE__{version: leaf_version, script: s}
    end

    @spec from_string(non_neg_integer(), String.t()) :: t()
    def from_string(leaf_version, script_hex) do
      {:ok, script} = Script.parse_script(script_hex)
      from_script(leaf_version, script)
    end

    @doc """
      serialize returns a binary concatenation of the leaf_version and Script. TapLeaf structs
      store the Script in binary and alredy prepended with the compact size, so that is not added here.
    """
    @spec serialize(t()) :: binary
    def serialize(%__MODULE__{version: v, script: s}), do: :binary.encode_unsigned(v) <> s

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
    new_left = merge_branches(l_branches, r_hash)
    new_right = merge_branches(r_branches, l_hash)

    node = new_left ++ new_right

    # combine the branches to form root node.
    {l_hash, r_hash} = Utils.lexicographical_sort(l_hash, r_hash)
    hash = tagged_hash_tapbranch(l_hash <> r_hash)
    {node, hash}
  end

  defp merge_branches([], _), do: []

  defp merge_branches([{leaf, c} | tail], hash) do
    [{leaf, c <> hash} | merge_branches(tail, hash)]
  end

  @spec build_control_block(Point.t(), script_tree(), non_neg_integer()) :: binary
  def build_control_block(p = %Point{}, script_tree, script_index) do
    {tree, hash} = merkelize_script_tree(script_tree)
    {tapleaf, merkle_path} = Enum.at(tree, script_index)
    q = tweak_pubkey(p, hash)
    q_parity = if Point.has_even_y(q), do: 0, else: 1

    <<q_parity + tapleaf.version>> <> Point.x_bytes(p) <> merkle_path
  end
end
