defmodule Bitcoinex.Script do
  @moduledoc """
  	a module for manipulating Bitcoin Scripts
  """

  import Bitcoinex.Opcode

  alias Bitcoinex.Secp256k1.Point

  alias Bitcoinex.{Utils, Address, Segwit, Base58, Network}

  @wsh_length 32
  @tapkey_length 32
  @h160_length 20

  @type script_type :: :p2pk | :p2pkh | :p2sh | :p2wpkh | :p2wsh | :p2tr | :non_standard

  @type t :: %__MODULE__{
          items: list
        }

  @enforce_keys [
    :items
  ]
  defstruct [:items]

  defp invalid_opcode_error(msg), do: {:error, "invalid opcode: #{msg}"}

  def is_valid_opcode(i) when is_integer(i), do: i >= 0x00 && i < 0xFF

  @doc """
  	new returns an empty script object.
  """
  @spec new() :: t()
  def new, do: %__MODULE__{items: []}

  @doc """
  	is_true? returns true if the script's only item is op_true, false otherwise.
  """
  @spec is_true?(t()) :: bool
  def is_true?(%__MODULE__{items: [0x51]}), do: true
  def is_true?(%__MODULE__{items: [:op_true]}), do: true
  def is_true?(_), do: false

  @doc """
  	to_list returns the script as a list of items
  """
  @spec to_list(t()) :: list
  def to_list(%__MODULE__{items: script}), do: script

  @doc """
  	empty? returns true for empty scripts, false otherwise.
  """
  @spec empty?(t()) :: bool
  def empty?(%__MODULE__{items: []}), do: true
  def empty?(_), do: false

  @doc """
  	script_length returns the number of items in the script.
  """
  @spec script_length(t()) :: non_neg_integer()
  def script_length(%__MODULE__{items: items}), do: length(items)

  @doc """
  	byte_length returns the byte length of the serialized script.
  """
  @spec byte_length(t()) :: non_neg_integer()
  def byte_length(script) do
    script
    |> serialize_script()
    |> byte_size()
  end

  @doc """
  	get_op_num returns the integer associated with the passed opcode atom.
  """
  @spec get_op_num(atom) :: {:ok, non_neg_integer()} | :error
  def get_op_num(op), do: Map.fetch(opcode_atoms(), op)

  @doc """
  	get_op_atom returns the atom associated with the passed opcode integer.
  """
  @spec get_op_atom(non_neg_integer()) :: non_neg_integer() | {:ok, atom}
  def get_op_atom(i), do: if(i > 0 and i < 0x4C, do: i, else: Map.fetch(opcode_nums(), i))

  @doc """
  	pop returns the first element of the script and the remaining script. 
  	Returns nil if script is empty
  """
  @spec pop(t()) :: nil | {:ok, non_neg_integer() | binary, t()}
  def pop(%__MODULE__{items: []}), do: nil
  def pop(%__MODULE__{items: [item | stack]}), do: {:ok, item, %__MODULE__{items: stack}}

  @doc """
  	push_op pushes a single opcode to the script as an integer and returns the script.
  """
  @spec push_op(t(), atom | non_neg_integer()) :: {:ok, t()} | {:error, String.t()}
  def push_op(%__MODULE__{items: stack}, item) do
    # item is opcode num
    if is_integer(item) and item >= 0 and item < 0xFF do
      {:ok, %__MODULE__{items: [item | stack]}}
    else
      # item is atom
      case get_op_num(item) do
        :error -> invalid_opcode_error(item)
        {:ok, op} -> {:ok, %__MODULE__{items: [op | stack]}}
      end
    end
  end

  # used to push data lengths and raw binary
  defp push_raw_data(%__MODULE__{items: stack}, data) do
    %__MODULE__{items: [data | stack]}
  end

  @doc """
  	push_data returns a script with the binary data and any 
  	accompanying pushdata or pushbytes opcodes added to the front of the script.
  """
  @spec push_data(t(), binary) :: {:ok, t()} | {:error, String.t()}
  def push_data(script = %__MODULE__{}, data) do
    datalen = byte_size(data)
    script = push_raw_data(script, data)

    cond do
      datalen < 0x4C ->
        push_op(script, datalen)

      datalen <= 0xFF ->
        push_op(script, :op_pushdata1)

      datalen <= 0xFFFF ->
        push_op(script, :op_pushdata2)

      datalen <= 0xFFFFFFFF ->
        push_op(script, :op_pushdata4)

      true ->
        {:error, "invalid data length, must be 0..0xffffffff, got #{datalen}"}
    end
  end

  # SERIALIZE & PARSE 
  defp serializer(%__MODULE__{items: []}, acc), do: acc

  defp serializer(%__MODULE__{items: [item | script]}, acc) when is_integer(item) do
    # prevents UTF-8 ints from becoming strings
    serializer(%__MODULE__{items: script}, acc <> Utils.int_to_little(item, 1))
  end

  # For data pushes
  defp serializer(%__MODULE__{items: [item | script]}, acc) when is_binary(item) do
    len = byte_size(item)

    cond do
      # CHECK IF PUSHBYTES75 is valid
      len < 0x4C ->
        serializer(%__MODULE__{items: script}, acc <> item)

      len <= 0xFF ->
        len = len |> Utils.int_to_little(1)
        serializer(%__MODULE__{items: script}, acc <> len <> item)

      # PUSHDATA limited to 520 bytes, so no PUSHDATA2 > 520 is a valid script.
      # Should we allow this?
      len <= 0xFFFF ->
        len = Utils.int_to_little(len, 2)
        serializer(%__MODULE__{items: script}, acc <> len <> item)

      # no PUSHDATA4 is a valid script.
      # Should we allow this?
      len <= 0xFFFFFFFF ->
        len = Utils.int_to_little(len, 4)
        serializer(%__MODULE__{items: script}, acc <> len <> item)

      true ->
        {:error, "data is too long"}
    end
  end

  @doc """
  	serialize_script serializes the script into binary 
  	according to Bitcoin's standard.
  """
  @spec serialize_script(t()) :: binary
  def serialize_script(script = %__MODULE__{}) do
    # serialize_script(%Script{items: [0x81]}) will still display "Q" but 
    # it functions as binary 0x51. Use to_hex for displaying scripts.
    serializer(script, <<>>)
  end

  @doc """
  	to_hex returns the hex of a serialized script. 
  """
  @spec to_hex(t()) :: String.t()
  def to_hex(script) do
    script
    |> serialize_script()
    |> Base.encode16(case: :lower)
  end

  @doc """
  	parse_script parses a binary or hex string into a script.
  """
  @spec parse_script(binary) :: {:ok, t()} | {:error, String.t()}
  def parse_script(script_str) when is_binary(script_str) do
    try do
      case Utils.hex_to_bin(script_str) do
        {:error, _msg} ->
          # necessary to allow parse_script to accept raw binary script
          parser(new(), script_str)

        bin ->
          parser(new(), bin)
      end
    rescue
      _ -> {:error, "invalid script. parse_script accepts hex or binary."}
    end
  end

  defp parser(script, <<>>), do: {:ok, script}

  defp parser(script, <<next::binary-size(1), bin::binary>>) do
    op = :binary.decode_unsigned(next)

    cond do
      # PUSHBYTES
      op > 0x00 and op < 0x4C ->
        {:ok, rest} = parser(script, :binary.part(bin, op, byte_size(bin) - op))

        rest
        |> push_raw_data(:binary.part(bin, 0, op))
        |> push_op(op)

      # PUSHDATA1
      op == 0x4C ->
        len = bin |> :binary.part(0, 1) |> Utils.little_to_int()
        {:ok, rest} = parser(script, :binary.part(bin, len + 1, byte_size(bin) - len - 1))

        rest
        |> push_raw_data(:binary.part(bin, 1, len))
        |> push_op(op)

      # PUSHDATA2
      op == 0x4D ->
        len = bin |> :binary.part(0, 2) |> Utils.little_to_int()
        {:ok, rest} = parser(script, :binary.part(bin, len + 2, byte_size(bin) - len - 2))

        rest
        |> push_raw_data(:binary.part(bin, 2, len))
        |> push_op(op)

      # PUSHDATA4
      op == 0x4E ->
        len = bin |> :binary.part(0, 4) |> Utils.little_to_int()
        {:ok, rest} = parser(script, :binary.part(bin, len + 4, byte_size(bin) - len - 4))

        rest
        |> push_raw_data(:binary.part(bin, 4, len))
        |> push_op(op)

      # OPCODE
      is_valid_opcode(op) ->
        {:ok, rest} = parser(script, :binary.part(bin, 0, byte_size(bin)))
        push_op(rest, op)

      true ->
        invalid_opcode_error(op)
    end
  end

  @doc """
  	raw_combine directly concatenates two scripts with no checks.
  """
  @spec raw_combine(t(), t()) :: t()
  def raw_combine(%__MODULE__{items: s1}, %__MODULE__{items: s2}),
    do: %__MODULE__{items: s1 ++ s2}

  @doc """
  	display_script returns a human readable string of the script, with
  	op_codes shown by name rather than number. 
  """
  @spec display_script(t()) :: String.t()
  def display_script(script) do
    " " <> scriptxt = display_script(script, "")
    scriptxt
  end

  defp display_script(%__MODULE__{items: []}, acc), do: acc

  defp display_script(%__MODULE__{items: [item | stack]}, acc) when is_integer(item) do
    if item > 0 and item < 0x4C do
      display_script(%__MODULE__{items: stack}, acc <> " OP_PUSHBYTES_#{item}")
    else
      {:ok, op_atom} = get_op_atom(item)
      upper_op = op_atom |> to_string() |> String.upcase()
      display_script(%__MODULE__{items: stack}, acc <> " " <> upper_op)
    end
  end

  defp display_script(%__MODULE__{items: [item | stack]}, acc) when is_binary(item) do
    display_script(%__MODULE__{items: stack}, acc <> " " <> Base.encode16(item, case: :lower))
  end

  # SCRIPT TYPE DETERMINERS

  @doc """
  	is_p2pk? returns whether a given script is of the p2pk format:
  	<33-byte or 65-byte pubkey> OP_CHECKSIG
  """
  @spec is_p2pk?(t()) :: boolean
  def is_p2pk?(%__MODULE__{
        items: [len, pubkey, 0xAC]
      })
      when len in [33, 65] and len == byte_size(pubkey) do
    true
  end

  def is_p2pk?(%__MODULE__{}), do: false

  @doc """
  	is_p2pkh? returns whether a given script is of the p2pkh format:
  	OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  """
  @spec is_p2pkh?(t()) :: boolean
  def is_p2pkh?(%__MODULE__{
        items: [0x76, 0xA9, @h160_length, <<_::binary-size(@h160_length)>>, 0x88, 0xAC]
      }),
      do: true

  def is_p2pkh?(%__MODULE__{}), do: false

  @doc """
  	is_p2sh? returns whether a given script is of the p2sh format:
  	OP_HASH160 OP_PUSHBYTES_20 <20-byte hash> OP_EQUAL
  """
  @spec is_p2sh?(t()) :: boolean
  def is_p2sh?(%__MODULE__{items: [0xA9, @h160_length, <<_::binary-size(@h160_length)>>, 0x87]}),
    do: true

  def is_p2sh?(%__MODULE__{}), do: false

  @doc """
  	is_p2wpkh? returns whether a given script is of the p2wpkh format:
  	OP_0 OP_PUSHBYTES_20 <20-byte hash>
  """
  @spec is_p2wpkh?(t()) :: boolean
  def is_p2wpkh?(%__MODULE__{items: [0x00, @h160_length, <<_::binary-size(@h160_length)>>]}),
    do: true

  def is_p2wpkh?(%__MODULE__{}), do: false

  @doc """
  	is_p2wsh? returns whether a given script is of the p2wsh format:
  	OP_0 OP_PUSHBYTES_32 <32-byte hash>
  """
  @spec is_p2wsh?(t()) :: boolean
  def is_p2wsh?(%__MODULE__{items: [0x00, @wsh_length, <<_::binary-size(@wsh_length)>>]}),
    do: true

  def is_p2wsh?(%__MODULE__{}), do: false

  @doc """
  	is_p2tr? returns whether a given script is of the p2tr format:
  	OP_1 OP_PUSHBYTES_32 <32-byte hash>
  """
  @spec is_p2tr?(t()) :: boolean
  def is_p2tr?(%__MODULE__{items: [0x01, @tapkey_length, <<_::binary-size(@tapkey_length)>>]}),
    do: true

  def is_p2tr?(%__MODULE__{}), do: false

  @doc """
  	get_script_type determines the type of a script based on its elements
  	returns :non_standard if no type matches
  """
  @spec get_script_type(t()) :: script_type
  def get_script_type(script = %__MODULE__{}) do
    cond do
      # sorted by most prevalent
      is_p2pkh?(script) -> :p2pkh
      is_p2sh?(script) -> :p2sh
      is_p2wpkh?(script) -> :p2wpkh
      is_p2wsh?(script) -> :p2wsh
      is_p2pk?(script) -> :p2pk
      is_p2tr?(script) -> :p2tr
      true -> :non_standard
    end
  end

  # CREATE COMMON SCRIPTS

  @doc """
  	create_p2pk creates a p2pk script using the passed public key
  """
  @spec create_p2pk(binary) :: {:ok, t()} | {:error, String.t()}
  def create_p2pk(pk) when is_binary(pk) and byte_size(pk) in [33, 65] do
    {:ok, s} = push_op(new(), 0xAC)
    push_data(s, pk)
  end

  def create_p2pk(_), do: {:error, "pubkey must be 33 or 65 bytes compressed or uncompressed SEC"}

  @doc """
  	create_p2pkh creates a p2pkh script using the passed 20-byte public key hash
  """
  @spec create_p2pkh(binary) :: {:ok, t()} | {:error, String.t()}
  def create_p2pkh(<<pkh::binary-size(@h160_length)>>) do
    {:ok, s} = push_op(new(), 0xAC)
    {:ok, s} = push_op(s, 0x88)
    {:ok, s} = push_data(s, pkh)
    {:ok, s} = push_op(s, 0xA9)
    push_op(s, 0x76)
  end

  def create_p2pkh(_), do: {:error, "pubkey hash must be a #{@h160_length}-byte hash"}

  @doc """
  	create_p2sh creates a p2sh script using the passed 20-byte public key hash
  """
  @spec create_p2sh(binary) :: {:ok, t()} | {:error, String.t()}
  def create_p2sh(<<sh::binary-size(@h160_length)>>) do
    {:ok, s} = push_op(new(), 0x87)
    {:ok, s} = push_data(s, sh)
    push_op(s, 0xA9)
  end

  def create_p2sh(_), do: {:error, "script hash must be a #{@h160_length}-byte hash"}

  @doc """
  	create_witness_scriptpubkey creates any witness script from a witness version
  	and witness program. It performs no validity checks. 
  """
  @spec create_witness_scriptpubkey(non_neg_integer(), binary) :: {:ok, t()}
  def create_witness_scriptpubkey(witver, witness_program) do
    {:ok, s} = push_data(new(), witness_program)
    push_op(s, witver)
  end

  @doc """
  	create_p2wpkh creates a p2wpkh script using the passed 20-byte public key hash
  """
  @spec create_p2wpkh(binary) :: {:ok, t()}
  def create_p2wpkh(<<pkh::binary-size(@h160_length)>>),
    do: create_witness_scriptpubkey(0x00, pkh)

  def create_p2wpkh(_), do: {:error, "pubkey hash must be a #{@h160_length}-byte hash"}

  @doc """
  	create_p2wsh creates a p2wsh script using the passed 32-byte script hash
  """
  @spec create_p2wsh(binary) :: {:ok, t()}
  def create_p2wsh(<<sh::binary-size(@wsh_length)>>), do: create_witness_scriptpubkey(0x00, sh)
  def create_p2wsh(_), do: {:error, "script hash must be a #{@wsh_length}-byte hash"}

  @doc """
  	create_p2tr creates a p2tr script using the passed 32-byte public key
  """
  @spec create_p2tr(binary) :: {:ok, t()}
  def create_p2tr(<<pk::binary-size(@tapkey_length)>>), do: create_witness_scriptpubkey(0x01, pk)
  def create_p2tr(_), do: {:error, "public key must be #{@tapkey_length}-bytes"}

  @doc """
  	create_p2sh_p2wpkh creates a p2wsh script using the passed 20-byte public key hash
  """
  @spec create_p2sh_p2wpkh(binary) :: {:ok, t(), t()}
  def create_p2sh_p2wpkh(<<pkh::binary-size(@h160_length)>>) do
    {:ok, p2wpkh} = create_p2wpkh(pkh)

    {:ok, p2sh} =
      p2wpkh
      |> serialize_script()
      |> Utils.hash160()
      |> create_p2sh()

    # return both p2sh script and redeem script (p2wpkh script)
    {:ok, p2sh, p2wpkh}
  end

  def create_p2sh_p2wpkh(_), do: {:error, "public key hash must be #{@h160_length}-bytes"}

  # CREATE SCRIPTS FROM PUBKEYS

  @doc """
  	public_key_hash takes the hash160 of the public key's compressed sec encoding. 
  	Can be used to create a pkh script.
  """
  @spec public_key_hash(Point.t()) :: binary
  def public_key_hash(p = %Point{}) do
    p
    |> Point.sec()
    |> Utils.hash160()
  end

  @doc """
  	public_key_to_p2pkh creates a p2pkh script from a public key. 
  	All public keys are compressed.
  """
  @spec public_key_to_p2pkh(Point.t()) :: {:ok, t()}
  def public_key_to_p2pkh(p = %Point{}) do
    p
    |> public_key_hash()
    |> create_p2pkh()
  end

  def public_key_to_p2pkh(_), do: {:error, "invalid public key"}

  @doc """
  	public_key_to_p2wpkh creates a p2wpkh script from a public key. 
  	All public keys are compressed.
  """
  @spec public_key_to_p2wpkh(Point.t()) :: {:ok, t()}
  def public_key_to_p2wpkh(p = %Point{}) do
    p
    |> public_key_hash()
    |> create_p2wpkh()
  end

  def public_key_to_p2wpkh(_), do: {:error, "invalid public key"}

  @doc """
  	public_key_to_p2sh_p2wpkh creates a p2sh-p2wpkh script from a public key. 
  	All public keys are compressed.
  """
  @spec public_key_to_p2sh_p2wpkh(Point.t()) :: {:ok, t(), t()}
  def public_key_to_p2sh_p2wpkh(p = %Point{}) do
    p
    |> public_key_hash()
    |> create_p2sh_p2wpkh()
  end

  def public_key_to_p2sh_p2wpkh(_), do: {:error, "invalid public key"}

  # ADDRESS CREATION & DECODING

  @doc """
  	from_address produces the scriptpubkey from an address.
  """
  @spec from_address(String.t()) ::
          {:error, String.t()} | {:ok, t(), Bitcoinex.Network.network_name()}
  def from_address(addr) do
    case String.slice(addr, 0, 2) do
      # segwit addresses 
      p when p in ["bc", "tb"] ->
        case Segwit.decode_address(addr) do
          {:ok, {network, version, program}} ->
            {:ok, script} = create_witness_scriptpubkey(version, :binary.list_to_bin(program))
            {:ok, script, network}

          {:error, _msg} ->
            {:error, "invalid segwit address"}
        end

      # legacy addresses
      _ ->
        try do
          {:ok, <<pfx::little-size(8), body::binary>>} = Base58.decode(addr)
          tpkh = Network.testnet().p2pkh_version_decimal_prefix
          mpkh = Network.mainnet().p2pkh_version_decimal_prefix
          tsh = Network.testnet().p2sh_version_decimal_prefix
          msh = Network.mainnet().p2sh_version_decimal_prefix

          case pfx do
            # p2pkh testnet
            ^tpkh ->
              {:ok, s} = create_p2pkh(body)
              {:ok, s, :testnet}

            # p2pkh mainnet
            ^mpkh ->
              {:ok, s} = create_p2pkh(body)
              {:ok, s, :mainnet}

            # p2sh testnet
            ^tsh ->
              {:ok, s} = create_p2sh(body)
              {:ok, s, :testnet}

            # p2sh mainnet
            ^msh ->
              {:ok, s} = create_p2sh(body)
              {:ok, s, :mainnet}
          end
        rescue
          _ -> {:error, "invalid address"}
        end
    end
  end

  @doc """
  	to_address converts a script object into the proper address type
  """
  @spec to_address(t(), Network.network_name()) ::
          {:ok, String.t()} | {:error, String.t()}
  def to_address(script = %__MODULE__{}, network) do
    {:ok, head, script} = pop(script)

    case head do
      # segwit 0
      0x00 ->
        {:ok, len, script} = pop(script)
        {:ok, <<res::binary-size(len)>>, _script} = pop(script)

        if len in [@h160_length, @wsh_length] do
          Segwit.encode_address(network, 0, :binary.bin_to_list(res))
        else
          {:error, "invalid witness program length. Must be in [#{@h160_length}, #{@wsh_length}]"}
        end

      # segwit 1 (taproot)
      0x01 ->
        {:ok, @tapkey_length, script} = pop(script)
        {:ok, <<res::binary-size(@tapkey_length)>>, _script} = pop(script)
        Segwit.encode_address(network, 1, :binary.bin_to_list(res))

      # p2sh
      0xA9 ->
        {:ok, @h160_length, script} = pop(script)
        {:ok, <<res::binary-size(@h160_length)>>, _script} = pop(script)
        {:ok, Address.encode(res, network, :p2sh)}

      # p2pkh 
      0x76 ->
        {:ok, 0xA9, script} = pop(script)
        {:ok, @h160_length, script} = pop(script)
        {:ok, <<res::binary-size(@h160_length)>>, _script} = pop(script)
        {:ok, Address.encode(res, network, :p2pkh)}

      _ ->
        {:error, "non standard script type"}
    end
  end
end
