defmodule EntropyGen do
  @moduledoc """
  Collect and combine seed entropy.

  Usage:
    mix run scripts/entropygen.exs                      # generate (default)
    mix run scripts/entropygen.exs -- generate
    mix run scripts/entropygen.exs -- combine H,H,...

  generate: build an entropy pool from 2048 bytes of OS RNG, 100 keystroke
            timings, and a free-text "jam" line, then print
            sha256d(<<0>> <> pool) <> sha256d(<<1>> <> pool) as 128 lowercase
            hex chars on stdout. All prompts/progress go to stderr so stdout
            can be redirected to a file. Refuses to run without a terminal.

  combine:  concatenate comma-separated hex blobs, compress with SHA-256d,
            take the first 16 bytes as BIP-39 entropy, and print the
            resulting 12-word mnemonic (Coldcard-style joined string plus a
            numbered two-column table). Deterministic: no RNG is mixed in.

  The vendored BIP-39 English wordlist (scripts/bip39_english.txt) is
  verified against its official SHA-256 on every load, and the encoder is
  checked against official BIP-39 test vectors before any mnemonic is
  printed. No network access is required or performed.
  """

  alias Bitcoinex.Utils

  @wordlist_file Path.join(__DIR__, "bip39_english.txt")
  @wordlist_sha256 "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
  @wordlist_size 2048

  @rng_bytes 2048
  @num_keystrokes 100

  # Official BIP-39 test vectors: 128-bit entropy (hex) -> 12-word mnemonic.
  @bip39_vectors [
    {"00000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
    {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank yellow"},
    {"80808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
    {"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"}
  ]

  @spec main([String.t()]) :: :ok
  def main(argv) do
    # `mix run script.exs -- args` passes the "--" separator through in argv
    argv =
      case argv do
        ["--" | rest] -> rest
        other -> other
      end

    case argv do
      [] -> cmd_generate()
      ["generate"] -> cmd_generate()
      ["combine", csv] -> cmd_combine(csv)
      ["combine"] -> die("combine requires a comma-separated hex argument")
      _ -> die("usage: mix run scripts/entropygen.exs -- [generate | combine H,H,...]")
    end

    :ok
  catch
    {:die, msg} ->
      IO.write(:stderr, "error: #{msg}\n")
      System.halt(1)
  end

  # -- generate ---------------------------------------------------------------

  defp cmd_generate do
    ensure_interactive!()

    IO.write(:stderr, "\n")

    IO.write(
      :stderr,
      "> Feel free to jam on your keyboard and enter some random bullshit, " <>
        "whose bytes will be incorporated into your entropy preimage: "
    )

    jam =
      case IO.gets("") do
        line when is_binary(line) -> String.replace_suffix(line, "\n", "")
        _eof_or_error -> die("stdin closed while reading input")
      end

    jitter = keystroke_jitter(@num_keystrokes)
    pool = :crypto.strong_rand_bytes(@rng_bytes) <> jitter <> jam

    IO.puts(Base.encode16(finalize_pool(pool), case: :lower))
  end

  @doc """
  Derive the final 64-byte output from an entropy pool:
  sha256d(<<0>> <> pool) <> sha256d(<<1>> <> pool).
  """
  @spec finalize_pool(binary()) :: binary()
  def finalize_pool(pool) do
    Utils.double_sha256(<<0>> <> pool) <> Utils.double_sha256(<<1>> <> pool)
  end

  # Refuse to collect entropy without an interactive terminal: silently timing
  # reads from a pipe or closed stdin would produce low-entropy jitter.
  defp ensure_interactive! do
    opts = :io.getopts(:standard_io)

    stdin_tty? = Keyword.get(opts, :stdin, false) or Keyword.get(opts, :terminal, false)

    if stdin_tty? != true do
      die("stdin is not a terminal; generate requires an interactive session")
    end
  end

  # Collect `n` keystroke timings from the terminal in raw mode (single keys,
  # no Enter, no echo). Each inter-key delta in nanoseconds is encoded as
  # 8 bytes little-endian. The terminal is always restored.
  #
  # Keystrokes are read through the Erlang io system (`IO.getn/2`) rather than
  # a separate /dev/tty file handle: the BEAM's tty driver reads stdin itself,
  # and a second reader on the same terminal races it for bytes. `stty` must
  # also target the tty by device path (e.g. /dev/ttys004): Erlang ports are
  # spawned detached from the controlling terminal, so `stty < /dev/tty` in a
  # subshell fails with "Device not configured".
  defp keystroke_jitter(n) do
    tty_path = controlling_tty_path!()
    saved = save_stty!(tty_path)
    old_encoding = Keyword.get(:io.getopts(:standard_io), :encoding, :unicode)

    try do
      # one byte per read, regardless of utf8 validity of the keys mashed
      :io.setopts(:standard_io, binary: true, encoding: :latin1)
      shell_ok!("stty raw -echo < #{tty_path}", "failed to set the terminal to raw mode")
      # prompt only after raw mode is active, so no keystroke is lost to the
      # canonical-mode input queue during the switch
      IO.write(:stderr, "Type #{n} keys (only timing is used):\r\n")
      collect_timings(n, 1, [])
    after
      restore_stty(tty_path, saved)
      :io.setopts(:standard_io, encoding: old_encoding)
      IO.write(:stderr, "\n")
    end
  end

  # Resolve the controlling terminal's device path (e.g. /dev/ttys004) from
  # this OS process, so subshells can run `stty` against it.
  defp controlling_tty_path! do
    case System.cmd("ps", ["-o", "tty=", "-p", System.pid()]) do
      {out, 0} ->
        name = String.trim(out)

        if name =~ ~r"^[A-Za-z0-9/]+$" and name not in ["??", "-"] do
          "/dev/" <> name
        else
          die("cannot determine controlling terminal (ps reported #{inspect(name)})")
        end

      {_out, _status} ->
        die("cannot determine controlling terminal (`ps -o tty=` failed)")
    end
  end

  defp collect_timings(n, i, acc) when i > n, do: IO.iodata_to_binary(Enum.reverse(acc))

  defp collect_timings(n, i, acc) do
    t0 = System.monotonic_time(:nanosecond)

    case IO.getn("", 1) do
      key when is_binary(key) and byte_size(key) >= 1 ->
        delta = System.monotonic_time(:nanosecond) - t0
        IO.write(:stderr, "\r#{i}/#{n}")
        collect_timings(n, i + 1, [<<delta::little-unsigned-64>> | acc])

      :eof ->
        die("terminal closed mid-collection; refusing to emit low-entropy output")

      other ->
        die("terminal read failed (#{inspect(other)}); aborting")
    end
  end

  defp save_stty!(tty_path) do
    case System.shell("stty -g < #{tty_path}") do
      {out, 0} ->
        saved = String.trim(out)

        if saved =~ ~r/^[A-Za-z0-9=:,.+_-]+$/ do
          saved
        else
          die("unexpected `stty -g` output; refusing to continue")
        end

      {_out, _status} ->
        die("`stty -g` failed; generate requires a controlling terminal")
    end
  end

  defp restore_stty(tty_path, saved) do
    case System.shell("stty '#{saved}' < #{tty_path}") do
      {_out, 0} ->
        :ok

      {_out, _status} ->
        System.shell("stty sane < #{tty_path}")
        IO.write(:stderr, "\nwarning: failed to restore terminal settings; ran `stty sane`\n")
    end
  end

  defp shell_ok!(cmd, err_msg) do
    case System.shell(cmd) do
      {_out, 0} -> :ok
      {_out, _status} -> die(err_msg)
    end
  end

  # -- combine ----------------------------------------------------------------

  defp cmd_combine(csv) do
    blobs =
      case parse_hex_csv(csv) do
        {:ok, blobs} -> blobs
        {:error, msg} -> die(msg)
      end

    words =
      case load_wordlist() do
        {:ok, words} -> words
        {:error, msg} -> die(msg)
      end

    case self_check(words) do
      :ok -> :ok
      {:error, msg} -> die(msg)
    end

    chosen = mnemonic_words(IO.iodata_to_binary(blobs), words)
    for_coldcard = Enum.map_join(chosen, &String.capitalize/1)

    if String.length(for_coldcard) >= 100 do
      die("produced a wordlist of length #{String.length(for_coldcard)}")
    end

    IO.puts("")
    IO.puts("Input to coldcard: " <> for_coldcard)
    IO.puts("")

    Enum.each(0..5, fn row ->
      IO.puts(
        "#{pad2(row + 1)}. #{String.pad_trailing(String.capitalize(Enum.at(chosen, row)), 12)} " <>
          "#{pad2(row + 7)}. #{String.capitalize(Enum.at(chosen, row + 6))}"
      )
    end)
  end

  defp pad2(n), do: String.pad_leading(Integer.to_string(n), 2)

  @doc """
  Parse a comma-separated list of hex strings (spaces ignored, empty segments
  skipped) into a list of binaries.
  """
  @spec parse_hex_csv(String.t()) :: {:ok, [binary()]} | {:error, String.t()}
  def parse_hex_csv(csv) do
    parts =
      csv
      |> String.replace(" ", "")
      |> String.split(",")
      |> Enum.reject(&(&1 == ""))

    decoded = Enum.map(parts, &Base.decode16(&1, case: :mixed))

    cond do
      Enum.any?(decoded, &(&1 == :error)) ->
        {:error, "inputs must be comma-separated hex strings"}

      decoded == [] ->
        {:error, "no entropy given"}

      true ->
        {:ok, Enum.map(decoded, fn {:ok, blob} -> blob end)}
    end
  end

  @doc """
  Compress `blob` with SHA-256d and map the first 16 bytes to 12 BIP-39 words.
  """
  @spec mnemonic_words(binary(), tuple()) :: [String.t()]
  def mnemonic_words(blob, words) do
    ent = binary_part(Utils.double_sha256(blob), 0, 16)
    encode_mnemonic(ent, words)
  end

  @doc """
  BIP-39 encode 16 bytes of entropy: append the 4-bit checksum (top 4 bits of
  SHA-256(ent)) and split the 132 bits into 12 big-endian 11-bit word indices.
  """
  @spec encode_mnemonic(binary(), tuple()) :: [String.t()]
  def encode_mnemonic(ent, words) when byte_size(ent) == 16 and tuple_size(words) == 2048 do
    <<cs::4, _::bitstring>> = Utils.sha256(ent)
    bits = <<ent::binary, cs::4>>

    for <<idx::11 <- bits>>, do: elem(words, idx)
  end

  @doc """
  Load the vendored BIP-39 English wordlist, verifying its SHA-256 digest and
  word count before use. Returns the 2048 words as a tuple.
  """
  @spec load_wordlist() :: {:ok, tuple()} | {:error, String.t()}
  def load_wordlist do
    with {:ok, data} <- read_wordlist_file(),
         :ok <- check_wordlist_hash(data) do
      words = String.split(data, ~r/\s+/, trim: true)

      if length(words) == @wordlist_size do
        {:ok, List.to_tuple(words)}
      else
        {:error, "BIP-39 wordlist has #{length(words)} words, expected #{@wordlist_size}"}
      end
    end
  end

  defp read_wordlist_file do
    case File.read(@wordlist_file) do
      {:ok, data} -> {:ok, data}
      {:error, reason} -> {:error, "cannot read #{@wordlist_file} (#{inspect(reason)})"}
    end
  end

  defp check_wordlist_hash(data) do
    if Base.encode16(Utils.sha256(data), case: :lower) == @wordlist_sha256 do
      :ok
    else
      {:error, "BIP-39 wordlist hash mismatch"}
    end
  end

  @doc """
  Verify the mnemonic encoder against official BIP-39 128-bit test vectors.
  """
  @spec self_check(tuple()) :: :ok | {:error, String.t()}
  def self_check(words) do
    failure =
      Enum.find(@bip39_vectors, fn {ent_hex, expected} ->
        ent = Base.decode16!(ent_hex, case: :lower)
        Enum.join(encode_mnemonic(ent, words), " ") != expected
      end)

    case failure do
      nil -> :ok
      {ent_hex, _} -> {:error, "BIP-39 self-check failed for entropy #{ent_hex}"}
    end
  end

  defp die(msg), do: throw({:die, msg})
end

if System.get_env("ENTROPYGEN_SKIP_MAIN") != "1" do
  EntropyGen.main(System.argv())
end
