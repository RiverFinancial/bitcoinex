defmodule Bitcoinex.Secp256k1 do
  # current mostly copy from https://github.com/comboy/bitcoin-elixir/blob/develop/lib/bitcoin/secp256k1.ex

  @moduledoc """
  ECDSA Secp256k1 curve operations.
  By default erlang's :crypto.verify is used to make it less problematic when using
  as a library (no need for gcc when you just want to parse something).
  However, if :libsecp256k1 NIF is available, it's used. To enable it just uncomment
  appropriate line in mix.exs deps.
  libsecp256k1: https://github.com/bitcoin-core/secp256k1
  If gcc and git dependencies are not a problem, use NIF. It's much faster and it's
  the proper way to do it consensus-wise. Do note that even though it's unlikely, an error
  in the NIF or libsecp256k1 will bring the whole erlang VM down (not just the process)
  """

  require Logger

  @spec ecdsa_recover_compact(binary, binary, atom, integer) ::
          {:ok, binary} | {:error, String.t()}
  def ecdsa_recover_compact(msg, compactSig, compressed, recoverId) do
    case :libsecp256k1.ecdsa_recover_compact(msg, compactSig, compressed, recoverId) do
      {:error, error} ->
        {:error, List.to_string(error)}

      {:ok, _} = ok ->
        ok
    end
  end

  @doc """
  Secp256k1 parameters.
  http://www.secg.org/sec2-v2.pdf
  """
  @spec params :: map
  def params do
    %{
      p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F,
      a: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000,
      b: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007,
      G:
        0x04_79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798_483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8,
      n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141,
      h: 0x01
    }
  end
end
