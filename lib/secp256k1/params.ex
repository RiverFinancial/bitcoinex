defmodule Bitcoinex.Secp256k1.Params do
  @doc """
  Secp256k1 parameters.
  http://www.secg.org/sec2-v2.pdf
  """
  @spec curve :: %{
          p: non_neg_integer(),
          a: non_neg_integer(),
          b: non_neg_integer(),
          g_x: non_neg_integer(),
          g_y: non_neg_integer(),
          n: non_neg_integer(),
          h: non_neg_integer()
        }
  def curve do
    %{
      p: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F,
      a: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000,
      b: 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007,
      g_x: 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
      g_y: 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8,
      n: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141,
      h: 0x01
    }
  end

  @doc """
  Checks that k is a valid scalar in [1, n-1], where n is the curve order.
  Signature components r and s must be in this range.
  """
  @spec in_curve_order_range?(term()) :: boolean()
  def in_curve_order_range?(k), do: is_integer(k) and k >= 1 and k <= curve().n - 1
end
