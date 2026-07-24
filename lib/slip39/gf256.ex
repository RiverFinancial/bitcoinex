defmodule Bitcoinex.SLIP39.GF256 do
  @moduledoc """
  Arithmetic over the Galois field GF(256) used by SLIP-39 Shamir Secret Sharing.

  The field is GF(2^8) with the Rijndael/AES reducing polynomial
  `0x11B` (x^8 + x^4 + x^3 + x + 1). Field addition and subtraction are both
  bitwise XOR. Multiplication and division are implemented with exp/log
  tables generated at compile time from the generator `3` (0x03), which is a
  primitive element of the field: the exp table has cycle length 255 and the
  log table covers every nonzero element.

  `interpolate/2` performs byte-lane-wise Lagrange interpolation over share
  values, per the SLIP-39 formula
  `f(x) = sum_i y_i * prod_{j != i} (x - x_j) / (x_i - x_j)`.
  """

  import Bitwise

  # Compile-time exp/log table generation. NOTE: a same-module defp is not
  # callable at this module's own compile time, so the shift-and-reduce
  # ("Russian peasant") multiplication is an anonymous function evaluated in
  # the module body.
  slow_mul = fn a, b ->
    0..7
    |> Enum.reduce({0, a}, fn i, {acc, shifted} ->
      acc = if (b >>> i &&& 1) == 1, do: bxor(acc, shifted), else: acc
      shifted = shifted <<< 1
      shifted = if shifted > 0xFF, do: bxor(shifted, 0x11B), else: shifted
      {acc, shifted}
    end)
    |> elem(0)
  end

  # exp_list = [3^0, 3^1, ..., 3^254]; 3^255 wraps back to 1 (cycle length 255).
  {exp_list, wrap} = Enum.map_reduce(0..254, 1, fn _i, x -> {x, slow_mul.(x, 3)} end)

  # Compile-time sanity checks: the cycle closes at 1 and the 255 powers of 3
  # are distinct, i.e. 3 generates the whole multiplicative group.
  1 = wrap
  log_by_value = exp_list |> Enum.with_index() |> Map.new()
  255 = map_size(log_by_value)

  @exp_table List.to_tuple(exp_list)
  # log[0] is undefined in the field; slot 0 holds a placeholder that is
  # never read (mul/divide/pow short-circuit on 0 before any table lookup).
  @log_table 0..255 |> Enum.map(&Map.get(log_by_value, &1, 0)) |> List.to_tuple()

  @doc """
  Field addition (== subtraction): bitwise XOR.

  ## Examples

      iex> Bitcoinex.SLIP39.GF256.add(0x57, 0x13)
      0x44

      iex> Bitcoinex.SLIP39.GF256.add(0xAB, 0xAB)
      0
  """
  @spec add(byte(), byte()) :: byte()
  def add(a, b), do: bxor(a, b)

  @doc """
  Field multiplication via the exp/log tables.

  ## Examples

  The FIPS-197 (AES) known answer `{57} * {13} = {fe}`:

      iex> Bitcoinex.SLIP39.GF256.mul(0x57, 0x13)
      0xFE
  """
  @spec mul(byte(), byte()) :: byte()
  def mul(0, _b), do: 0
  def mul(_a, 0), do: 0

  def mul(a, b) do
    # Integer.mod (not rem) to stay consistent with divide/2 and pow/2, whose
    # operands can go negative; the sum here is always non-negative, so the two
    # would agree, but a uniform reduction avoids a future copy-paste footgun.
    elem(@exp_table, Integer.mod(elem(@log_table, a) + elem(@log_table, b), 255))
  end

  @doc """
  Field division: `a / b`. Raises `ArithmeticError` when `b == 0`.

  Named `divide/2` rather than `div/2`: a local `div/2` conflicts with the
  auto-imported `Kernel.div/2`.

  ## Examples

      iex> Bitcoinex.SLIP39.GF256.divide(0xFE, 0x13)
      0x57
  """
  @spec divide(byte(), byte()) :: byte()
  def divide(_a, 0), do: raise(ArithmeticError, message: "GF(256) division by zero")
  def divide(0, _b), do: 0

  def divide(a, b) do
    elem(@exp_table, Integer.mod(elem(@log_table, a) - elem(@log_table, b), 255))
  end

  @doc """
  Field exponentiation: `a` raised to the (integer) power `n`.

  `pow(a, 0) == 1` for all `a` (including 0, by convention). Negative
  exponents are supported for nonzero `a` (multiplicative inverse); a
  negative power of 0 raises `ArithmeticError`.

  ## Examples

      iex> Bitcoinex.SLIP39.GF256.pow(3, 255)
      1
  """
  @spec pow(byte(), integer()) :: byte()
  def pow(_a, 0), do: 1
  def pow(0, n) when n > 0, do: 0
  def pow(0, _n), do: raise(ArithmeticError, message: "GF(256) 0 raised to a negative power")

  def pow(a, n) do
    elem(@exp_table, Integer.mod(elem(@log_table, a) * n, 255))
  end

  @doc """
  Lagrange interpolation of the polynomial defined by `points`, evaluated at
  `x`, independently for each byte lane of the share values.

  `points` is a list of `{x_i, y_i}` where each `y_i` is a binary of the same
  length `n`; the return value is the `n`-byte binary `f(x)`. All `x_i` must
  be distinct (caller-guaranteed). If `x` equals one of the `x_i`, the
  corresponding `y_i` is returned directly. Raises `ArgumentError` if the
  `y_i` do not all share the same byte length.

  ## Examples

      iex> Bitcoinex.SLIP39.GF256.interpolate([{0, <<9, 9>>}, {1, <<9, 9>>}], 255)
      <<9, 9>>
  """
  @spec interpolate([{byte(), binary()}], byte()) :: binary()
  def interpolate(points, x) do
    case List.keyfind(points, x, 0) do
      {^x, y} -> y
      nil -> lagrange_interpolate(points, x)
    end
  end

  defp lagrange_interpolate([{_x0, y0} | _] = points, x) do
    lane_count = byte_size(y0)

    unless Enum.all?(points, fn {_xi, yi} -> byte_size(yi) == lane_count end) do
      raise ArgumentError, "interpolation points must all have the same byte length"
    end

    xs = Enum.map(points, fn {xi, _yi} -> xi end)
    zero_lanes = List.duplicate(0, lane_count)

    points
    |> Enum.map(fn {xi, yi} ->
      coefficient =
        xs
        |> Enum.reject(&(&1 == xi))
        |> Enum.reduce(1, fn xj, acc ->
          mul(acc, divide(add(x, xj), add(xi, xj)))
        end)

      yi |> :binary.bin_to_list() |> Enum.map(&mul(coefficient, &1))
    end)
    |> Enum.reduce(zero_lanes, fn lanes, acc -> Enum.zip_with(lanes, acc, &bxor/2) end)
    |> :binary.list_to_bin()
  end
end
