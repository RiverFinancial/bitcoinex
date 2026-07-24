defmodule Bitcoinex.SLIP39.GF256Test do
  use ExUnit.Case
  use ExUnitProperties

  import Bitwise

  alias Bitcoinex.SLIP39.GF256

  doctest Bitcoinex.SLIP39.GF256

  # Independent slow reference multiplication (shift-and-reduce over the
  # Rijndael polynomial 0x11B) used to cross-check the table-based mul/2.
  defp ref_mul(a, b) do
    0..7
    |> Enum.reduce({0, a}, fn i, {acc, shifted} ->
      acc = if (b >>> i &&& 1) == 1, do: bxor(acc, shifted), else: acc
      shifted = shifted <<< 1
      shifted = if shifted > 0xFF, do: bxor(shifted, 0x11B), else: shifted
      {acc, shifted}
    end)
    |> elem(0)
  end

  defp combinations(_list, 0), do: [[]]
  defp combinations([], _k), do: []

  defp combinations([head | tail], k) do
    for(combo <- combinations(tail, k - 1), do: [head | combo]) ++ combinations(tail, k)
  end

  # f(x) = a2*x^2 + a1*x + a0 in GF(256), per byte lane.
  defp eval_poly(coefficient_lanes, x) do
    coefficient_lanes
    |> Enum.map(fn [a2, a1, a0] ->
      GF256.mul(a2, GF256.pow(x, 2))
      |> GF256.add(GF256.mul(a1, x))
      |> GF256.add(a0)
    end)
    |> :binary.list_to_bin()
  end

  describe "add/2" do
    test "a + a == 0 for all a" do
      for a <- 0..255, do: assert(GF256.add(a, a) == 0)
    end

    test "a + 0 == a for all a" do
      for a <- 0..255, do: assert(GF256.add(a, 0) == a)
    end
  end

  describe "mul/2" do
    test "a * 0 == 0 and 0 * a == 0 for all a" do
      for a <- 0..255 do
        assert GF256.mul(a, 0) == 0
        assert GF256.mul(0, a) == 0
      end
    end

    test "a * 1 == a for all a" do
      for a <- 0..255, do: assert(GF256.mul(a, 1) == a)
    end

    test "known AES vector: 0x57 * 0x13 == 0xFE (FIPS-197 sec. 4.2)" do
      assert GF256.mul(0x57, 0x13) == 0xFE
      assert GF256.mul(0x13, 0x57) == 0xFE
    end

    test "commutativity on a sample grid" do
      for a <- [0, 1, 2, 3, 0x53, 0x57, 0xCA, 0xFF],
          b <- [0, 1, 7, 0x13, 0x80, 0xFE, 0xFF] do
        assert GF256.mul(a, b) == GF256.mul(b, a)
      end
    end

    test "matches slow reference multiplication over the full field" do
      for a <- 0..255, b <- 0..255 do
        assert GF256.mul(a, b) == ref_mul(a, b)
      end
    end
  end

  describe "divide/2" do
    test "mul(a, divide(1, a)) == 1 for all nonzero a" do
      for a <- 1..255, do: assert(GF256.mul(a, GF256.divide(1, a)) == 1)
    end

    test "divide inverts mul on samples" do
      for a <- [1, 2, 0x53, 0x57, 0xCA, 0xFF], b <- [1, 3, 0x13, 0x80, 0xFE] do
        assert GF256.divide(GF256.mul(a, b), b) == a
        assert GF256.mul(GF256.divide(a, b), b) == a
      end
    end

    test "divide(0, b) == 0 for nonzero b" do
      for b <- [1, 2, 0x13, 0xFF], do: assert(GF256.divide(0, b) == 0)
    end

    test "division by zero raises ArithmeticError" do
      assert_raise ArithmeticError, fn -> GF256.divide(5, 0) end
      assert_raise ArithmeticError, fn -> GF256.divide(0, 0) end
    end
  end

  describe "pow/2" do
    test "pow(a, 0) == 1 for all a" do
      for a <- 0..255, do: assert(GF256.pow(a, 0) == 1)
    end

    test "pow(a, 1) == a for all a" do
      for a <- 0..255, do: assert(GF256.pow(a, 1) == a)
    end

    test "exp/log table consistency across the full field" do
      # pow via the tables must agree with repeated reference multiplication,
      # and 3 must generate every nonzero element exactly once.
      for a <- 0..255 do
        assert GF256.pow(a, 2) == ref_mul(a, a)
        assert GF256.pow(a, 3) == ref_mul(ref_mul(a, a), a)
      end

      powers_of_3 = Enum.map(0..254, &GF256.pow(3, &1))
      assert Enum.sort(powers_of_3) == Enum.to_list(1..255)
    end

    test "negative exponent is the multiplicative inverse for nonzero a" do
      for a <- [1, 2, 0x57, 0xFF], do: assert(GF256.mul(a, GF256.pow(a, -1)) == 1)
    end

    test "pow(0, n) == 0 for positive n and raises for negative n" do
      assert GF256.pow(0, 5) == 0
      assert_raise ArithmeticError, fn -> GF256.pow(0, -1) end
    end
  end

  describe "interpolate/2" do
    test "degree-0 (constant) polynomial is recovered exactly" do
      points = [{1, <<0x2A, 0x07>>}, {2, <<0x2A, 0x07>>}]
      assert GF256.interpolate(points, 0) == <<0x2A, 0x07>>
      assert GF256.interpolate(points, 255) == <<0x2A, 0x07>>
    end

    test "degree-1 line is recovered exactly" do
      # f(x) = a*x + b per byte lane
      lanes = [{0x53, 0x11}, {0xCA, 0xFE}]

      f = fn x ->
        lanes
        |> Enum.map(fn {a, b} -> GF256.add(GF256.mul(a, x), b) end)
        |> :binary.list_to_bin()
      end

      points = [{0, f.(0)}, {1, f.(1)}]

      for x <- [2, 3, 100, 254, 255] do
        assert GF256.interpolate(points, x) == f.(x)
      end
    end

    test "reconstructs a known polynomial's f(255) from T points" do
      coefficient_lanes = [[0x53, 0xCA, 0x11], [0x02, 0x87, 0xFE]]
      points = for x <- [0, 1, 2], do: {x, eval_poly(coefficient_lanes, x)}

      assert GF256.interpolate(points, 255) == eval_poly(coefficient_lanes, 255)
      assert GF256.interpolate(points, 254) == eval_poly(coefficient_lanes, 254)
    end

    test "result is independent of which T points are chosen" do
      coefficient_lanes = [[0x53, 0xCA, 0x11], [0x02, 0x87, 0xFE]]
      all_points = for x <- [0, 1, 2, 3, 4], do: {x, eval_poly(coefficient_lanes, x)}
      expected = eval_poly(coefficient_lanes, 255)

      for subset <- combinations(all_points, 3) do
        assert GF256.interpolate(subset, 255) == expected
      end
    end

    test "returns the matching y when x is one of the given points" do
      points = [{5, <<1, 2, 3>>}, {9, <<4, 5, 6>>}]
      assert GF256.interpolate(points, 9) == <<4, 5, 6>>
    end

    test "points with unequal byte lengths raise ArgumentError" do
      points = [{1, <<1, 2, 3>>}, {2, <<4, 5>>}]

      assert_raise ArgumentError, fn -> GF256.interpolate(points, 0) end

      # but the early keyfind path still returns a matching y directly,
      # without needing the other lanes to line up
      assert GF256.interpolate(points, 2) == <<4, 5>>
    end
  end

  describe "field properties" do
    property "mul is commutative" do
      check all(a <- integer(0..255), b <- integer(0..255)) do
        assert GF256.mul(a, b) == GF256.mul(b, a)
      end
    end

    property "divide(mul(a, b), b) == a for nonzero b" do
      check all(a <- integer(0..255), b <- integer(1..255)) do
        assert GF256.divide(GF256.mul(a, b), b) == a
      end
    end

    property "mul distributes over add" do
      check all(a <- integer(0..255), b <- integer(0..255), c <- integer(0..255)) do
        assert GF256.mul(a, GF256.add(b, c)) ==
                 GF256.add(GF256.mul(a, b), GF256.mul(a, c))
      end
    end

    property "pow(a, 255) == 1 for nonzero a (Fermat)" do
      check all(a <- integer(1..255)) do
        assert GF256.pow(a, 255) == 1
      end
    end
  end
end
